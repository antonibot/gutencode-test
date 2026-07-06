// llm_usage — a per-call LLM token + cost METER. Matches python/go; durable. Dangerous property = COST INTEGRITY:
// (1) COST SERVER-DERIVED, never client-supplied — the event carries TOKENS only (no cost field); cost is computed
// from a fixed code-reviewed PRICE TABLE; unknown (provider,model) or an unpriced dimension is 422, deny-by-default
// (never $0/free, never under-count). (2) NO DOUBLE-COUNT — idempotent on (owner, identifier) via scopedKey+claimOnce;
// a same-identifier retry with ANY different cost-input is 409 (the provider-inclusive body-hash, computed over the
// request AS SENT — an omitted `at` hashes as a sentinel, never the server-minted default, so a byte-identical retry
// replays 201 even across a wall-clock second tick). (3) APPEND-ONLY (no
// update/delete route). (4) AGGREGATE DERIVED on read (GET /summary). (5) OWNER-SCOPED (owner = requireIdentity).
// (6) INTEGER-EXACT: rate is nanodollars-per-1000-tokens (real per-token rates are sub-nanodollar); cost =
// floor(tokens*rate/1000), the intermediate within the 2^53-safe range; a per-dimension token ceiling bounds it.
// Every route requireIdentity.
import { isStrictInt, nextId, problem, requireIdentity, sendJSON, storeGet, storeValues, testNow } from '../core/runtime.js';
import { registerUsageSink } from '../core/usage.js';
import { digestHex, scopedKey } from '../parts/digest.js';
import { envInt } from '../parts/env_int.js';
import { claimOnce } from '../parts/idempotent_claim.js';
import { paginate } from '../parts/paginate.js';
import { isWellFormed } from '../parts/well_formed.js';

const ROUTE = 'POST /llm_usage/events'; // the dedup-slot discriminator (per-operation, owner-scoped slot)
const REPLAY = envInt(process.env.LLM_USAGE_REPLAY_WINDOW, 300, 1); // the `at` anti-backdate window
const MAX_TOKENS = envInt(process.env.LLM_USAGE_MAX_TOKENS, 10000000, 1); // per-dimension ceiling

// THE PRICE TABLE (policy, code-reviewed) — provider -> model -> {dimension: nanodollars-per-1000-tokens}. Integer
// rate (real per-token rates are sub-nanodollar); per-1000 keeps tokens*rate within the 2^53-safe range. Same data +
// same cost ×3 (the manifest cost cases pin it). NEVER empty.
const PRICES = {
  openai: { 'gpt-4o': { input: 2500000, output: 10000000, cache_read: 1250000 },
            'gpt-4o-mini': { input: 150000, output: 600000, cache_read: 75000 } },
  anthropic: { 'claude-3-5-sonnet': { input: 3000000, output: 15000000, cache_read: 300000, cache_write: 3750000 },
               'claude-sonnet-4-6': { input: 3000000, output: 15000000, cache_read: 300000, cache_write: 3750000 },
               'claude-3-5-haiku': { input: 800000, output: 4000000, cache_read: 80000, cache_write: 1000000 } },
  // the offline provider's row: exists so the metering wire is provable offline (armed via AI_USAGE_METER_FAKE);
  // every rate 0 — a priced-at-zero provider is EXPLICIT policy, not a silent $0 (an unknown model still 422s).
  fake: { fake: { input: 0, output: 0, cache_read: 0, cache_write: 0, reasoning: 0 } },
};
// the event token field -> the price dimension (FIXED order -> a deterministic ×3 body-hash)
const DIMS = [['input_tokens', 'input'], ['output_tokens', 'output'], ['cache_read_input_tokens', 'cache_read'],
              ['cache_creation_input_tokens', 'cache_write'], ['reasoning_tokens', 'reasoning']];
const SUM_FIELDS = ['input_tokens', 'output_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens', 'reasoning_tokens', 'cost_nanodollars'];

// state in store: seq "llm_usage_event" · ns "llm_usage_events" scopedKey(route, owner, identifier) -> the WHOLE record
// {id, owner, identifier, provider, model, <5 token dims>, at, cost_nanodollars, body_hash}. Owner-scoped slot. ×3.

// an OPTIONAL token field: absent -> 0; else a STRICT int (isStrictInt bounds 2^53 ×3) that is >= 0; null = invalid.
function tok(body, field) {
  if (body[field] === undefined) return 0;
  if (!isStrictInt(body, field) || body[field] < 0) return null;
  return body[field];
}

// cost_nanodollars = Σ_dim floor(tokens*rate/1000) (integer-EXACT). Unknown (provider,model) or an unpriced dimension
// with tokens>0 -> {err} for a 422. A per-dimension ceiling rejects an absurd count.
function deriveCost(provider, model, tokens, maxTok) {
  const rates = (PRICES[provider] || {})[model];
  if (rates === undefined) return { err: 'no price for this provider/model' };
  let cost = 0;
  for (const [field, dim] of DIMS) {
    const n = tokens[dim];
    if (n === 0) continue;
    if (n > maxTok) return { err: `${field} exceeds the per-call ceiling` };
    const rate = rates[dim];
    if (rate === undefined) return { err: `no price for the ${dim} dimension of this model` };
    cost += Math.floor((n * rate) / 1000); // n*rate <= 2^53-safe (per-1000); floor matches py // and go / ×3
  }
  return { cost };
}

// The fingerprint over ALL cost-determining fields AS THE CLIENT SENT THEM. atSent is the CLIENT's at, or the '-'
// sentinel when omitted (String(int) never renders a bare '-') — the server-minted default must NEVER enter the hash:
// it is wall-clock-quantized, so two byte-identical no-`at` retries straddling a second boundary would fingerprint
// differently and 409 instead of replaying a legitimate client retry. Matches python/go exactly.
const bodyHash = (e, atSent) => digestHex('provider', e.provider, 'model', e.model, 'in', e.input_tokens, 'out', e.output_tokens,
  'cr', e.cache_read_input_tokens, 'cw', e.cache_creation_input_tokens, 're', e.reasoning_tokens, 'at', atSent, 'cost', e.cost_nanodollars);

const publicView = (e) => ({ id: e.id, identifier: e.identifier, provider: e.provider, model: e.model,
  input_tokens: e.input_tokens, output_tokens: e.output_tokens, cache_read_input_tokens: e.cache_read_input_tokens,
  cache_creation_input_tokens: e.cache_creation_input_tokens, reasoning_tokens: e.reasoning_tokens,
  at: e.at, cost_nanodollars: e.cost_nanodollars });

export async function llmUsageRecord(req, res, params, body) {
  const owner = await requireIdentity(req, res); // an authenticated caller meters ITS OWN usage
  if (owner === null) return;
  if (!body || !isWellFormed(body.identifier) || !isWellFormed(body.provider) || !isWellFormed(body.model)) {
    return problem(res, 422, 'invalid body');
  }
  const tokens = {};
  for (const [field, dim] of DIMS) {
    const v = tok(body, field);
    if (v === null) return problem(res, 422, 'invalid body');
    tokens[dim] = v;
  }
  const now = testNow(req);
  let at = now;      // the STORED/returned time; the hash gets `at` AS SENT
  let atSent = '-';  // the client omitted `at` — the sentinel, never the server-minted default
  if (body.at !== undefined) {
    if (!isStrictInt(body, 'at')) return problem(res, 422, 'invalid body');
    at = body.at;
    atSent = body.at;
  }
  if (Math.abs(at - now) > REPLAY) return problem(res, 422, 'at is outside the replay window'); // before the body-hash
  const e = { owner, identifier: body.identifier, provider: body.provider, model: body.model,
    input_tokens: tokens.input, output_tokens: tokens.output, cache_read_input_tokens: tokens.cache_read,
    cache_creation_input_tokens: tokens.cache_write, reasoning_tokens: tokens.reasoning, at };
  const r = await commit(e, atSent, MAX_TOKENS); // the shared recording core (derive cost, fingerprint, claim exactly-once)
  if (r.status !== 201) return problem(res, r.status, r.msg);
  sendJSON(res, 201, publicView(r.record));
}

// commit — THE transport-free recording CORE shared by the HTTP route AND the in-process usage sink (the ONE writer
// of llm_usage_events; one namespace writer, one price authority). Derives the SERVER cost (422 on unknown/unpriced),
// fingerprints the body AS SENT, and claims the (owner, identifier) slot exactly-once. Returns { status, msg?, record? }:
// 201 = recorded/replayed · 409/422 = refused. `atSent` = the client's at or the '-' sentinel; e.at = the stored time.
async function commit(e, atSent, maxTok) {
  const tokens = { input: e.input_tokens, output: e.output_tokens, cache_read: e.cache_read_input_tokens,
    cache_write: e.cache_creation_input_tokens, reasoning: e.reasoning_tokens };
  const d = deriveCost(e.provider, e.model, tokens, maxTok); // SERVER-derived (anti-self-billing)
  if (d.err) return { status: 422, msg: d.err };
  e.cost_nanodollars = d.cost;
  e.body_hash = bodyHash(e, atSent);
  const scoped = scopedKey(ROUTE, e.owner, e.identifier); // owner-scoped dedup slot (private to the caller)
  let prior = await storeGet('llm_usage_events', scoped); // fast path: a settled identifier never mints
  if (prior === undefined) {
    e.id = await nextId('llm_usage_event'); // mint BEFORE the claim (a race loser's id is a harmless gap)
    prior = await claimOnce('llm_usage_events', scoped, e); // exactly-once: a racing loser gets the winner
  }
  if (prior.owner !== e.owner) return { status: 409, msg: 'identifier is not owned by this caller' }; // defense-in-depth
  if (prior.body_hash !== e.body_hash) return { status: 409, msg: 'identifier reused with a different body' };
  return { status: 201, record: prior };
}

// recordEvent — THE usage-sink recorder registered into the core hook (the SAME writer as the HTTP route). A producer
// calls usageRecord(owner, call, now); core forwards it here. The sink omits the client `at` (the '-' sentinel), so a
// byte-identical retry replays across a wall-clock tick. A refused event (unpriced/409) throws, so the core seam
// contains + logs it and the producer's run continues (a broken meter never breaks a chat).
async function recordEvent(owner, call, now) {
  const e = { owner, identifier: call.identifier, provider: call.provider, model: call.model,
    input_tokens: call.input_tokens || 0, output_tokens: call.output_tokens || 0,
    cache_read_input_tokens: call.cache_read_input_tokens || 0,
    cache_creation_input_tokens: call.cache_creation_input_tokens || 0, reasoning_tokens: call.reasoning_tokens || 0,
    at: now };
  const r = await commit(e, '-', MAX_TOKENS);
  if (r.status !== 201) throw new Error(r.msg);
}

// self-register the recorder into the core usage hook at import — guaranteed pre-serve (the app imports every domain
// module to mount routes before the server listens), so no request can race an unregistered sink.
registerUsageSink(recordEvent);

function parseTS(v) {
  if (v === null || v === '') return { set: false };
  if (!/^-?[0-9]+$/.test(v)) return { bad: true };
  const n = Number(v);
  if (!Number.isSafeInteger(n)) return { bad: true }; // bounded 2^53 ×3
  return { set: true, v: n };
}

export async function llmUsageSummary(req, res) {
  // unbounded-safe: scalar aggregate — sums the OWNER's events into per-(provider,model) totals + a grand total; no
  // raw collection returned (the O(n) scan is the documented store-swap-at-scale limit). OWNER-ISOLATION enforced.
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const q = new URL(req.url, 'http://localhost').searchParams;
  const frm = parseTS(q.get('from'));
  const to = parseTS(q.get('to'));
  if (frm.bad || to.bad) return problem(res, 422, 'from/to must be an integer epoch');
  const model = q.get('model');
  const groups = new Map();
  const total = Object.fromEntries(SUM_FIELDS.map((f) => [f, 0]));
  for (const rec of await storeValues('llm_usage_events')) {
    if (rec.owner !== owner) continue;
    if ((frm.set && rec.at < frm.v) || (to.set && rec.at > to.v) || (model && rec.model !== model)) continue; // `model` falsy (absent/empty) -> no filter (×3 with go/py)
    const key = `${rec.provider}\u0000${rec.model}`;
    let g = groups.get(key);
    if (g === undefined) { g = { provider: rec.provider, model: rec.model, ...Object.fromEntries(SUM_FIELDS.map((f) => [f, 0])) }; groups.set(key, g); }
    for (const f of SUM_FIELDS) { g[f] += rec[f]; total[f] += rec[f]; }
  }
  const by_model = [...groups.values()].sort((a, b) => (a.provider === b.provider ? (a.model < b.model ? -1 : 1) : (a.provider < b.provider ? -1 : 1)));
  sendJSON(res, 200, { ...total, by_model });
}

export async function llmUsageEvents(req, res) {
  // OWNER-scoped audit trail, BOUNDED through paginate. NEVER the body_hash; ordered by id.
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const mine = (await storeValues('llm_usage_events')).filter((r) => r.owner === owner).sort((a, b) => a.id - b.id).map(publicView);
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(mine, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}
