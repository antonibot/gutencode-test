// ai_provider — the unified LLM gateway: the ONE seam every caller uses for completions. The dangerous property
// is BILLING HONESTY: the meter is CONSERVED (usage always equals the sum of every billed completion — the
// update is one atomic read-modify-write through storeDo) and a cache replay is NEVER re-billed. Model fallback
// degrades an unknown model to the default — never a 5xx. The offline fake is deterministic (tokens are utf-8
// BYTE lengths, the x3-identical semantic); SHIPPED adapters for Anthropic + OpenAI swap in behind the same
// shape (INTEROP.md): AI_PROVIDER=anthropic|openai with the matching key env set round-trips the REAL API per
// call — global fetch only (no SDK), env read at call time, one configured model per deployment (AI_MODEL or
// the provider default), upstream non-2xx mapped to a LOUD 502 problem+json with a SANITIZED snippet (the key
// is never echoed), timeout/network failure to 504, and a failed call is never billed and never cached.
// HONESTY CONTRACT (identical x3): AI_PROVIDER naming a real provider WITHOUT its key env — or any unknown
// value — makes POST /ai/complete REFUSE per call with a 501 that says exactly what to set, NEVER silent fake
// output under a real provider's name (GET /ai/usage keeps working: the failure stays local to completions,
// and a refusal is never billed or cached). The cache key comes from the digest part. Durable: meter and
// cache survive a restart.
import { problem, requireAdmin, requireIdentity, sendJSON, storeDo, storeGet, storePut } from '../core/runtime.js';
import { digestHex } from '../parts/digest.js';
import { envInt } from '../parts/env_int.js';
import { makeWellFormed } from '../parts/well_formed.js';

const DEFAULT_MODEL = 'fake';
const MODELS = new Set(['fake', 'fast', 'smart']);
// the SHIPPED real providers (INTEROP.md): key env · default model · base-URL env + real endpoint. The base-URL
// override is both a proxy/gateway feature and the offline test seam (the invariant drives a loopback stub).
const KEY_ENV = { anthropic: 'ANTHROPIC_API_KEY', openai: 'OPENAI_API_KEY' };
const REAL_MODEL = { anthropic: 'claude-sonnet-4-6', openai: 'gpt-4o' };
const BASE_ENV = { anthropic: 'ANTHROPIC_BASE_URL', openai: 'OPENAI_BASE_URL' };
const BASE_DEFAULT = { anthropic: 'https://api.anthropic.com', openai: 'https://api.openai.com' };
const ANTHROPIC_VERSION = '2023-06-01'; // the Messages API version pin — a wire constant the API requires
const UPSTREAM_BODY_CAP = 1048576; // UTF-16 units kept of a provider response (a text completion is KBs)
const MAX_SAFE_TOKENS = 9007199254740991; // 2**53-1 — a reported token count past this bills 0, never overflows
// state in store: ns "ai_provider_meter" key "total" (atomic RMW) · ns "ai_provider_cache" digest(model,prompt)

// the HONESTY GATE (identical in python/go): returns { which } naming who runs this call — 'fake' (the
// offline default) or a SHIPPED real adapter whose key env is set — else { refusal } with the 501 detail
// (byte-identical x3) for a keyless real name / unknown value. Checked per CALL (not at boot) and BEFORE the
// cache/meter, so the app stays usable and a refusal is never billed or cached. 501 Not Implemented —
// deliberate: not 503 (the missing key is not transient; retrying cannot succeed until an operator sets one)
// and not a 4xx (the request is valid; the DEPLOYMENT lacks the capability).
function providerSelect() {
  const which = process.env.AI_PROVIDER || 'fake';
  if (which === 'fake') return { which };
  if (Object.hasOwn(KEY_ENV, which)) {
    if (!process.env[KEY_ENV[which]]) return { refusal: `provider '${which}' needs ${KEY_ENV[which]} — see INTEROP.md` };
    return { which };
  }
  return { refusal: `unknown provider '${which}' — see INTEROP.md` };
}

// a provider-reported token count, contained: an integral number in [0, 2**53-1] bills as-is; anything else
// (absent, non-numeric, negative, fractional, absurd magnitude) bills 0 — the CONSERVED meter can never be
// poisoned or overflowed by an upstream payload. Identical decision in python/go.
function usageInt(v) {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= MAX_SAFE_TOKENS ? v : 0;
}

// the SHIPPED adapter (global fetch only, no SDK): POST the provider's completion API, extract the text + real
// token usage into the gateway's response shape. Env is read per CALL (key, base URL, timeout, ceiling).
// Failure map (identical x3): upstream non-2xx -> { fail: 502 + status + a <=200-char body snippet with the
// key value REDACTED (never echo credentials, never dump headers) }; timeout / network / bad endpoint -> 504;
// a 2xx whose body isn't the documented shape -> 502. The caller refuses BEFORE the cache write and the meter
// add, so a failure is never billed and never cached. Returns { result } or { fail: { status, detail } }.
async function realComplete(which, model, prompt) {
  const key = process.env[KEY_ENV[which]]; // non-empty — providerSelect checked
  const timeout = envInt(process.env.AI_TIMEOUT_SECONDS, 60, 1, 600);
  const base = (process.env[BASE_ENV[which]] || BASE_DEFAULT[which]).replace(/\/+$/, '');
  const anthropic = which === 'anthropic';
  const url = base + (anthropic ? '/v1/messages' : '/v1/chat/completions');
  const payload = anthropic
    ? { model, max_tokens: envInt(process.env.AI_MAX_TOKENS, 1024, 1), messages: [{ role: 'user', content: prompt }] }
    : { model, messages: [{ role: 'user', content: prompt }] };
  const headers = anthropic
    ? { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': ANTHROPIC_VERSION }
    : { 'content-type': 'application/json', authorization: `Bearer ${key}` };
  let resp;
  let text;
  try {
    resp = await fetch(url, { method: 'POST', headers, body: JSON.stringify(payload),
                              signal: AbortSignal.timeout(timeout * 1000) });
    text = await resp.text();
  } catch { // timeout, refused, DNS, malformed base URL
    return { fail: { status: 504, detail: `provider '${which}' upstream timeout or network failure` } };
  }
  if (!resp.ok) { // non-2xx: loud + sanitized, never invented text
    const redacted = key ? text.split(key).join('[redacted]') : text;
    const snippet = [...redacted].slice(0, 200).join('');
    return { fail: { status: 502, detail: `provider '${which}' upstream error (HTTP ${resp.status}): ${snippet}` } };
  }
  const fail = { status: 502, detail: `provider '${which}' upstream error: unexpected response shape` };
  if (text.length > UPSTREAM_BODY_CAP) return { fail };
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return { fail };
  }
  let out;
  let usage;
  if (anthropic) {
    if (!Array.isArray(data.content)) return { fail };
    out = ''; // concatenate the text blocks (usually exactly one)
    for (const block of data.content) {
      if (block && block.type === 'text') {
        if (typeof block.text !== 'string') return { fail };
        out += block.text;
      }
    }
    usage = data.usage && typeof data.usage === 'object' ? data.usage : {};
    usage = { prompt_tokens: usageInt(usage.input_tokens), completion_tokens: usageInt(usage.output_tokens), cost: 0 };
  } else {
    out = data?.choices?.[0]?.message?.content;
    if (typeof out !== 'string') return { fail };
    const u = data.usage && typeof data.usage === 'object' ? data.usage : {};
    usage = { prompt_tokens: usageInt(u.prompt_tokens), completion_tokens: usageInt(u.completion_tokens), cost: 0 };
  }
  // contain the extracted text BEFORE it is cached/served: an upstream `\ud800` escape parses to a lone
  // surrogate (python mirrors; go's decoder substitutes natively). cost stays 0: token counts are the
  // provider's real numbers, but no price table is baked in (prices move) — wire your own pricing into the
  // billed usage if you want money units in the meter.
  return { result: { model, output: makeWellFormed(out), usage } };
}

function fakeComplete(model, prompt) {
  // deterministic offline completion: token counts are utf-8 BYTE lengths so all three languages agree
  const pTokens = Buffer.byteLength(prompt, 'utf8');
  return { model, output: `[${model}] ` + prompt.toUpperCase(),
           usage: { prompt_tokens: pTokens,
                    completion_tokens: pTokens + Buffer.byteLength(model, 'utf8') + 3, cost: 0 } };
}

export async function aiProviderComplete(req, res, params, body) {
  if ((await requireIdentity(req, res)) === null) return; // authn -> validation, auth BEFORE the body checks (×3)
  // FOLLOW-ON: the meter stays a single global 'total' key for now; the PER-SUBJECT meter + per-caller cache
  // key (bill/quota the caller, scope the cache by subject) is a documented data-model change — see INTEROP.md.
  if (!body || typeof body.prompt !== 'string' || body.prompt === '' ||
      (body.model !== undefined && typeof body.model !== 'string')) {
    return problem(res, 422, 'invalid body');
  }
  const sel = providerSelect();
  if (sel.refusal) return problem(res, 501, sel.refusal); // fail LOUD on a keyless/unknown AI_PROVIDER — never silent fake output
  // offline: unknown model FALLS BACK to the default, never a 5xx. Wired: ONE configured model per deployment
  // (AI_MODEL, else the provider default), so spend stays operator-controlled — the request `model` field is
  // not a caller escalation channel; any value falls back to the configured model (the same doctrine).
  const model = sel.which === 'fake'
    ? (MODELS.has(body.model) ? body.model : DEFAULT_MODEL)
    : (process.env.AI_MODEL || REAL_MODEL[sel.which]);
  const key = digestHex(model, body.prompt);
  const prior = await storeGet('ai_provider_cache', key);
  if (prior !== undefined) {
    return sendJSON(res, 200, { ...prior, cached: true }); // a replay is served stored and NEVER re-billed
  }
  let result;
  if (sel.which === 'fake') {
    result = fakeComplete(model, body.prompt);
  } else {
    const r = await realComplete(sel.which, model, body.prompt);
    if (r.fail) return problem(res, r.fail.status, r.fail.detail); // upstream failure: refused BEFORE the cache/meter — never billed or cached
    result = r.result;
  }
  // rmw-safe: convergent-or-benign — the cache key is digest(model, prompt); the offline completion is
  // deterministic (identical concurrent writes), and a sampling real provider makes two concurrent misses a
  // benign last-write-wins cache fill (each real call WAS made and IS billed, so conservation still holds)
  await storePut('ai_provider_cache', key, result);
  // CONSERVED: one atomic add per billed completion
  await storeDo('ai_provider_meter', 'total', (m) => {
    const meter = m || { requests: 0, prompt_tokens: 0, completion_tokens: 0, cost: 0 };
    return [{ requests: meter.requests + 1,
              prompt_tokens: meter.prompt_tokens + result.usage.prompt_tokens,
              completion_tokens: meter.completion_tokens + result.usage.completion_tokens,
              cost: meter.cost + result.usage.cost }, null];
  });
  sendJSON(res, 200, { ...result, cached: false });
}

export async function aiProviderUsage(req, res) {
  // ADMIN-ONLY: this is the GLOBAL usage meter (total requests/tokens/cost across ALL completions) — it exposes
  // the app's total AI spend. authn -> authz BEFORE the read (no token -> 401, a valid non-admin -> 403), ×3.
  if ((await requireAdmin(req, res)) === null) return;
  const m = await storeGet('ai_provider_meter', 'total');
  sendJSON(res, 200, m || { requests: 0, prompt_tokens: 0, completion_tokens: 0, cost: 0 });
}
