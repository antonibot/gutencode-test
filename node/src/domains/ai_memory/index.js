// ai_memory — a long-term, owner-scoped agent-memory store whose dangerous property is RETENTION-ENFORCED / BOUNDED.
// Matches python/go; durable. See ai_memory.py for the full contract. (1) BOUNDED — a per-(owner,scope) index caps
// memories per scope (evict past MAX_MEMORIES); a per-owner scope index caps the NUMBER of scopes (a NEW scope past
// MAX_SCOPES is REJECTED 422) — a per-scope cap ALONE leaves the per-owner total unbounded because `scope` is a
// free-form caller string (the partition-COUNT trap). (2) EVICTION — evict min-(importance ASC, created_at ASC, id
// ASC) EXPIRED-FIRST, never dropping a LIVE memory while an expired one keeps its slot. (3) TTL — optional ttl_seconds
// => a server-DERIVED expires_at (smuggled discarded; the sum is overflow-guarded + clamped to 2^53-1); lazy
// read-hide, `expired <=> now > expires_at` (AT = LIVE), inert without APP_TEST_CLOCK. (4) FORGET — DELETE by id
// (purge the scope-index entry THEN the row) or a whole scope (scope REQUIRED). (5) OWNER-SCOPED — owner =
// requireIdentity; rows keyed by the composite `${owner}\x1f${id}` (id server-minted via nextId); the scope index is
// the LIVENESS set (a read gates on it, never a raw row scan that could resurrect an orphan); not-yours == 404.
// content/tags/metadata are CONTAINED (keys AND values) before store. Retrieval: per-scope, newest-first (created_at
// desc, id asc), expired-excluded, paginated, optional ?tag= / ?q= (ASCII-only case-fold substring). Append-only: no
// update, no dedup. Same names + DECISIONS in all three languages.
import { intParam, isStrictInt, nextId, problem, requireIdentity, sendJSON, storeDelete, storeDo, storeGet, storePut, testNow } from '../../core/runtime.js';
import { envInt } from '../../parts/env_int.js';
import { paginate } from '../../parts/paginate.js';
import { isWellFormed, makeWellFormed } from '../../parts/well_formed.js';

const OWNER = 'ai_memory_owner';   // "<owner>"           -> [scope, ...]                                   (bounds the scope COUNT)
const SCOPE = 'ai_memory_scope';   // `${owner}\x1f${scope}` -> [{ id, created_at, expires_at, importance }] (the liveness set)
const MEM = 'ai_memory_memory';    // `${owner}\x1f${id}`    -> { id, owner, scope, content, tags, metadata, importance, created_at, expires_at }

const MAX_SAFE = Number.MAX_SAFE_INTEGER; // 2^53 - 1
const MAX_TAG_BYTES = 128;
const MAX_SCOPE_BYTES = 256;

const maxScopes = () => envInt(process.env.AI_MEMORY_MAX_SCOPES, 100, 1);
const maxMemories = () => envInt(process.env.AI_MEMORY_MAX_MEMORIES, 1000, 1);
const maxTags = () => envInt(process.env.AI_MEMORY_MAX_TAGS, 20, 1);
const maxContentBytes = () => envInt(process.env.AI_MEMORY_MAX_CONTENT_BYTES, 16384, 1);
const maxMetadataBytes = () => envInt(process.env.AI_MEMORY_MAX_METADATA_BYTES, 4096, 1);

const mkey = (owner, id) => `${owner}\x1f${id}`;      // owner-partitioned rows (B can't read A's id)
const skey = (owner, scope) => `${owner}\x1f${scope}`; // owner-partitioned per-scope index

// cleanScope — isWellFormed (reject a control char < 0x20 so the \x1f key separator can't be forged) -> 422; then
// makeWellFormed (contain a lone surrogate so the key + echo are UTF-8-safe). Returns null on reject (already responded).
function cleanScope(res, raw) {
  if (!isWellFormed(raw)) { problem(res, 422, 'the scope must be non-empty with no control characters'); return null; }
  const cleaned = makeWellFormed(raw);
  if (Buffer.byteLength(cleaned, 'utf8') > MAX_SCOPE_BYTES) { problem(res, 422, 'the scope is too large'); return null; }
  return cleaned;
}

function cleanTags(res, tags) {
  if (tags === undefined || tags === null) return [];
  if (!Array.isArray(tags) || !tags.every((t) => typeof t === 'string')) { problem(res, 422, 'tags must be an array of strings'); return null; }
  if (tags.length > maxTags()) { problem(res, 422, 'too many tags'); return null; }
  const out = [];
  for (const t of tags) {
    if (!isWellFormed(t)) { problem(res, 422, 'a tag must be non-empty with no control characters'); return null; }
    const cleaned = makeWellFormed(t); // CONTAIN before store (a re-read would 5xx on a lone surrogate otherwise)
    if (Buffer.byteLength(cleaned, 'utf8') > MAX_TAG_BYTES) { problem(res, 422, 'a tag is too large'); return null; }
    out.push(cleaned);
  }
  return out;
}

function cleanMetadata(res, metadata) {
  if (metadata === undefined || metadata === null) return {};
  if (typeof metadata !== 'object' || Array.isArray(metadata) || !Object.values(metadata).every((v) => typeof v === 'string')) {
    problem(res, 422, 'metadata must be an object of string values'); return null;
  }
  // Object.create(null) so a hostile "__proto__" metadata KEY is stored as DATA (matches the py dict / go map + the
  // central sanitizeJson); a plain {} would DROP it via the inherited prototype setter (a x3 data-fidelity break).
  const out = Object.create(null);
  for (const k of Object.keys(metadata)) {
    out[makeWellFormed(k)] = makeWellFormed(metadata[k]); // CONTAIN key + value before store (a re-read must never 5xx)
  }
  // byte-cap = raw UTF-8 byte-SUM over the CONTAINED, COLLAPSED `out` (distinct surrogate keys collapse to one U+FFFD
  // entry, matching go's json decode-collapse) -> identical x3; NEVER a JSON serialization (escaping/key-order diverges).
  let total = 0;
  for (const k of Object.keys(out)) total += Buffer.byteLength(k, 'utf8') + Buffer.byteLength(out[k], 'utf8');
  if (total > maxMetadataBytes()) { problem(res, 422, 'metadata is too large'); return null; }
  return out;
}

// expiresAt — DERIVED (server-computed; a smuggled expires_at is discarded). 0 = never. Guard the overflow BEFORE the
// add (node loses precision AT 2^53 inside the add) then clamp to 2^53-1 so it is identical x3.
function expiresAt(now, ttl, ttlSet) {
  if (!ttlSet) return 0;
  if (ttl > MAX_SAFE - now) return MAX_SAFE;
  return now + ttl;
}

const expired = (e, now) => e.expires_at !== 0 && now > e.expires_at; // AT = LIVE (now > exp)

// evictLess — the eviction order: EXPIRED-FIRST (live 0 < 1), then lowest importance, oldest, lowest id. All-integer =>
// identical x3. True iff a should be evicted before b.
function evictLess(a, b, now) {
  const la = expired(a, now) ? 0 : 1;
  const lb = expired(b, now) ? 0 : 1;
  if (la !== lb) return la < lb;
  if (a.importance !== b.importance) return a.importance < b.importance;
  if (a.created_at !== b.created_at) return a.created_at < b.created_at;
  return a.id < b.id;
}

// fold — ASCII-only case fold (A-Z -> a-z); non-ASCII stays BYTE-EXACT. Iterates code points (like py); only single
// ASCII A-Z is ever touched -> identical x3 with go's byte fold.
function fold(s) {
  let out = '';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    out += (c >= 65 && c <= 90) ? String.fromCodePoint(c + 32) : ch;
  }
  return out;
}

// inIndex — the per-scope index is LIVENESS-AUTHORITATIVE: an id is live only if IN its scope index (closes the
// evict/torn-window orphan-resurrection).
async function inIndex(owner, scope, id) {
  const entries = (await storeGet(SCOPE, skey(owner, scope))) || [];
  return entries.some((e) => e.id === id);
}

function publicView(rec) {
  const out = { id: rec.id, scope: rec.scope, content: rec.content, tags: rec.tags, metadata: rec.metadata, importance: rec.importance, created_at: rec.created_at };
  if (rec.expires_at !== 0) out.expires_at = rec.expires_at;
  return out;
}

// reserveScope — reserve `scope` in the per-owner scope index; return true iff REJECTED (a NEW scope past MAX_SCOPES).
async function reserveScope(owner, scope) {
  const mx = maxScopes();
  let rejected = false;
  await storeDo(OWNER, owner, (cur) => {
    const scopes = cur || [];
    if (scopes.includes(scope)) return [undefined, null];          // already present -> no write
    if (scopes.length >= mx) { rejected = true; return [undefined, null]; } // reject: the partition-COUNT bound
    // unbounded-safe: the per-owner scope list is bounded at MAX_SCOPES by the reject-past-cap guard above — a NEW
    // scope past the cap is 422, never an eviction (evicting a scope = a silent mass-delete). Bounds the partition
    // COUNT — the number of KEYS in the namespace, a different axis from one list's length (proven by
    // I-BOUNDED-SCOPES, x3).
    return [[...scopes, scope], null];
  });
  return rejected;
}

// appendEvict — append `entry` to the per-scope index; if past MAX_MEMORIES evict min-(importance,created_at,id)
// EXPIRED-FIRST. Returns the evicted id (0 = none).
async function appendEvict(owner, scope, entry, now) {
  const mx = maxMemories();
  let evicted = 0;
  await storeDo(SCOPE, skey(owner, scope), (cur) => {
    // unbounded-safe: bounded at MAX_MEMORIES by the importance-weighted, expired-first eviction below — deliberately
    // NOT a positional drop-oldest tail-slice (age != staleness in a long-term store). Proven by I-BOUNDED + I-EVICT-CORRECT.
    const next = [...(cur || []), entry];
    if (next.length > mx) {
      let vi = 0;
      for (let i = 1; i < next.length; i++) if (evictLess(next[i], next[vi], now)) vi = i;
      evicted = next[vi].id;
      next.splice(vi, 1);
    }
    return [next, null];
  });
  return evicted;
}

export async function aiMemoryAdd(req, res, params, body) {
  const owner = await requireIdentity(req, res); // mutation-auth: identity — owner is the token subject, never a body field
  if (owner === null) return;
  if (!body || typeof body.content !== 'string') return problem(res, 422, 'content is required');
  if (body.content === '') return problem(res, 422, 'content is required');
  const content = makeWellFormed(body.content); // CONTAIN before store (a re-read must never 5xx)
  if (Buffer.byteLength(content, 'utf8') > maxContentBytes()) return problem(res, 422, 'content is too large');
  // NULL PARITY (x3): an explicit `null` for an OPTIONAL field is treated as ABSENT (use the default) — matching go (a
  // JSON null decodes to a nil *T) and py (Optional[...]). content is required (null -> 422); a null tag/metadata VALUE
  // is an invalid value (not a string -> 422).
  const scopeRaw = body.scope === undefined || body.scope === null ? 'default' : body.scope;
  if (typeof scopeRaw !== 'string') return problem(res, 422, 'the scope must be a string');
  const scope = cleanScope(res, scopeRaw);
  if (scope === null) return;
  const tags = cleanTags(res, body.tags);
  if (tags === null) return;
  const metadata = cleanMetadata(res, body.metadata);
  if (metadata === null) return;
  let importance = 0;
  if (body.importance !== undefined && body.importance !== null) {
    if (!isStrictInt(body, 'importance') || body.importance < 0) return problem(res, 422, 'importance must be a non-negative integer');
    importance = body.importance;
  }
  let ttlSet = false;
  let ttl = 0;
  if (body.ttl_seconds !== undefined && body.ttl_seconds !== null) {
    if (!isStrictInt(body, 'ttl_seconds') || body.ttl_seconds < 1) return problem(res, 422, 'ttl_seconds must be a positive integer');
    ttl = body.ttl_seconds;
    ttlSet = true;
  }
  const now = testNow(req);
  const expires_at = expiresAt(now, ttl, ttlSet);
  const id = await nextId('ai_memory_id'); // server-mint (globally unique); a rejected add wastes it as a benign gap
  if (await reserveScope(owner, scope)) return problem(res, 422, 'too many scopes'); // bound the partition COUNT first
  const evicted = await appendEvict(owner, scope, { id, created_at: now, expires_at, importance }, now);
  // the row, written AFTER the do seams (the callbacks are pure). A crash here leaves a benign skew the read-side
  // existence check hides (a 404, never a torn 500).
  await storePut(MEM, mkey(owner, id), { id, owner, scope, content, tags, metadata, importance, created_at: now, expires_at });
  if (evicted !== 0) await storeDelete(MEM, mkey(owner, evicted)); // purge the evicted row (the index already dropped it)
  const out = { id, scope, created_at: now };
  if (expires_at !== 0) out.expires_at = expires_at;
  sendJSON(res, 201, out);
}

export async function aiMemoryList(req, res) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const url = new URL(req.url, 'http://localhost').searchParams;
  const scope = cleanScope(res, url.get('scope') || 'default'); // empty/missing -> the "default" partition
  if (scope === null) return;
  const now = testNow(req);
  // read-scope: owner. The OWNER index is authoritative for scope existence: a scope not listed for this owner has NO
  // retrievable memories, so gating here keeps the retrievable set bounded even if a concurrent forget_scope||add
  // orphaned the scope index (the two-key race, closed on the RETRIEVABLE surface). [I-RACE-FORGET-SCOPE]
  const ownerScopes = (await storeGet(OWNER, owner)) || [];
  const entries = ownerScopes.includes(scope) ? ((await storeGet(SCOPE, skey(owner, scope))) || []) : [];
  let rows = [];
  for (const e of entries) {
    if (expired(e, now)) continue; // lazy expiry: an expired memory is read-hidden
    const rec = await storeGet(MEM, mkey(owner, e.id));
    if (rec !== undefined) rows.push(rec); // read-side check hides an index/row torn window
  }
  const tag = url.get('tag');
  if (tag) {
    const needle = makeWellFormed(tag);
    rows = rows.filter((r) => r.tags.includes(needle));
  }
  const qq = url.get('q');
  if (qq) {
    const needle = fold(makeWellFormed(qq));
    rows = rows.filter((r) => fold(r.content).includes(needle));
  }
  rows.sort((a, b) => (a.created_at !== b.created_at ? b.created_at - a.created_at : a.id - b.id)); // newest-first, tie id asc
  const views = rows.map(publicView);
  const { items, next, ok } = paginate(views, url.get('cursor') || '', url.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function aiMemoryGet(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const id = intParam(params.id); // STRICT path int: null for "1.0"/"abc"/control chars
  if (id === null) return problem(res, 422, 'invalid id');
  // unbounded-safe: a single memory by key; OWNER-scoped (the composite key includes owner -> not-yours == 404). The
  // scope index is LIVENESS-AUTHORITATIVE: an expired OR evicted/torn (not-in-index) memory is 404 (never resurrected).
  const rec = await storeGet(MEM, mkey(owner, id));
  if (rec === undefined) return problem(res, 404, 'memory not found');
  const now = testNow(req);
  // liveness = scope still in the OWNER index (race-safe) AND id in the scope index AND not expired. The owner-index
  // gate makes an orphan row (scope removed by a concurrent forget_scope) non-retrievable. [I-RACE-FORGET-SCOPE]
  const ownerScopes = (await storeGet(OWNER, owner)) || [];
  if (expired(rec, now) || !ownerScopes.includes(rec.scope) || !(await inIndex(owner, rec.scope, id))) {
    return problem(res, 404, 'memory not found');
  }
  sendJSON(res, 200, publicView(rec));
}

export async function aiMemoryForget(req, res, params) {
  const owner = await requireIdentity(req, res); // mutation-auth: identity — forget ONE memory (owner-scoped: not-yours == 404)
  if (owner === null) return;
  const id = intParam(params.id);
  if (id === null) return problem(res, 422, 'invalid id');
  const rec = await storeGet(MEM, mkey(owner, id));
  if (rec === undefined) return problem(res, 404, 'memory not found'); // idempotent re-delete / cross-owner -> 404
  await storeDo(SCOPE, skey(owner, rec.scope), (cur) => [(cur || []).filter((e) => e.id !== id), null]); // filtered rebuild (shrinks)
  await storeDelete(MEM, mkey(owner, id));
  res.writeHead(204);
  res.end();
}

export async function aiMemoryForgetScope(req, res) {
  const owner = await requireIdentity(req, res); // mutation-auth: identity — forget a WHOLE scope
  if (owner === null) return;
  const scopeRaw = new URL(req.url, 'http://localhost').searchParams.get('scope');
  if (!scopeRaw) return problem(res, 422, 'scope is required'); // no silent wipe-all
  const scope = cleanScope(res, scopeRaw);
  if (scope === null) return;
  // OWNER-FIRST (B): remove the scope from the owner index atomically BEFORE reaping its index + rows. Reads gate on the
  // owner index, so the scope's memories are non-retrievable the instant this returns; a concurrent add that re-reserves
  // the scope re-counts it (a bounded counted-but-empty slot) instead of an uncounted-retrievable orphan.
  await storeDo(OWNER, owner, (cur) => [(cur || []).filter((s) => s !== scope), null]); // free the scope slot (rebuild)
  const entries = (await storeGet(SCOPE, skey(owner, scope))) || [];
  for (const e of entries) await storeDelete(MEM, mkey(owner, e.id)); // delete every row in the scope
  await storeDelete(SCOPE, skey(owner, scope)); // drop the scope index
  res.writeHead(204);
  res.end();
}
