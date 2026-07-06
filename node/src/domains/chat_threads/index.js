// chat_threads — a durable, owner-scoped AI-chat history store. Matches python/go; durable; see python/router.py
// for the full contract. (1) ORDERED — a message's position is a SERVER-MINTED, per-thread strictly-monotonic
// seq, incremented inside ONE atomic read-modify-write on the thread row: racing appends serialize to distinct
// consecutive seqs and the transcript reads back in exactly append order (a replay that reorders turns silently
// corrupts a model's context). (2) IMMUTABLE — no route edits or deletes a single message ("edit" in a chat
// product appends a new turn). (3) BOUNDED BOTH WAYS — messages-per-thread AND threads-per-owner are both capped,
// REJECT-past-cap 422, never a silent eviction (dropping a user's chat history is data loss). (4) OWNER-ISOLATED
// — owner = requireIdentity (never a body field); rows keyed `${owner}\x1f${id}` / `${owner}\x1f${id}\x1f${seq}`
// (ids + seqs are server-minted digits, so the key cannot be forged); not-yours == 404 on every surface; the
// per-owner index is the LIVENESS authority (a delete's crash residue is never resurrected). (5) CASCADE DELETE —
// owner-index-first: the cap slot is freed and the thread instantly non-listable, then the row is removed and the
// message rows reaped. last_seq is the honest high-water mark of accepted appends (a crash between mint and write
// is a seq gap — never a reorder). Threads list newest-activity-first; messages list seq ASC; both paginated.
// Same names + DECISIONS in all three languages.
import { intParam, nextId, problem, requireIdentity, sendJSON, storeDelete, storeDo, storeGet, storePut, testNow } from '../../core/runtime.js';
import { envInt } from '../../parts/env_int.js';
import { paginate } from '../../parts/paginate.js';
import { isWellFormed, makeWellFormed } from '../../parts/well_formed.js';

const INDEX = 'chat_threads_index';   // "<owner>"                     -> [thread id, ...] (liveness + the thread-COUNT bound)
const THREAD = 'chat_threads_thread'; // `${owner}\x1f${id}`           -> { id, owner, title, metadata, created_at, updated_at, last_seq }
const MSG = 'chat_threads_message';   // `${owner}\x1f${id}\x1f${seq}` -> { seq, thread_id, owner, role, content, metadata, created_at }

const ROLES = ['user', 'assistant', 'system', 'tool']; // the CLOSED role set, exact lowercase ("User" -> 422; a case-fold would drift x3)
const MAX_TITLE_BYTES = 256;    // a title is a display line (a fixed structural bound)
const MAX_META_PAIRS = 16;      // metadata bounds: the field's settled numbers (16 pairs, 64-char keys, 512-char values)
const MAX_META_KEY_CHARS = 64;
const MAX_META_VALUE_CHARS = 512;

const maxThreads = () => envInt(process.env.CHAT_THREADS_MAX_THREADS, 500, 1);      // threads per owner (reject past cap)
const maxMessages = () => envInt(process.env.CHAT_THREADS_MAX_MESSAGES, 1000, 1);   // messages per thread (reject past cap)
const maxContentBytes = () => envInt(process.env.CHAT_THREADS_MAX_CONTENT_BYTES, 16384, 1);

const tkey = (owner, id) => `${owner}\x1f${id}`;            // owner-partitioned thread rows (B can't reach A's id)
const mkey = (owner, id, seq) => `${owner}\x1f${id}\x1f${seq}`; // one immutable slot per (thread, seq)

// cleanTitle — an empty title is legal (an untitled thread). A NON-empty title is a display LINE: reject control
// characters (the shared identifier rule), contain a lone surrogate, cap bytes. Returns null on reject (already responded).
function cleanTitle(res, raw) {
  if (typeof raw !== 'string') { problem(res, 422, 'the title must be a string'); return null; }
  if (raw === '') return '';
  if (!isWellFormed(raw)) { problem(res, 422, 'the title must have no control characters'); return null; }
  const cleaned = makeWellFormed(raw);
  if (Buffer.byteLength(cleaned, 'utf8') > MAX_TITLE_BYTES) { problem(res, 422, 'the title is too large'); return null; }
  return cleaned;
}

// cleanMetadata — every value must be a string (number/bool/object/array/null -> 422); keys AND values are
// CONTAINED, then the CONTAINED, COLLAPSED dict is bounded: pair count + per-key/per-value CODE-POINT lengths
// (matching go, whose JSON decode already collapsed distinct lone-surrogate keys into one U+FFFD entry).
// Object.create(null) so a hostile "__proto__" key is stored as DATA (matches the py dict / go map).
function cleanMetadata(res, metadata) {
  if (metadata === undefined || metadata === null) return {};
  if (typeof metadata !== 'object' || Array.isArray(metadata) || !Object.values(metadata).every((v) => typeof v === 'string')) {
    problem(res, 422, 'metadata must be an object of string values'); return null;
  }
  const out = Object.create(null);
  for (const k of Object.keys(metadata)) out[makeWellFormed(k)] = makeWellFormed(metadata[k]);
  const keys = Object.keys(out);
  if (keys.length > MAX_META_PAIRS) { problem(res, 422, 'too many metadata entries'); return null; }
  for (const k of keys) {
    if ([...k].length > MAX_META_KEY_CHARS) { problem(res, 422, 'a metadata key is too long'); return null; }
    if ([...out[k]].length > MAX_META_VALUE_CHARS) { problem(res, 422, 'a metadata value is too long'); return null; }
  }
  return out;
}

// cleanContent — message content is free TEXT (multi-line chat turns are the norm), never a key component (keys
// are the owner + server-minted digits): contain a lone surrogate, cap bytes; control characters ride along as data.
function cleanContent(res, raw) {
  if (typeof raw !== 'string' || raw === '') { problem(res, 422, 'content must be a non-empty string'); return null; }
  const cleaned = makeWellFormed(raw);
  if (Buffer.byteLength(cleaned, 'utf8') > maxContentBytes()) { problem(res, 422, 'content is too large'); return null; }
  return cleaned;
}

// inIndex — the per-owner thread index is LIVENESS-AUTHORITATIVE: a thread is live only while its id is IN the
// index; every per-thread surface gates on it, so a delete's crash residue is never resurrected.
async function inIndex(owner, id) {
  return ((await storeGet(INDEX, owner)) || []).includes(id);
}

const threadPublic = (rec) => ({ id: rec.id, title: rec.title, metadata: rec.metadata, created_at: rec.created_at, updated_at: rec.updated_at, last_seq: rec.last_seq });
const messagePublic = (rec) => ({ seq: rec.seq, thread_id: rec.thread_id, role: rec.role, content: rec.content, metadata: rec.metadata, created_at: rec.created_at });

// reserveSlot — append `id` to the per-owner thread index; true iff REJECTED (past MAX_THREADS).
async function reserveSlot(owner, id) {
  const mx = maxThreads();
  let rejected = false;
  await storeDo(INDEX, owner, (cur) => {
    const tids = cur || [];
    if (tids.length >= mx) { rejected = true; return [undefined, null]; } // reject: leave unwritten (the thread-COUNT bound)
    // unbounded-safe: the per-owner thread list is bounded at MAX_THREADS by the reject-past-cap guard above — a
    // create past the cap is a loud 422, never an eviction (evicting a thread would silently delete a user's chat
    // history); bounding the number of threads bounds the KEY-SPACE, so the per-owner total is capped at
    // MAX_THREADS x MAX_MESSAGES by construction.
    return [[...tids, id], null];
  });
  return rejected;
}

export async function chatThreadsCreate(req, res, params, body) {
  const owner = await requireIdentity(req, res); // mutation-auth: identity — owner is the token subject, never a body field
  if (owner === null) return;
  let title = '';
  if (body && body.title !== undefined && body.title !== null) { // NULL PARITY: an explicit null is treated as absent (x3)
    title = cleanTitle(res, body.title);
    if (title === null) return;
  }
  const metadata = cleanMetadata(res, body ? body.metadata : undefined);
  if (metadata === null) return;
  const now = testNow(req);
  const id = await nextId('chat_threads_id'); // server-mint (globally unique); a cap-rejected create wastes it as a benign gap
  if (await reserveSlot(owner, id)) return problem(res, 422, 'too many threads'); // bound the thread COUNT first
  const rec = { id, owner, title, metadata, created_at: now, updated_at: now, last_seq: 0 };
  await storePut(THREAD, tkey(owner, id), rec); // ONE write — the row is born consistent
  sendJSON(res, 201, threadPublic(rec));
}

export async function chatThreadsList(req, res) {
  const owner = await requireIdentity(req, res); // read-scope: owner — the caller's own threads via the OWNER INDEX (never a store-wide scan)
  if (owner === null) return;
  const tids = (await storeGet(INDEX, owner)) || [];
  const rows = [];
  for (const tid of tids) {
    const rec = await storeGet(THREAD, tkey(owner, tid));
    if (rec !== undefined) rows.push(rec); // read-side check hides a create-tear ghost slot
  }
  rows.sort((a, b) => (a.updated_at !== b.updated_at ? b.updated_at - a.updated_at : b.id - a.id)); // newest activity first, tie: newest id
  const url = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(rows.map(threadPublic), url.get('cursor') || '', url.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function chatThreadsGet(req, res, params) {
  const owner = await requireIdentity(req, res); // read-scope: owner — the composite key includes the owner (not-yours == 404)
  if (owner === null) return;
  const id = intParam(params.id); // STRICT path int: null for "1.0"/"abc"/control chars
  if (id === null) return problem(res, 422, 'invalid id');
  const rec = await storeGet(THREAD, tkey(owner, id));
  if (rec === undefined || !(await inIndex(owner, id))) return problem(res, 404, 'thread not found'); // liveness-gated
  sendJSON(res, 200, threadPublic(rec));
}

export async function chatThreadsUpdate(req, res, params, body) {
  const owner = await requireIdentity(req, res); // mutation-auth: identity — rename/retag ONE of the caller's threads
  if (owner === null) return;
  const id = intParam(params.id);
  if (id === null) return problem(res, 422, 'invalid id');
  const titlePresent = !!body && body.title !== undefined && body.title !== null;      // NULL PARITY: null == absent
  const metaPresent = !!body && body.metadata !== undefined && body.metadata !== null;
  if (!titlePresent && !metaPresent) return problem(res, 422, 'nothing to update: provide title and/or metadata');
  let title = '';
  if (titlePresent) {
    title = cleanTitle(res, body.title);
    if (title === null) return;
  }
  let metadata = {};
  if (metaPresent) {
    metadata = cleanMetadata(res, body.metadata);
    if (metadata === null) return;
  }
  const now = testNow(req);
  if (!(await inIndex(owner, id))) return problem(res, 404, 'thread not found'); // liveness gate: absent / not-yours / ghost
  let missing = false;
  let updated = null;
  await storeDo(THREAD, tkey(owner, id), (cur) => {
    if (cur === undefined) { missing = true; return [undefined, null]; }
    const row = { ...cur, updated_at: now };
    if (titlePresent) row.title = title;
    if (metaPresent) row.metadata = metadata;
    updated = row;
    return [row, null]; // RMW through the atomic seam — never get-then-put; messages are untouched
  });
  if (missing) return problem(res, 404, 'thread not found');
  sendJSON(res, 200, threadPublic(updated));
}

export async function chatThreadsDelete(req, res, params) {
  const owner = await requireIdentity(req, res); // mutation-auth: identity — the cascade delete, owner-index-FIRST
  if (owner === null) return;
  const id = intParam(params.id);
  if (id === null) return problem(res, 422, 'invalid id');
  let rec = await storeGet(THREAD, tkey(owner, id));
  if (rec === undefined || !(await inIndex(owner, id))) return problem(res, 404, 'thread not found'); // re-delete -> 404
  // (a) free the cap slot + make the thread non-listable atomically (every read gates on the index)
  await storeDo(INDEX, owner, (cur) => [(cur || []).filter((t) => t !== id), null]); // a filtered rebuild (shrinks)
  // (b) remove the row (get/append/messages now 404) — re-read first so the reap covers the freshest accepted seq
  const fresh = await storeGet(THREAD, tkey(owner, id));
  if (fresh !== undefined) rec = fresh;
  await storeDelete(THREAD, tkey(owner, id));
  // (c) reap the message rows (best-effort, behind the liveness gate — a crash here leaves unreachable orphans only)
  for (let seq = 1; seq <= rec.last_seq; seq++) await storeDelete(MSG, mkey(owner, id, seq));
  res.writeHead(204);
  res.end();
}

export async function chatThreadsAppend(req, res, params, body) {
  const owner = await requireIdentity(req, res); // mutation-auth: identity — append one immutable turn to the caller's OWN thread
  if (owner === null) return;
  const id = intParam(params.id);
  if (id === null) return problem(res, 422, 'invalid id');
  if (!body || typeof body.role !== 'string' || !ROLES.includes(body.role)) {
    return problem(res, 422, 'role must be one of user|assistant|system|tool'); // the CLOSED set, exact lowercase ("User" -> 422)
  }
  const content = cleanContent(res, body.content);
  if (content === null) return;
  const metadata = cleanMetadata(res, body.metadata);
  if (metadata === null) return;
  const now = testNow(req);
  if (!(await inIndex(owner, id))) return problem(res, 404, 'thread not found'); // liveness gate: absent / not-yours / deleted
  let missing = false;
  let full = false;
  let seq = 0;
  await storeDo(THREAD, tkey(owner, id), (cur) => {
    if (cur === undefined) { missing = true; return [undefined, null]; }
    if (cur.last_seq >= maxMessages()) { full = true; return [undefined, null]; } // reject past the cap — history is never evicted
    // the seq mint: bounded by the cap (every increment costs an accepted request, so it can never approach the
    // integer ceiling); the updated_at bump lifts the thread in the activity-ordered list. A smuggled body
    // seq/owner/thread_id/created_at is simply never read [derived: seq].
    const row = { ...cur, last_seq: cur.last_seq + 1, updated_at: now };
    seq = row.last_seq;
    return [row, null];
  });
  if (missing) return problem(res, 404, 'thread not found');
  if (full) return problem(res, 422, 'thread is full');
  const rec = { seq, thread_id: id, owner, role: body.role, content, metadata, created_at: now };
  await storePut(MSG, mkey(owner, id, seq), rec); // the slot is written ONCE, after the mint (the do callback stays
  sendJSON(res, 201, messagePublic(rec));         // pure); a crash between mint and write is a seq GAP — never a reorder
}

export async function chatThreadsMessages(req, res, params) {
  const owner = await requireIdentity(req, res); // read-scope: owner — the transcript in replay order (seq ASC by construction)
  if (owner === null) return;
  const id = intParam(params.id);
  if (id === null) return problem(res, 422, 'invalid id');
  const rec = await storeGet(THREAD, tkey(owner, id));
  if (rec === undefined || !(await inIndex(owner, id))) return problem(res, 404, 'thread not found'); // liveness-gated
  const views = [];
  for (let seq = 1; seq <= rec.last_seq; seq++) { // a direct walk of the per-seq slots — no store-wide scan, so
    const msg = await storeGet(MSG, mkey(owner, id, seq)); // cross-owner isolation holds by key construction
    if (msg !== undefined) views.push(messagePublic(msg)); // a mint-tear gap is skipped (order intact, count honest)
  }
  const url = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(views, url.get('cursor') || '', url.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}
