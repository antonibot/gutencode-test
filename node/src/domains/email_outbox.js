// email — outbound email behind a provider PORT, two dangerous properties proven, matching python/go:
// (1) EXACTLY-ONCE DISPATCH: idempotent on the Idempotency-Key via scopedKey + claimOnce (the atomic storeDo RMW)
// — two processes racing one key produce ONE recorded message, the loser is served the winner. The slot is SCOPED
// to the authenticated caller (a key is PRIVATE). A same-key retry with ANY different message (recipient/subject/
// body/template) is 409 — never a silent re-send, never a dropped Bcc. (2) HEADER SAFETY: every header-bound field
// rejects CR/LF + control/NEL/line-separator (addresses via validEmail, the rendered subject via validHeaderText,
// AFTER template rendering) so a subject (or a template value rendered into it) can never open a second header line;
// we REJECT (422), stricter than silent sanitizers. OWNER-scoped (owner = requireIdentity, never a body field):
// another caller's message is 404. Append-only; durable (a keyed send dedups after restart). Offline: the default
// backend RECORDS to the store (the record IS the outbox); a real provider is the dispatch swap-point (INTEROP.md).
import { intParam, nextId, problem, requireIdentity, sendJSON, storeGet, storePut, storeValues, testNow } from '../core/runtime.js';
import { digestHex, scopedKey } from '../parts/digest.js';
import { claimOnce } from '../parts/idempotent_claim.js';
import { paginate } from '../parts/paginate.js';
import { isWellFormed, makeWellFormed } from '../parts/well_formed.js';

const ROUTE = 'POST /email_outbox/messages';     // the dedup-slot discriminator (per-operation, owner-scoped slot)
const MAX_SUBJECT_BYTES = 998;            // RFC 5322 §2.1.1 line length — a hard protocol limit

// an operator LIMIT: a positive int within the 2^53-safe range (so go/node/python AGREE ×3 — env-knob overflow class).
function envLimit(name, def) {
  const raw = process.env[name];
  if (raw === undefined) return def;
  const v = Number(raw);
  return Number.isSafeInteger(v) && v >= 1 ? v : def;
}
const MAX_RECIPIENTS = envLimit('EMAIL_MAX_RECIPIENTS', 50);
const MAX_BODY_BYTES = envLimit('EMAIL_MAX_BODY_BYTES', 262144);

// THE TEMPLATE REGISTRY (policy, code-reviewed) — id -> {subject, html, text}; same data + same render ×3. NEVER empty.
const TEMPLATES = {
  verify_email: { subject: 'Verify your email address', html: '<p>Hi {{name}},</p><p>Confirm your address: {{link}}</p>', text: 'Hi {{name}},\nConfirm your address: {{link}}' },
  reset_password: { subject: 'Reset your password', html: '<p>Hi {{name}},</p><p>Reset your password: {{link}}</p>', text: 'Hi {{name}},\nReset your password: {{link}}' },
  notify: { subject: 'New message: {{title}}', html: '<p>{{body}}</p>', text: '{{body}}' },
};
const PLACEHOLDER = /\{\{([A-Za-z0-9_]+)\}\}/g; // ASCII-explicit -> ×3 parity with py/go

const LOCAL_CHARS = new Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.!#$%&'*+/=?^_`{|}~-");
const LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

// validEmail — a strict boundary validator: a SUPERSET of the connector email_domain extractor + RFC 5321 caps + the
// WHATWG dot-atom charset. Surrounding whitespace is REJECTED (not trimmed — trimming differs ×3). Valid addresses
// are ASCII, so .length (UTF-16 units) == code points == octets for anything that could pass -> the decision is ×3.
function validEmail(s) {
  if (typeof s !== 'string' || s === '' || s.length > 254) return false;
  if ((s.match(/@/g) || []).length !== 1) return false;
  const at = s.indexOf('@');
  const local = s.slice(0, at);
  const domain = s.slice(at + 1);
  if (local === '' || domain === '' || local.length > 64 || domain.length > 255) return false;
  for (const c of local) if (!LOCAL_CHARS.has(c)) return false;
  const labels = domain.split('.');
  if (labels.length < 2) return false;
  for (const lbl of labels) if (!LABEL.test(lbl)) return false;
  return true;
}

// validHeaderText — the header-injection wall: reject CR/LF + the rest of C0, DEL, C1 (incl. NEL) and U+2028/U+2029.
function validHeaderText(s) {
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (c < 0x20 || c === 0x7F || (c >= 0x80 && c <= 0x9F) || c === 0x2028 || c === 0x2029) return false;
  }
  return true;
}

// render — scan the TEMPLATE for {{key}} (never iterate data -> deterministic ×3); a placeholder with no data value
// -> ok:false (a 422). Single-pass (a substituted value is not re-scanned). Object.hasOwn guards prototype keys.
function render(tpl, data) {
  let ok = true;
  const out = tpl.replace(PLACEHOLDER, (_m, key) => {
    if (!Object.hasOwn(data, key)) { ok = false; return ''; }
    return data[key];
  });
  return { out, ok };
}

const h = (s) => digestHex(s);                  // pre-hash one field to fixed colon-free hex
const hl = (xs) => digestHex(...xs.map(h));      // pre-hash each list element -> injective (the scoped_key idiom)

// bodyHashOf — the fingerprint over EVERY message-determining REQUEST field (digestHex joins with ':' and is NOT
// injective for free text, so each variable-length field is PRE-HASHED first). An added bcc / a changed data value
// all drift the hash -> a same-key reuse with any different message is 409.
function bodyHashOf(frm, to, cc, bcc, reply, subject, html, text, tid, data) {
  const dparts = Object.keys(data).sort().flatMap((k) => [h(k), h(data[k])]);
  return digestHex('from', h(frm), 'to', hl(to), 'cc', hl(cc), 'bcc', hl(bcc), 'reply', hl(reply),
    'subj', h(subject), 'html', h(html), 'text', h(text), 'tid', h(tid), 'data', digestHex(...dparts));
}

// dispatch — the offline fake backend: the stored record IS the sent message (record-to-store). A real backend
// transmits here; the INTEROP swap-point. Called ONLY on a fresh claim, so a retried/raced send never sends twice.
function dispatch(rec) {}

const publicView = (m) => ({ id: m.id, from: m.from, to: m.to, cc: m.cc, bcc: m.bcc, reply_to: m.reply_to, subject: m.subject, created_at: m.created_at });

// undefined -> []; an array of strings -> itself; anything else -> null (invalid type)
function asStringArray(v) {
  if (v === undefined) return [];
  if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return v;
  return null;
}

export async function emailOutboxSend(req, res, params, body) {
  const owner = await requireIdentity(req, res); // authenticated mutation (no/invalid token -> 401), before any write
  if (owner === null) return;
  if (!body || typeof body !== 'object' || Array.isArray(body)) return problem(res, 422, 'invalid body');
  if (typeof body.from !== 'string' || !validEmail(body.from)) return problem(res, 422, 'from is not a valid email address');
  const to = asStringArray(body.to);
  const cc = asStringArray(body.cc);
  const bcc = asStringArray(body.bcc);
  const reply = asStringArray(body.reply_to);
  if (to === null || cc === null || bcc === null || reply === null) return problem(res, 422, 'invalid body');
  for (const group of [to, cc, bcc, reply]) for (const a of group) if (!validEmail(a)) return problem(res, 422, 'a recipient address is not valid');
  if (to.length === 0) return problem(res, 422, 'to must contain at least one recipient');
  if (to.length + cc.length + bcc.length > MAX_RECIPIENTS) return problem(res, 422, 'too many recipients');
  const seen = new Set();
  for (const group of [to, cc, bcc]) for (const a of group) {
    if (seen.has(a)) return problem(res, 422, 'a recipient address is duplicated across to, cc and bcc');
    seen.add(a);
  }
  const hasTpl = body.template !== undefined && body.template !== null;
  const hasRaw = body.subject !== undefined || body.html !== undefined || body.text !== undefined;
  if (hasTpl && hasRaw) return problem(res, 422, 'provide either a template or subject and body, not both');
  let subject;
  let html;
  let text;
  let bodyHash;
  let data = {};
  if (hasTpl) {
    const t = body.template;
    if (typeof t !== 'object' || Array.isArray(t) || typeof t.id !== 'string') return problem(res, 422, 'invalid body');
    if (t.data !== undefined) {
      if (typeof t.data !== 'object' || t.data === null || Array.isArray(t.data) || !Object.values(t.data).every((v) => typeof v === 'string')) {
        return problem(res, 422, 'invalid body');
      }
      data = t.data;
    }
    if (!Object.hasOwn(TEMPLATES, t.id)) return problem(res, 422, 'unknown template');
    // CONTAIN the data values BEFORE render + fingerprint (a lone surrogate cannot be UTF-8-hashed -> would throw).
    const cdata = {};
    for (const k of Object.keys(data)) cdata[k] = makeWellFormed(data[k]);
    const tpl = TEMPLATES[t.id];
    const r1 = render(tpl.subject, cdata);
    const r2 = render(tpl.html, cdata);
    const r3 = render(tpl.text, cdata);
    if (!r1.ok || !r2.ok || !r3.ok) return problem(res, 422, 'template variable not provided');
    subject = makeWellFormed(r1.out); html = makeWellFormed(r2.out); text = makeWellFormed(r3.out);
    bodyHash = bodyHashOf(body.from, to, cc, bcc, reply, '', '', '', t.id, cdata);
  } else {
    if (body.subject !== undefined && typeof body.subject !== 'string') return problem(res, 422, 'invalid body');
    if (body.html !== undefined && typeof body.html !== 'string') return problem(res, 422, 'invalid body');
    if (body.text !== undefined && typeof body.text !== 'string') return problem(res, 422, 'invalid body');
    if (typeof body.subject !== 'string' || (body.html === undefined && body.text === undefined)) {
      return problem(res, 422, 'a raw send needs a subject and at least one of html or text');
    }
    // CONTAIN BEFORE the fingerprint (a lone surrogate from a \u-escape cannot be UTF-8-hashed).
    subject = makeWellFormed(body.subject); html = makeWellFormed(body.html || ''); text = makeWellFormed(body.text || '');
    bodyHash = bodyHashOf(body.from, to, cc, bcc, reply, subject, html, text, '', {});
  }
  // RENDER-THEN-VALIDATE: header-safety + bounds on the CONTAINED, rendered output.
  if (!validHeaderText(subject)) return problem(res, 422, 'subject must not contain control characters or line breaks');
  if (Buffer.byteLength(subject, 'utf8') > MAX_SUBJECT_BYTES) return problem(res, 422, 'subject is too long');
  if (Buffer.byteLength(html, 'utf8') + Buffer.byteLength(text, 'utf8') > MAX_BODY_BYTES) return problem(res, 422, 'message body is too large');
  const created_at = testNow(req);
  const build = (eid) => ({ id: eid, owner, from: body.from, to, cc, bcc, reply_to: reply, subject, html, text, created_at, body_hash: bodyHash });
  const key = req.headers['idempotency-key'];
  if (key === undefined) { // no key -> no dedupe (opt-in)
    const eid = await nextId('email_outbox_message');
    const rec = build(eid);
    await storePut('email_outbox_messages', String(eid), rec);
    dispatch(rec);
    return sendJSON(res, 201, publicView(rec));
  }
  let nKeys = 0; // a single opaque token; node comma-joins duplicate headers, so count raw header lines and reject >1 (×3)
  for (let i = 0; i < req.rawHeaders.length; i += 2) if (req.rawHeaders[i].toLowerCase() === 'idempotency-key') nKeys += 1;
  if (nKeys > 1) return problem(res, 422, 'Idempotency-Key must be a single value');
  if (!isWellFormed(key)) return problem(res, 422, 'Idempotency-Key must be non-empty with no control characters');
  const scoped = scopedKey(ROUTE, owner, key);
  let prior = await storeGet('email_outbox_messages', scoped); // fast path: a settled key never mints
  if (prior === undefined) {
    const eid = await nextId('email_outbox_message'); // mint BEFORE the claim (a race loser's id is a harmless gap)
    const rec = build(eid);
    prior = await claimOnce('email_outbox_messages', scoped, rec);
    if (prior.id === eid) dispatch(prior); // I won the claim -> send ONCE
  }
  if (prior.owner !== owner) return problem(res, 409, 'Idempotency-Key is not owned by this caller');
  if (prior.body_hash !== bodyHash) return problem(res, 409, 'Idempotency-Key reused with a different message');
  sendJSON(res, 201, publicView(prior));
}

export async function emailOutboxList(req, res) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const rows = (await storeValues('email_outbox_messages')).filter((m) => m.owner === owner).sort((a, b) => a.id - b.id).map(publicView);
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(rows, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function emailOutboxGet(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const id = intParam(params.message_id);
  if (id === null) return problem(res, 422, 'invalid message id');
  // unbounded-safe: a single-record lookup by id (returns at most one row); OWNER-scoped — not-yours == 404
  for (const m of await storeValues('email_outbox_messages')) {
    if (m.id === id && m.owner === owner) return sendJSON(res, 200, publicView(m));
  }
  return problem(res, 404, 'message not found');
}
