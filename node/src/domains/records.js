// records — the App-Layer DATA SUBSTRATE: declare a typed record schema, then owner-scoped CRUD
// (create/list/get/update/delete) over the durable store. Dangerous properties, all proven (same ×3 as python/go):
// (1) OWNER-SCOPED: a record belongs to the caller who created it (the core requireIdentity seam); the owner is
//     stamped from the authenticated subject, NEVER a body field. A by-id get/patch/delete of another caller's record
//     is 404 — byte-indistinguishable from missing (existence never leaks); the LIST returns only the caller's rows.
// (2) NO MASS-ASSIGNMENT: a write reads ONLY the DECLARED field names out of the body `fields` map (allowlist-READ,
//     via Object.hasOwn); a smuggled owner/id/type (top-level, in fields, or a case-variant) is never consulted.
// (3) EXACTLY-ONCE CREATE: id = scopedKey('/records', owner, key) — deterministic, owner-partitioned, idempotent —
//     written through claimOnce, so a repeat key returns the SAME record.
// (4) TYPED VALIDATION: each declared field validated per type with cross-language-identical accept/reject; PATCH is a
//     partial merge of validated declared fields through the atomic storeDo RMW seam; owner/id/created_at never client-writable.
// The record TYPE is authored here (the ×3 source of truth; the manifest x-record_schema mirrors it). The by-id slot
// key is the composite `<owner>\x1f<id>` so a cross-owner id lands in a different slot.
import { orgRole, problem, requireIdentity, sendJSON, storeDelete, storeDo, storeGet, storeValues, testNow } from '../core/runtime.js';
import { scopedKey } from '../parts/digest.js';
import { claimOnce } from '../parts/idempotent_claim.js';
import { paginate } from '../parts/paginate.js';
import { isWellFormed, makeWellFormed, safeNumber, sanitizeJson } from '../parts/well_formed.js';

// [0-9] not \d (\d would also match Unicode digits in some engines) — ×3 parity with python/go.
const DATE_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;
const DATETIME_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})?$/;

// The record TYPE — same field set + types as records.py / records.go.
const SCHEMA = [
  { name: 'title', type: 'text', required: true },
  { name: 'count', type: 'number', required: false },
  { name: 'done', type: 'boolean', required: false },
  { name: 'due', type: 'datetime', required: false },
  { name: 'day', type: 'date', required: false },
  { name: 'status', type: 'select', required: false, options: ['open', 'closed'] },
  { name: 'meta', type: 'json', required: false },
];

const publicView = (rec) => ({ id: rec.id, owner: rec.owner, created_at: rec.created_at, updated_at: rec.updated_at, fields: rec.fields });

// an ORG record's public view = the user view PLUS scope:'org' (the org partition marker). USER records stay byte-identical.
const orgPublicView = (rec) => ({ ...publicView(rec), scope: 'org' });

// recordsOrgCtx is the org-scope AUTHZ ladder (mirrors records.py _org_ctx / records.go recordsOrgCtx), applied BEFORE
// any body validation: the ?org= slug must be well-formed (a forged/control-char slug -> 422), then the caller must be
// an ACTIVE member of that org (the core orgRole seam, never a client field) — a non-member/pending/missing org is
// undefined -> 404, byte-identical to a missing record so existence never leaks. Returns the validated slug, or null
// (the error response is already sent).
async function recordsOrgCtx(res, org, caller) {
  if (!isWellFormed(org)) { problem(res, 422, 'the org slug must be non-empty with no control characters'); return null; }
  if ((await orgRole(org, caller)) === undefined) { problem(res, 404, 'record not found'); return null; }
  return org;
}

function dateOK(s) {
  // strict ISO format + field ranges, NOT calendar validity (NOT ×3-identical: go normalizes, node rolls over,
  // python raises) — an owned v2 hardening. ASCII digits guaranteed by the regex, so slicing is safe.
  if (!DATE_RE.test(s)) return false;
  const mo = Number(s.slice(5, 7));
  const da = Number(s.slice(8, 10));
  return mo >= 1 && mo <= 12 && da >= 1 && da <= 31;
}

function datetimeOK(s) {
  if (!DATETIME_RE.test(s)) return false;
  const mo = Number(s.slice(5, 7));
  const da = Number(s.slice(8, 10));
  const hh = Number(s.slice(11, 13));
  const mi = Number(s.slice(14, 16));
  const se = Number(s.slice(17, 19));
  return mo >= 1 && mo <= 12 && da >= 1 && da <= 31 && hh <= 23 && mi <= 59 && se <= 59;
}

// validateOne returns [validated, ''] or [null, message]; the message is byte-identical to python/go.
function validateOne(name, ftype, options, value) {
  switch (ftype) {
    case 'text':
      if (typeof value !== 'string') return [null, `field '${name}' must be text`];
      return [makeWellFormed(value), ''];
    case 'number':
      return safeNumber(name, value);
    case 'boolean':
      if (typeof value !== 'boolean') return [null, `field '${name}' must be a boolean`];
      return [value, ''];
    case 'date':
      if (typeof value !== 'string' || !dateOK(value)) return [null, `field '${name}' must be a date (YYYY-MM-DD)`];
      return [value, ''];
    case 'datetime':
      if (typeof value !== 'string' || !datetimeOK(value)) return [null, `field '${name}' must be an ISO-8601 datetime`];
      return [value, ''];
    case 'select':
      if (typeof value === 'string' && options.includes(value)) return [value, ''];
      return [null, `field '${name}' is not an allowed option`];
    default:
      return sanitizeJson(name, value); // json: recursed — surrogate-safe strings + the ×3-safe number ceiling
  }
}

function validateFields(fieldsIn, creating) {
  // returns [out, ''] or [null, message]
  if (typeof fieldsIn !== 'object' || fieldsIn === null || Array.isArray(fieldsIn)) return [null, 'fields must be an object'];
  const out = {};
  for (const f of SCHEMA) {
    if (Object.hasOwn(fieldsIn, f.name)) { // allowlist-READ: only DECLARED names, own props only
      const [vv, msg] = validateOne(f.name, f.type, f.options || [], fieldsIn[f.name]);
      if (msg) return [null, msg];
      out[f.name] = vv;
    } else if (creating && f.required) {
      return [null, `field '${f.name}' is required`];
    }
  }
  return [out, ''];
}

export async function recordsCreate(req, res, params, body) {
  const owner = await requireIdentity(req, res); // the runtime parsed the body already, so identity-first is fine
  if (owner === null) return;
  const org = new URL(req.url, 'http://localhost').searchParams.get('org');
  if (org) {
    const slug = await recordsOrgCtx(res, org, owner); // membership FIRST: 422 (bad slug) then 404 (non-member) BEFORE body validation
    if (slug === null) return;
    if (!body || typeof body.key !== 'string') return problem(res, 422, 'invalid body');
    if (!isWellFormed(body.key)) return problem(res, 422, 'the record key must be non-empty with no control characters');
    const [validated, msg] = validateFields(body.fields === undefined ? {} : body.fields, true);
    if (msg) return problem(res, 422, msg);
    const now = testNow(req);
    const rid = scopedKey('/records@org', slug, body.key); // a DISTINCT route literal -> a disjoint id space
    const rec = { id: rid, owner: slug, created_at: now, updated_at: now, fields: validated }; // owner = the verified org slug, never client-set
    const winner = await claimOnce('records_org_rows', `${slug}\x1f${rid}`, rec); // exactly-once per (org, key); a distinct partition
    return sendJSON(res, 201, orgPublicView(winner));
  }
  if (!body || typeof body.key !== 'string') return problem(res, 422, 'invalid body');
  if (!isWellFormed(body.key)) return problem(res, 422, 'the record key must be non-empty with no control characters');
  const [validated, msg] = validateFields(body.fields === undefined ? {} : body.fields, true);
  if (msg) return problem(res, 422, msg);
  const now = testNow(req);
  const rid = scopedKey('/records', owner, body.key); // owner from the token, never client-set
  const rec = { id: rid, owner, created_at: now, updated_at: now, fields: validated };
  const winner = await claimOnce('records_rows', `${owner}\x1f${rid}`, rec); // exactly-once: a repeat key returns the SAME record
  sendJSON(res, 201, publicView(winner));
}

export async function recordsList(req, res) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const org = new URL(req.url, 'http://localhost').searchParams.get('org');
  if (org) {
    const slug = await recordsOrgCtx(res, org, owner); // non-member (incl. missing org) -> 404, never a leaked empty page
    if (slug === null) return;
    const mine = (await storeValues('records_org_rows')).filter((r) => r.owner === slug)
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)).map(orgPublicView);
    const q = new URL(req.url, 'http://localhost').searchParams;
    const { items, next, ok } = paginate(mine, q.get('cursor') || '', q.get('limit') || '');
    if (!ok) return problem(res, 422, 'invalid cursor or limit');
    return sendJSON(res, 200, { results: items, next_cursor: next });
  }
  // SCOPED read: only the caller's rows leave the store (filtered on the authenticated owner FIELD as stored, never
  // a client-supplied value), id-sorted (ASCII hex -> lexicographic agrees ×3) for a stable paged walk, then a
  // BOUNDED page; a stranger gets an empty page, never 403.
  const mine = (await storeValues('records_rows')).filter((r) => r.owner === owner)
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)).map(publicView);
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(mine, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function recordsGet(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const org = new URL(req.url, 'http://localhost').searchParams.get('org');
  if (org) {
    const slug = await recordsOrgCtx(res, org, owner); // non-member -> 404 (same 404 as a missing org record)
    if (slug === null) return;
    const rec = await storeGet('records_org_rows', `${slug}\x1f${params.record_id}`);
    if (rec === undefined) return problem(res, 404, 'record not found');
    return sendJSON(res, 200, orgPublicView(rec));
  }
  const rec = await storeGet('records_rows', `${owner}\x1f${params.record_id}`); // cross-owner id -> different slot -> 404
  if (rec === undefined) return problem(res, 404, 'record not found');
  sendJSON(res, 200, publicView(rec));
}

export async function recordsUpdate(req, res, params, body) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const org = new URL(req.url, 'http://localhost').searchParams.get('org');
  if (org) {
    const slug = await recordsOrgCtx(res, org, owner); // membership FIRST (404) before body validation (422)
    if (slug === null) return;
    const [validated, msg] = validateFields(body && body.fields !== undefined ? body.fields : {}, false);
    if (msg) return problem(res, 422, msg);
    const now = testNow(req);
    const rec = await storeDo('records_org_rows', `${slug}\x1f${params.record_id}`, (cur) => {
      if (cur === undefined) return [undefined, undefined];
      const merged = { ...cur, fields: { ...cur.fields, ...validated }, updated_at: now }; // owner/id/created_at untouched
      return [merged, merged];
    });
    if (rec === undefined) return problem(res, 404, 'record not found');
    return sendJSON(res, 200, orgPublicView(rec));
  }
  const [validated, msg] = validateFields(body && body.fields !== undefined ? body.fields : {}, false); // validate BEFORE the transaction
  if (msg) return problem(res, 422, msg);
  const now = testNow(req);
  const rec = await storeDo('records_rows', `${owner}\x1f${params.record_id}`, (cur) => {
    if (cur === undefined) return [undefined, undefined]; // 404 (no resurrection)
    const merged = { ...cur, fields: { ...cur.fields, ...validated }, updated_at: now }; // owner/id/created_at untouched
    return [merged, merged];
  });
  if (rec === undefined) return problem(res, 404, 'record not found');
  sendJSON(res, 200, publicView(rec));
}

export async function recordsDelete(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const org = new URL(req.url, 'http://localhost').searchParams.get('org');
  if (org) {
    const slug = await recordsOrgCtx(res, org, owner); // non-member -> 404 (existence never leaks)
    if (slug === null) return;
    const composite = `${slug}\x1f${params.record_id}`;
    if ((await storeGet('records_org_rows', composite)) === undefined) return problem(res, 404, 'record not found');
    await storeDelete('records_org_rows', composite);
    res.writeHead(204);
    res.end();
    return;
  }
  const composite = `${owner}\x1f${params.record_id}`;
  if ((await storeGet('records_rows', composite)) === undefined) return problem(res, 404, 'record not found'); // idempotent re-delete / cross-owner -> 404
  await storeDelete('records_rows', composite);
  res.writeHead(204);
  res.end();
}
