// file_store HTTP handlers — REAL byte objects behind a swappable provider: base64-in-JSON upload, raw-bytes
// download (the stored Content-Type reflected + the stored-XSS defense headers), JSON meta/list/delete, per-owner
// file-COUNT AND total-BYTES quotas. The row (never the index) is the content authority for GET/meta; the index is
// the delete-existence authority. Same names + DECISIONS as the python/go impls. Store + validators live in
// store.js/validate.js (this file stays under the 400-LOC budget).
import { problem, sendJSON, requireIdentity, testNow } from '../../core/runtime.js';
import { digestHex } from '../../parts/digest.js';
import { paginate } from '../../parts/paginate.js';
import { provider, fsAdmit, fsRelease, fsIndexEntries, fsMaxBytes, fsMaxKeys } from './store.js';
import { normKey, cleanContentType, decodeB64 } from './validate.js';

export async function fileStorePut(req, res, params, body) {
  // mutation-auth: identity — the object is owned by the caller (the token subject, never a body field
  // [guarded_fields: owner]). AUTH before the body grammar (a no-token PUT is 401 x3). Validate EVERYTHING before
  // the admission so a bad request never touches the index.
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  if (!body || typeof body.key !== 'string' || typeof body.content_b64 !== 'string') {
    return problem(res, 422, 'invalid body'); // key + content_b64 are REQUIRED strings (a number/missing is 422, like go's *string decode)
  }
  const key = normKey(body.key);
  if (key === null) return problem(res, 422, 'the object key is invalid');
  const ct = cleanContentType(body.content_type);
  if (ct === null) return problem(res, 422, 'content_type must be a valid type/subtype token');
  const raw = decodeB64(body.content_b64);
  if (raw === null) return problem(res, 422, 'content_b64 must be canonical base64');
  const size = raw.length; // derived: size — recomputed server-side; a smuggled value is ignored
  if (size > fsMaxBytes()) return problem(res, 422, 'file too large');
  const etag = digestHex(body.content_b64); // content-addressed over the CANONICAL b64 (via the digest part)
  const createdAt = testNow(req);
  const admit = await fsAdmit(owner, key, size); // RMW through the atomic index seam — never get-then-put
  if (admit === 'count') return problem(res, 422, `file count limit reached (max ${fsMaxKeys()})`);
  if (admit === 'quota') return problem(res, 422, 'storage quota exceeded');
  const p = provider();
  const row = { owner, key, content_b64: body.content_b64, content_type: ct, size, etag, created_at: createdAt };
  await p.put(owner, key, row); // THEN the object row (outside the do — a tear lands on the SAFE side)
  sendJSON(res, 201, { key, provider: p.name, size, etag, content_type: ct, created_at: createdAt });
}

export async function fileStoreList(req, res) {
  // read-scope: owner — the caller's own {key, size} served from the per-owner INDEX (one point-read, codepoint
  // order by construction — no namespace scan), BOUNDED through paginate. `size` here is the quota RESERVATION
  // (== actual outside a documented tear window); per-item etag/content_type live in /meta.
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const entries = await fsIndexEntries(owner);
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(entries, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items.map((e) => ({ key: e.key, size: e.size })), next_cursor: next });
}

export async function fileStoreMeta(req, res, params) {
  // read-scope: owner — the JSON mirror; `size` here is the ACTUAL (row) size. AUTH before the path grammar. Row
  // authority: a cross-owner key is a different composite -> 404 (existence never leaks).
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const key = normKey(params.file_key);
  if (key === null) return problem(res, 422, 'the object key is invalid');
  const row = await provider().get(owner, key);
  if (!row) return problem(res, 404, 'object not found');
  sendJSON(res, 200, { key: row.key, size: row.size, etag: row.etag,
    content_type: row.content_type, created_at: row.created_at });
}

export async function fileStoreGet(req, res, params) {
  // read-scope: owner — the REAL-bytes download. AUTH before the path grammar (a no-token probe is 401 x3). The row
  // (never the index) is the content authority; not-yours == 404. The stored content_type is reflected, PLUS the
  // stored-XSS defense (nosniff + bare attachment): a VALID text/html served same-origin is an attack the write
  // grammar cannot and should not block.
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const key = normKey(params.file_key);
  if (key === null) return problem(res, 422, 'the object key is invalid');
  const row = await provider().get(owner, key);
  if (!row) return problem(res, 404, 'object not found');
  const body = decodeB64(row.content_b64); // the stored b64 is canonical by construction -> always decodes (a Buffer)
  // setHeader (not a bare writeHead body) keeps the request-id/CORS headers already stamped; then flush + write bytes.
  res.setHeader('Content-Type', row.content_type); // the stored type, reflected
  res.setHeader('ETag', `"${row.etag}"`); // content-addressed, RFC 9110 quoted
  res.setHeader('X-Content-Type-Options', 'nosniff'); // stored-XSS defense: never sniff a text/html payload
  res.setHeader('Content-Disposition', 'attachment'); // ... and force download (bare token — no filename param)
  res.setHeader('Content-Length', String(body.length)); // explicit x3 (go auto-CLs only small bodies; node else chunks)
  res.writeHead(200);
  res.end(body);
}

export async function fileStoreDelete(req, res, params) {
  // mutation-auth: identity — free the quota slot. Row delete FIRST (idempotent), index-release LAST: the INDEX is
  // the delete-existence authority, so a phantom (entry, no row) is clearable (204) while a truly-missing key is 404.
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const key = normKey(params.file_key);
  if (key === null) return problem(res, 422, 'the object key is invalid');
  await provider().del(owner, key); // row first (idempotent)
  if (!(await fsRelease(owner, key))) return problem(res, 404, 'object not found'); // index release = the existence authority
  res.writeHead(204);
  res.end();
}
