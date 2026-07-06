// storage — object storage behind a swappable provider port (ports-and-adapters). USER-SCOPED: a stored
// object belongs to its uploader (the core requireIdentity seam), so every route is deny-by-default authenticated
// (no token -> 401) and an object is addressed by (owner, key) — caller A's `a.txt` and caller B's `a.txt` are
// DISTINCT objects (no cross-owner overwrite), the list returns ONLY the caller's own keys, and a cross-owner
// get/delete is 404 (byte-indistinguishable from missing — existence never leaks across owners). The dangerous
// property is INTEGRITY: round-trips are byte-for-byte and the etag is CONTENT-ADDRESSED (sha256 of the payload
// via the digest part), so corruption or substitution is always visible. The provider is selected ONCE
// (STORAGE_PROVIDER env, providers.js); handlers never name a backend. Store names and the object shape match
// the python/go impls.
import { problem, requireIdentity, sendJSON } from '../../core/runtime.js';
import { paginate } from '../../parts/paginate.js';
import { isWellFormed } from '../../parts/well_formed.js';
import { provider } from './providers.js';

function objectKey(res, raw) {
  if (!isWellFormed(raw)) {
    problem(res, 422, 'object key must be non-empty with no control characters');
    return null;
  }
  return raw;
}

export async function storagePut(req, res, params, body) {
  const owner = await requireIdentity(req, res); // the object is owned by the caller
  if (owner === null) return;
  // the key is an IDENTIFIER; the content is an opaque payload — a zero-byte object is valid
  if (!body || !isWellFormed(body.key) || typeof body.content !== 'string') {
    return problem(res, 422, 'invalid body');
  }
  sendJSON(res, 201, await provider().put(owner, body.key, body.content)); // stored under the (owner, key) pair
}

export async function storageList(req, res) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  // SCOPED read: only the caller's own bare keys ever leave the store (owner-filtered, prefix stripped), then a
  // BOUNDED page over that stable-ordered owner key set via the shared paginate part (the provider returns the
  // full owner list; bounding happens here, one layer up — so the provider signature stays stable across adapters).
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(await provider().keys(owner), q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function storageGet(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const key = objectKey(res, params.object_key);
  if (key === null) return;
  const obj = await provider().get(owner, key);
  if (obj === undefined) return problem(res, 404, 'object not found'); // not-yours == not-found
  sendJSON(res, 200, obj);
}

export async function storageDelete(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const key = objectKey(res, params.object_key);
  if (key === null) return;
  if (!(await provider().del(owner, key))) return problem(res, 404, 'object not found'); // not-yours == not-found
  res.writeHead(204);
  res.end();
}
