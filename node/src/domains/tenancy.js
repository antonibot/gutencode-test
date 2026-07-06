// tenancy — tenant isolation, the application-level row-scoping shape (models Postgres row-level security).
// Every row carries its tenant; EVERY read is scoped to the caller's tenant; a cross-tenant read is 404,
// byte-indistinguishable from a missing row (existence is never revealed across tenants). The tenant is the
// AUTHENTICATED identity (the core requireIdentity seam) — derived from the bearer token, NEVER a client-supplied
// X-Tenant-Id header — so a caller cannot read another tenant's rows by setting a header. Deny-by-default (no
// token -> 401). The demo resource is a note; the isolation pattern is the product. Store namespaces and the row
// shape match the python/go impls. (Minimal scope: tenant = authenticated principal; multi-user tenants via org
// membership are a follow-on.)
import { intParam, nextId, problem, requireIdentity, sendJSON, storeGet, storePut, storeValues } from '../core/runtime.js';
import { paginate } from '../parts/paginate.js';

export async function tenancyCreate(req, res, params, body) {
  const tenant = await requireIdentity(req, res);
  if (tenant === null) return;
  if (!body || typeof body.body !== 'string' || body.body.length === 0) {
    return problem(res, 422, 'invalid body');
  }
  const nid = await nextId('tenancy_note'); // atomic, durable; a crash before the put loses the id (a harmless gap)
  const row = { id: nid, tenant, body: body.body }; // tenant derived from the token, never client-set
  await storePut('tenancy_notes', String(nid), row);
  sendJSON(res, 201, row);
}

export async function tenancyList(req, res) {
  const tenant = await requireIdentity(req, res);
  if (tenant === null) return;
  // SCOPED read: only the caller's tenant's rows ever leave the store (filtered on the authenticated tenant),
  // then a bounded page over that owner-scoped list (store insertion order is stable + identical ×3).
  const items = (await storeValues('tenancy_notes')).filter((row) => row.tenant === tenant);
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items: page, next, ok } = paginate(items, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: page, next_cursor: next });
}

export async function tenancyGet(req, res, params) {
  const tenant = await requireIdentity(req, res);
  if (tenant === null) return;
  const nid = intParam(params.note_id);
  if (nid === null) return problem(res, 422, 'invalid note id'); // non-numeric/5.0 id -> 422, never a silent miss
  const row = await storeGet('tenancy_notes', String(nid));
  if (row === undefined || row.tenant !== tenant) {
    return problem(res, 404, 'note not found'); // not-yours == not-found: existence never leaks across tenants
  }
  sendJSON(res, 200, row);
}
