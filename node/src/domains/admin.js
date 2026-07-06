// admin — the guarded admin surface. (1) DENY-BY-DEFAULT GUARD: every route requires a valid admin bearer
// token compared CONSTANT-TIME against the env-backed secret; a missing/wrong token is 401 and an unauthorized
// mutation records NOTHING. (2) APPEND-ONLY: authorized actions get a monotonic id; no update or delete route.
// Self-contained — no sibling-domain import. Matches python/go; durable. Ordering: structural validation (422)
// runs before the auth guard (401), mirroring the framework ordering.
import { createHash, timingSafeEqual } from 'node:crypto';

import { intParam, nextId, problem, sendJSON, storeGet, storePut, storeValues } from '../core/runtime.js';
import { paginate } from '../parts/paginate.js';
import { isWellFormed } from '../parts/well_formed.js';

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'admin_dev_token_change_me'; // env-backed, rotatable
// state in store: seq "admin_action" · ns "admin_actions" String(id) -> {id, action, target}

// identity-exempt: a break-glass ADMIN token (constant-time vs the env ADMIN_TOKEN), NOT a user session — the
// header parse here IS the admin-secret check, by design. Wave B migrates this to requireIdentity + an admin role.
// deny-by-default: a Bearer that does not constant-time-match the admin secret is rejected. timingSafeEqual
// needs equal-length buffers, so compare fixed-length sha256 digests of both sides (a length-safe CT compare).
function authorized(req) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const a = createHash('sha256').update(token).digest();
  const b = createHash('sha256').update(ADMIN_TOKEN).digest();
  return timingSafeEqual(a, b);
}

export async function adminRecord(req, res, params, body) {
  if (!body || !isWellFormed(body.action) || !isWellFormed(body.target)) {
    return problem(res, 422, 'invalid body'); // 422 before the guard (parity with the framework ordering)
  }
  if (!authorized(req)) return problem(res, 401, 'admin authorization required'); // never reaches the store unauthorized
  const aid = await nextId('admin_action');
  const rec = { id: aid, action: body.action, target: body.target };
  await storePut('admin_actions', String(aid), rec); // append-only
  sendJSON(res, 201, rec);
}

export async function adminList(req, res) {
  if (!authorized(req)) return problem(res, 401, 'admin authorization required'); // GUARD PRESERVED — admin-only trail
  // unscoped-read: admin — the action trail is GLOBAL by design (every action, not per-caller); the admin guard
  // above is the explicit privileged gate. No per-caller owner field — the whole trail is the resource.
  const actions = (await storeValues('admin_actions')).sort((a, b) => a.id - b.id); // stable id order, identical ×3
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(actions, q.get('cursor') || '', q.get('limit') || ''); // bound the list
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function adminGet(req, res, params) {
  const id = intParam(params.action_id);
  if (id === null) return problem(res, 422, 'invalid action id'); // 422 before the guard (rejects 5.0 like py/go)
  if (!authorized(req)) return problem(res, 401, 'admin authorization required');
  const rec = await storeGet('admin_actions', String(id));
  if (rec === undefined) return problem(res, 404, 'action not found');
  sendJSON(res, 200, rec);
}
