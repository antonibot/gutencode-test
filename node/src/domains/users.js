// users — profiles + lifecycle, separate from auth credentials. (1) HANDLE UNIQUENESS: a handle is claimed
// exactly once via the idempotent_claim part — two processes racing the same handle create ONE user; a
// duplicate create is 409, never a silent overwrite. (2) MONOTONIC LIFECYCLE: deactivation is a terminal-value
// write — idempotent, race-convergent, never reversed. (3) IDENTITY: both mutations require the core
// requireIdentity seam (no/invalid token -> 401). CREATE is AUTHENTICATED-SELF — auth first, then field
// validation (422), then handle === caller (else 403, closing handle-squatting); the runtime parsed the body
// before the handler, so a no-token caller is 401 before any 422, matching python/go. DEACTIVATE is
// SELF-OR-ADMIN — auth first, then the self-or-admin authz (403, before the path-422/404), like the rbac
// admin pattern. (4) AUTHENTICATED READ: GET /{handle} requires a valid session (401 first, before the
// path-422/404) — visible to logged-in callers, not the anonymous public. Store names and shapes match python/go; durable.
import { isAdmin, nextId, problem, requireIdentity, sendJSON, storeGet, storePut } from '../core/runtime.js';
import { claimOnce } from '../parts/idempotent_claim.js';
import { isWellFormed } from '../parts/well_formed.js';

// state in store: seq "users_user" · ns "users_profiles" handle -> {id, handle, display_name, status}

export async function usersCreate(req, res, params, body) {
  const caller = await requireIdentity(req, res); // AUTH (runtime already parsed the body); 401 before any 422, ×3
  if (caller === null) return;
  if (!body || !isWellFormed(body.handle) || typeof body.display_name !== 'string' || body.display_name === '') {
    return problem(res, 422, 'invalid body'); // SEMANTIC field validation, after auth (mirrors python order)
  }
  if (body.handle !== caller) {
    return problem(res, 403, 'you may only create your own handle'); // AUTHENTICATED-SELF: closes handle-squatting
  }
  if ((await storeGet('users_profiles', body.handle)) !== undefined) {
    return problem(res, 409, 'handle taken'); // fast path: a settled handle never mints (ids stay contiguous)
  }
  // mint BEFORE the claim (a race loser's id is a gap), then claim the handle atomically — exactly one winner
  const rec = { id: await nextId('users_user'), handle: body.handle, display_name: body.display_name, status: 'active' };
  const settled = await claimOnce('users_profiles', body.handle, rec);
  if (settled.id !== rec.id) return problem(res, 409, 'handle taken'); // never silently overwrite a profile
  sendJSON(res, 201, settled);
}

async function lookup(req, res, params) {
  if (!isWellFormed(params.handle)) {
    problem(res, 422, 'the handle must be non-empty with no control characters');
    return null;
  }
  const user = await storeGet('users_profiles', params.handle);
  if (user === undefined) {
    problem(res, 404, 'user not found');
    return null;
  }
  return user;
}

export async function usersGet(req, res, params) {
  // AUTHENTICATED READ: visible to any logged-in caller (requireIdentity 401 first, before the path-422/404),
  // not the anonymous public; any authenticated caller may look up any handle. Returns only public fields.
  if ((await requireIdentity(req, res)) === null) return;
  const user = await lookup(req, res, params);
  if (user !== null) sendJSON(res, 200, user);
}

export async function usersDeactivate(req, res, params) {
  const caller = await requireIdentity(req, res); // AUTH first (path-only: 401 before path-422/404), ×3
  if (caller === null) return;
  // SELF-OR-ADMIN: the account owner OR a core admin may deactivate; anyone else is 403, resolved BEFORE the
  // well-formed/404 path checks (authn -> authz -> path/semantic), exactly as the rbac admin pattern orders it.
  if (caller !== params.handle && !(await isAdmin(caller))) {
    return problem(res, 403, 'you may only deactivate your own account');
  }
  const user = await lookup(req, res, params);
  if (user === null) return;
  // monotonic + idempotent: "deactivated" is TERMINAL — concurrent calls converge, nothing reactivates
  const deactivated = { ...user, status: 'deactivated' };
  await storePut('users_profiles', user.handle, deactivated);
  sendJSON(res, 200, deactivated);
}
