// ratelimit — fixed-window rate limiting. The dangerous property is that THE LIMIT HOLDS: at most LIMIT
// requests per key per window, the (LIMIT+1)th is 429, and — the part naive limiters get wrong — the consume is
// ONE atomic consume-or-deny read-modify-write through storeDo, so concurrent processes cannot race past the
// limit (a get-then-put limiter is breachable under load; this one is not). Windows derive from the test-clock
// seam; the counter is durable, so a restart never resets a window. LIMIT and WINDOW are env knobs. Store names
// and the row model match the python/go impls.
import { problem, requireService, sendJSON, storeDo, testNow } from '../core/runtime.js';
import { envInt } from '../parts/env_int.js';
import { isWellFormed } from '../parts/well_formed.js';

const LIMIT = envInt(process.env.RATELIMIT_LIMIT, 5);
const WINDOW = envInt(process.env.RATELIMIT_WINDOW, 60);
// state in store: ns "ratelimit_windows" `${key}:${windowId}` -> count (one row per key per window)

export async function ratelimitCheck(req, res, params, body) {
  // mutation-auth: service — a server-side throttle PRIMITIVE, NOT a user action, gated by the trusted SERVICE
  // seam (core.requireService), NOT requireIdentity: the throttle runs BEFORE the user is authenticated (login
  // brute-force protection throttles the username on the login attempt itself, pre-auth) and its subject is the
  // caller-supplied `body.key` (an ip/username/api-key) which the trusted service vouches for. The runtime already
  // parsed the body (PARSE), so AUTH is first in the handler, then the strict key check (SEMANTIC) — an
  // unauthenticated ill-typed body is 401 not 422, ×3. The `mutation-auth: service` declaration + the requireService
  // call sit in one handler — the declaration cannot drift from the enforcement.
  if (requireService(req, res) === null) return;
  if (!body || !isWellFormed(body.key)) return problem(res, 422, 'invalid body');
  const windowId = Math.floor(testNow(req) / WINDOW);
  // ATOMIC consume-or-deny: read the count and increment it in ONE exclusive transaction — two processes
  // racing the same key cannot both see count==LIMIT-1 and both pass. fn stays pure (no store calls inside).
  const remaining = await storeDo('ratelimit_windows', `${body.key}:${windowId}`, (count) => {
    const n = count || 0;
    if (n >= LIMIT) return [undefined, -1]; // deny: leave the row untouched
    return [n + 1, LIMIT - (n + 1)];
  });
  if (remaining < 0) return problem(res, 429, 'rate limit exceeded');
  sendJSON(res, 200, { allowed: true, remaining });
}
