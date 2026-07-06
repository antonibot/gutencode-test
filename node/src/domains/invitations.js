// invitations — invite + accept with single-use, expiring tokens. The dangerous property is
// ACCEPT-AT-MOST-ONCE-AND-NEVER-EXPIRED: the token is server-minted and unguessable; accepting is an atomic
// single-use consume through storeDo (two processes racing one token yield one acceptance + one 409), and
// expiry beats availability — an expired token is 410 even if never used. The expiry comes from the test-clock
// seam. Tokens are durable. Store names and shapes match python/go.
//
// TWO routes, TWO auth models: invitationsCreate requires identity (requireIdentity) and STAMPS the inviter =
// the authenticated caller, derived from the bearer token and NEVER a client-supplied body field (auth BEFORE
// validation, so a no-token caller is 401, ×3). invitationsAccept is intentionally PUBLIC (see its
// `mutation-auth: public` declaration): the 192-bit single-use capability token IS the credential.
import { randomBytes } from 'node:crypto';

import { isStrictInt, problem, requireIdentity, sendJSON, storeDo, storePut, testNow } from '../core/runtime.js';
import { envInt } from '../parts/env_int.js';
import { isWellFormed } from '../parts/well_formed.js';

const DEFAULT_TTL = envInt(process.env.INVITATIONS_TTL, 604800); // 7 days
// state in store: ns "invitations_tokens" token -> {token, email, inviter, status, expires_at}

export async function invitationsCreate(req, res, params, body) {
  const inviter = await requireIdentity(req, res); // authn -> validation: auth BEFORE the body checks (×3)
  if (inviter === null) return;
  if (!body || !isWellFormed(body.email)) return problem(res, 422, 'invalid body');
  let ttl = DEFAULT_TTL;
  if (body.ttl !== undefined) {
    if (!isStrictInt(body, 'ttl') || body.ttl < 1 || body.ttl > 31536000) {
      return problem(res, 422, 'ttl must be an integer between 1 and 31536000');
    }
    ttl = body.ttl;
  }
  const token = randomBytes(24).toString('base64url'); // unguessable, server-side — never client-set
  // inviter derived from the token, never client-set — a smuggled `inviter` body field cannot override it.
  const rec = { token, email: body.email, inviter, status: 'pending', expires_at: testNow(req) + ttl };
  await storePut('invitations_tokens', token, rec); // a fresh random key — plain write, parity with python/go
  sendJSON(res, 201, rec);
}

export async function invitationsAccept(req, res, params) {
  // mutation-auth: public — INTENTIONALLY unauthenticated. The 192-bit single-use capability token IS the
  // credential: accept consumes a token a recipient already holds (typically while logged OUT), so requiring a
  // session would break the invite flow. The token's secrecy + single-use/expiry are the authorization.
  const token = params.token;
  if (!isWellFormed(token)) return problem(res, 422, 'the token must be non-empty with no control characters');
  const now = testNow(req);
  let outcome = '';
  let accepted = null;
  await storeDo('invitations_tokens', token, (rec) => {
    if (rec === undefined) { outcome = 'unknown'; return [undefined, null]; }
    if (now > rec.expires_at) { outcome = 'expired'; return [undefined, null]; } // expiry beats availability
    if (rec.status === 'accepted') { outcome = 'used'; return [undefined, null]; }
    accepted = { ...rec, status: 'accepted' };
    outcome = 'ok'; // atomic single-use: the FIRST accept wins
    return [accepted, null];
  });
  if (outcome === 'unknown') return problem(res, 404, 'invitation not found');
  if (outcome === 'expired') return problem(res, 410, 'invitation expired');
  if (outcome === 'used') return problem(res, 409, 'invitation already accepted');
  sendJSON(res, 200, accepted);
}
