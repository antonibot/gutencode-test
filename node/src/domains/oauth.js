// oauth — the OAuth 2.0 authorization-code flow, server side. Three dangerous properties, all proven:
// (1) CSRF DEFENSE: the callback's state must match a PENDING flow issued FOR THAT PROVIDER — forged/unknown is
// 403; the flow key binds provider+state. (2) SINGLE-USE, END TO END: the consume is ONE atomic read-modify-
// write through storeDo (two processes racing a code get one token, one 409), AND a consumed state can never be
// re-opened — authorize claims the key via the idempotent_claim part, so re-authorizing a used state is 409
// (a consumed flow stays dead; a naive implementation would resurrect it). (3) DENY-BY-DEFAULT: only configured providers. The access
// token is an UNGUESSABLE server-minted CSPRNG value bound to the flow on consume (never a forgeable digest of the
// client-supplied inputs). Store names and shapes match the python/go impls.
//
// BOTH mutating routes are intentionally PUBLIC (see each handler's `mutation-auth: public` declaration), NOT
// require_identity: the end-user is logged OUT across this whole flow. oauthAuthorize is a pre-session flow-init
// primitive (records a pending flow keyed by state); oauthCallback is reached by the browser hitting the OAuth
// redirect, also logged-out — and there the `state` value IS the credential (matched to a pending flow, single-use,
// atomically consumed). require_identity would break every real callback.
import { randomBytes } from 'node:crypto';

import { problem, sendJSON, storeDo } from '../core/runtime.js';
import { claimOnce } from '../parts/idempotent_claim.js';
import { isWellFormed } from '../parts/well_formed.js';

const mintToken = () => `tok_${randomBytes(24).toString('base64url')}`; // CSPRNG, unguessable, server-minted

const PROVIDERS = new Set(['google', 'github']);
// state in store: ns "oauth_flows" `${provider}:${state}` -> {provider, state, status: pending|consumed}

const flowKey = (provider, state) => `${provider}:${state}`; // provider is VALIDATED vocabulary — no key forgery

export async function oauthAuthorize(req, res, params, body) {
  // mutation-auth: public — INTENTIONALLY unauthenticated. This is a pre-session, server-side flow-INITIATION
  // primitive: it records a PENDING flow keyed by state while the end-user is still logged OUT, so requiring a
  // session would break the start of every OAuth flow. (Follow-on: a later wave may gate this behind the user's
  // session for explicit consent — which would also close the state-squatting -> denial-of-login risk, where an
  // attacker pre-claims a victim's state value.)
  if (!body || !isWellFormed(body.provider) || !isWellFormed(body.state)) {
    return problem(res, 422, 'invalid body');
  }
  if (!PROVIDERS.has(body.provider)) return problem(res, 422, 'unknown provider'); // deny-by-default
  const flow = { provider: body.provider, state: body.state, status: 'pending' };
  // a state is single-use END TO END: claim atomically — a PENDING replay is harmless (same record back),
  // but a CONSUMED flow must never silently re-open
  const settled = await claimOnce('oauth_flows', flowKey(body.provider, body.state), flow);
  if (settled.status !== 'pending') return problem(res, 409, 'state already used');
  sendJSON(res, 201, settled);
}

export async function oauthCallback(req, res, params, body) {
  // mutation-auth: public — INTENTIONALLY unauthenticated. The browser hitting the OAuth redirect is logged OUT,
  // and the `state` value IS the capability credential: it is matched to a PENDING flow the server issued,
  // single-use, and atomically consumed (forged/unknown state -> 403; replay -> 409). require_identity would
  // break every real callback, since there is no session at the redirect.
  if (!body || !isWellFormed(body.provider) || !isWellFormed(body.state) || !isWellFormed(body.code)) {
    return problem(res, 422, 'invalid body');
  }
  if (!PROVIDERS.has(body.provider)) return problem(res, 422, 'unknown provider');
  const [kind, token] = await storeDo('oauth_flows', flowKey(body.provider, body.state), (flow) => {
    if (flow === undefined) return [undefined, ['forged', null]];        // no pending flow -> CSRF / forged
    if (flow.status === 'consumed') return [undefined, ['replay', null]]; // SINGLE-USE: already exchanged
    // mint an UNGUESSABLE server-side token (CSPRNG) and bind it to the flow in the SAME atomic consume — never a
    // deterministic digest of the client-supplied (provider, state, code) that anyone could forge offline.
    const t = mintToken();
    return [{ ...flow, status: 'consumed', token: t }, ['ok', t]];
  });
  if (kind === 'forged') return problem(res, 403, 'invalid state');
  if (kind === 'replay') return problem(res, 409, 'authorization code already used');
  sendJSON(res, 200, { provider: body.provider, state: body.state, access_token: token, status: 'authorized' });
}
