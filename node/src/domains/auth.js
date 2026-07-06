// auth — password authentication + the full session lifecycle, OWASP ASVS V2/V3-shaped and INTEROP-READY (the
// response envelope matches Supabase/Firebase/Auth0/Clerk/Cognito — see INTEROP.md). Passwords are salted + hashed
// via the CENTRAL password_hash part (PBKDF2-HMAC-SHA256, env-tunable iterations ≥ the ASVS floor); verify is
// constant-time and unknown-user == wrong-password (no enumeration, no timing leak). Sessions are the core
// "<id>.<secret>" seam (TTL + rotation + scoped logout). Registration is ENUMERATION-SAFE (silent success); email
// verify + password reset are single-use expiring token flows; pre-auth endpoints are throttled via the core seam.
// Store namespaces + record shapes match python/go; state survives a restart.
import { randomBytes, timingSafeEqual } from 'node:crypto';

import {
  problem, requireIdentity, sendJSON, sessionCreate, sessionResolve, sessionRotate, revokeCurrent,
  sessionRevokeAll, sessionTTLSeconds, throttle, storeGet, storePut, storeDo, testNow,
} from '../core/runtime.js';
import { digestHex } from '../parts/digest.js';
import { envInt } from '../parts/env_int.js';
import { hashPassword, verifyPassword } from '../parts/password_hash.js';
import { isWellFormed } from '../parts/well_formed.js';

const PW_MIN = 8;
const PW_MAX = 128; // min(8) ASVS 2.1.1; max(128) defends the unauth PBKDF2-DoS — COUNTS CODE POINTS (×3 parity)

function ctEqual(a, b) {
  const ba = Buffer.from(a, 'utf8'); const bb = Buffer.from(b, 'utf8');
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}
const randB64 = (n) => randomBytes(n).toString('base64');
const randURL = (n) => randomBytes(n).toString('base64url');
const pwOK = (pw) => { const n = [...pw].length; return n >= PW_MIN && n <= PW_MAX; };

const iterations = () => envInt(process.env.AUTH_PBKDF2_ITERATIONS, 200000, 100000);

async function throttleOK(res, action, key, now) {
  if (!(await throttle(`auth:${action}:${key}`, envInt(process.env.AUTH_THROTTLE_LIMIT, 10, 1), envInt(process.env.AUTH_THROTTLE_WINDOW, 300, 1), now))) {
    problem(res, 429, 'too many requests — slow down');
    return false;
  }
  return true;
}

function validCreds(res, body) {
  if (!body || typeof body.email !== 'string' || typeof body.password !== 'string'
      || !isWellFormed(body.email) || !pwOK(body.password)) {
    problem(res, 422, 'invalid body');
    return null;
  }
  return { email: body.email, password: body.password };
}

function userRecord(password, now) {
  const salt = randB64(16);
  return { salt, hash: hashPassword(password, salt, iterations()), email_verified: false, created_at: now };
}
// id is the email (a non-enumerable handle — NOT a sequential nextId)
const userOut = (email, rec) => ({ id: email, email, email_verified: !!(rec && rec.email_verified), created_at: (rec && rec.created_at) || 0 });

// the interop envelope. access_token == refresh_token == the rotating opaque server-side session token (single-token
// model; /refresh rotates it) — a DELIBERATE divergence from the AT/RT split (server-side sessions revoke immediately).
function envelopeBody(token, email, rec, now) {
  const ttl = sessionTTLSeconds();
  return { access_token: token, refresh_token: token, token_type: 'bearer', expires_in: ttl, expires_at: now + ttl, user: userOut(email, rec) };
}

const deliver = async (kind, to, token) => storePut('auth_outbox', `${kind}:${to}`, { to, kind, token });

async function mint(ns, subject, ttl, now) {
  const rid = randURL(12); const secret = randURL(32);
  await storePut(ns, rid, { subject, secret_hash: digestHex(secret), exp: now + ttl });
  return `${rid}.${secret}`;
}

// consume — SINGLE-USE: atomically (storeDo) verify + tombstone the token iff present, unexpired, secret matches.
async function consume(ns, token, now) {
  const i = (token || '').indexOf('.');
  if (i <= 0 || i >= token.length - 1) return null;
  const rid = token.slice(0, i); const secret = token.slice(i + 1);
  let subject = null;
  await storeDo(ns, rid, (cur) => {
    if (cur && now < (cur.exp || 0) && cur.secret_hash && ctEqual(digestHex(secret), cur.secret_hash)) {
      subject = cur.subject;
      return [{ subject: cur.subject, secret_hash: '', exp: 0 }, null]; // tombstone -> single-use
    }
    return [undefined, null];
  });
  return subject;
}

export async function authRegister(req, res, params, body) {
  // mutation-auth: public — ENUMERATION-SAFE signup (identical response new-or-existing; PBKDF2 on both paths).
  const c = validCreds(res, body); if (!c) return;
  const now = testNow(req);
  if (!(await throttleOK(res, 'register', c.email, now))) return;
  const record = userRecord(c.password, now); // PBKDF2 on both paths (flat timing) before the claim
  const created = await storeDo('auth_users', c.email, (cur) => (cur === undefined ? [record, true] : [undefined, false]));
  if (created) await deliver('verify', c.email, await mint('auth_verify', c.email, envInt(process.env.AUTH_VERIFY_TTL_SECONDS, 86400, 60), now));
  sendJSON(res, 200, { message: 'if the email is unregistered, a verification link has been sent' });
}

export async function authLogin(req, res, params, body) {
  // mutation-auth: public — constant-time check even for an absent user (no enumeration). -> interop envelope.
  const c = validCreds(res, body); if (!c) return;
  const now = testNow(req);
  if (!(await throttleOK(res, 'login', c.email, now))) return;
  const user = await storeGet('auth_users', c.email);
  const salt = user ? user.salt : randB64(16);
  const valid = verifyPassword(c.password, salt, iterations(), user ? user.hash : '');
  if (!user || !valid) return problem(res, 401, 'invalid credentials');
  if (process.env.AUTH_REQUIRE_VERIFIED === '1' && !user.email_verified) return problem(res, 401, 'email not verified');
  sendJSON(res, 200, envelopeBody(await sessionCreate(c.email, now), c.email, user, now));
}

export async function authRefresh(req, res, params, body) {
  // mutation-auth: refresh-token — the rotation token IS the credential; rotate (old dies); reuse -> revoke.
  if (!body || typeof body.token !== 'string') return problem(res, 422, 'invalid body');
  const now = testNow(req);
  const newTok = await sessionRotate(body.token, now);
  if (newTok === undefined) return problem(res, 401, 'invalid or expired token');
  const subject = await sessionResolve(newTok);
  sendJSON(res, 200, envelopeBody(newTok, subject || '', (await storeGet('auth_users', subject)) || {}, now));
}

export async function authLogout(req, res) {
  const subject = await requireIdentity(req, res);
  if (subject === null) return;
  const scope = new URL(req.url, 'http://localhost').searchParams.get('scope');
  if (scope === 'global') await sessionRevokeAll(subject);
  else await revokeCurrent(req); // the bearer is read in CORE, never parsed in the domain
  sendJSON(res, 200, { message: 'logged out' });
}

export async function authResetRequest(req, res, params, body) {
  // mutation-auth: public — ENUMERATION-SAFE: always 200; token minted on both paths (flat timing); only a real
  // account's token is delivered (never email a reset link to a non-account).
  if (!body || typeof body.email !== 'string' || !isWellFormed(body.email)) return problem(res, 422, 'invalid body');
  const now = testNow(req);
  if (!(await throttleOK(res, 'reset', body.email, now))) return;
  const token = await mint('auth_reset', body.email, envInt(process.env.AUTH_RESET_TTL_SECONDS, 3600, 60), now);
  if (await storeGet('auth_users', body.email)) await deliver('reset', body.email, token);
  else await storePut('auth_outbox', '__pad__', { to: '', kind: 'pad', token: '' }); // equal store work (timing flatness)
  sendJSON(res, 200, { message: 'if the email is registered, a reset link has been sent' });
}

export async function authResetConfirm(req, res, params, body) {
  // mutation-auth: reset-token — single-use token; set the new password AND revoke ALL sessions (ASVS 3.3.3 / #8).
  if (!body || typeof body.token !== 'string' || typeof body.password !== 'string' || !pwOK(body.password)) {
    return problem(res, 422, 'invalid body');
  }
  const now = testNow(req);
  const subject = await consume('auth_reset', body.token, now);
  if (!subject) return problem(res, 400, 'invalid or expired reset token');
  const salt = randB64(16);
  const newHash = hashPassword(body.password, salt, iterations()); // PBKDF2 outside storeDo (fn must be pure)
  const updated = await storeDo('auth_users', subject, (cur) => (cur ? [{ ...cur, salt, hash: newHash }, true] : [undefined, false]));
  if (!updated) return problem(res, 400, 'invalid or expired reset token');
  await sessionRevokeAll(subject);
  sendJSON(res, 200, { message: 'password reset; all sessions ended' });
}

export async function authVerifyRequest(req, res) {
  const subject = await requireIdentity(req, res);
  if (subject === null) return;
  const now = testNow(req);
  if (!(await throttleOK(res, 'verify', subject, now))) return;
  await deliver('verify', subject, await mint('auth_verify', subject, envInt(process.env.AUTH_VERIFY_TTL_SECONDS, 86400, 60), now));
  sendJSON(res, 200, { message: 'verification link sent' });
}

export async function authVerifyConfirm(req, res, params, body) {
  // mutation-auth: verify-token — single-use token; marks the bound subject's email verified.
  if (!body || typeof body.token !== 'string') return problem(res, 422, 'invalid body');
  const now = testNow(req);
  const subject = await consume('auth_verify', body.token, now);
  if (!subject) return problem(res, 400, 'invalid or expired verification token');
  const updated = await storeDo('auth_users', subject, (cur) => (cur ? [{ ...cur, email_verified: true }, true] : [undefined, false]));
  if (!updated) return problem(res, 400, 'invalid or expired verification token');
  sendJSON(res, 200, { message: 'email verified' });
}

export async function authMe(req, res) {
  // identity from the core session seam: deny-by-default (no/invalid/expired token -> 401).
  const subject = await requireIdentity(req, res);
  if (subject === null) return;
  sendJSON(res, 200, userOut(subject, (await storeGet('auth_users', subject)) || {}));
}
