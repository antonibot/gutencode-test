// api_keys — issue/list/verify/rotate/revoke API keys with scopes; every key records created_at (seconds, the core
// clock seam, preserved across rotate). (1) NO PLAINTEXT AT REST: the secret is shown
// ONCE; only sha256(secret) (the digest part) is stored. (2) CONSTANT-TIME, NON-ENUMERABLE VERIFY: every
// verify hashes and runs ONE timingSafeEqual against a record (a dummy when the id is unknown) — an unknown id
// and a wrong secret are the same {valid:false} after the same work; scopes only when valid. (3) ROTATION
// invalidates the old secret. (4) REVOCATION is monotonic. Key is `ak_<id>_<secret>`; the prefix is public,
// the secret is not. Store names and shapes match python/go; durable.
//
// OWNERSHIP — a key is USER-SCOPED: it belongs to the caller who created it. create/get/list/rotate/revoke call
// requireIdentity (the core seam) FIRST, the OWNER is stamped from the authenticated subject at create (never a body
// field), and a management op on another caller's key id is 404 — byte-identical to a missing id, so the enumerable
// sequential id leaks no existence (the tenancy not-yours==not-found pattern). apiKeysList is the same owner-scoping
// over a COLLECTION (only the caller's keys, paginated, secret/owner-blind; a stranger gets an empty page, never 403).
// apiKeysVerify stays PUBLIC (see its declaration).
import { randomBytes, timingSafeEqual } from 'node:crypto';

import { intParam, nextId, problem, requireIdentity, sendJSON, storeGet, storePut, storeValues, testNow } from '../core/runtime.js';
import { digestHex } from '../parts/digest.js';
import { paginate } from '../parts/paginate.js';
import { isWellFormed } from '../parts/well_formed.js';

const DUMMY_HASH = digestHex('api_keys_absent_record_filler');
// state in store: seq "api_keys_key" · ns "api_keys_records" String(id) -> {id,name,owner,scopes,prefix,secret_hash,status}

// the public view NEVER includes secret_hash OR owner (owner is private, like the hash); created_at IS public
const publicView = (rec) => ({ id: rec.id, name: rec.name, scopes: rec.scopes, prefix: rec.prefix, status: rec.status, created_at: rec.created_at });

async function issue(rec) {
  const secret = randomBytes(24).toString('base64url');
  const stored = { ...rec, secret_hash: digestHex(secret) };
  await storePut('api_keys_records', String(rec.id), stored);
  return { ...publicView(stored), key: `ak_${rec.id}_${secret}` };
}

// load expects requireIdentity to have run already; it does the path-int check, loads, then enforces owner==caller,
// returning 404 for a missing OR cross-owner id (not-yours == not-found: existence never leaks cross-owner).
async function load(req, res, params, owner) {
  const kid = intParam(params.key_id);
  if (kid === null) { problem(res, 422, 'invalid key id'); return null; }
  const rec = await storeGet('api_keys_records', String(kid));
  if (rec === undefined || rec.owner !== owner) { problem(res, 404, 'api key not found'); return null; }
  return rec;
}

export async function apiKeysCreate(req, res, params, body) {
  const owner = await requireIdentity(req, res); // the runtime parsed the body already, so identity-first is fine here
  if (owner === null) return;
  if (!body || !isWellFormed(body.name) || !Array.isArray(body.scopes) || body.scopes.length === 0
      || !body.scopes.every(isWellFormed)) {
    return problem(res, 422, 'invalid body');
  }
  const kid = await nextId('api_keys_key');
  // owner derived from the token, never client-set; created_at = the birth time via the core clock seam (preserved across rotate)
  const at = testNow(req);
  sendJSON(res, 201, await issue({ id: kid, name: body.name, owner, scopes: body.scopes, prefix: `ak_${kid}`, status: 'active', created_at: at }));
}

export async function apiKeysGet(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const rec = await load(req, res, params, owner);
  if (rec !== null) sendJSON(res, 200, publicView(rec));
}

export async function apiKeysList(req, res) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  // OWNER-SCOPED LIST: only the caller's keys leave the store — filtered INLINE on the authenticated owner, mapped to
  // the secret/owner-blind publicView, then a BOUNDED page. Cross-owner isolation proven by I8; a stranger gets an
  // empty page, never 403.
  // sorted by id (the stable order) — rotate/revoke re-write a row + bump its rowid, so an explicit id-sort is
  // required for a stable paged walk (the notifications/admin precedent; tenancy/audit_log never UPDATE a row).
  const mine = (await storeValues('api_keys_records')).filter((r) => r.owner === owner)
    .sort((a, b) => a.id - b.id).map(publicView);
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(mine, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function apiKeysVerify(req, res, params, body) {
  // mutation-auth: public — INTENTIONALLY unauthenticated. The `ak_<id>_<secret>` key IS the credential (like a
  // login): a caller verifies it BEFORE it has a session, so requireIdentity would break the route's purpose. It
  // mutates no stored state on behalf of any user — it only recomputes the hash and runs one constant-time compare.
  // The owner-scoping guards the MANAGEMENT ops (create/get/rotate/revoke), not this credential check.
  if (!body || typeof body.key !== 'string' || body.key === '') return problem(res, 422, 'invalid body');
  // parse `ak_<id>_<secret>`; a malformed key still runs the dummy compare (uniform timing)
  let keyId = '';
  let secret = '';
  const firstUnderscore = body.key.indexOf('_');
  const secondUnderscore = body.key.indexOf('_', firstUnderscore + 1);
  if (body.key.startsWith('ak_') && secondUnderscore > firstUnderscore) {
    keyId = body.key.slice(3, secondUnderscore);
    secret = body.key.slice(secondUnderscore + 1);
  }
  const rec = keyId ? await storeGet('api_keys_records', keyId) : undefined;
  const stored = rec ? rec.secret_hash : DUMMY_HASH;
  // ALWAYS one constant-time compare (hex strings are fixed length 64, so timingSafeEqual is safe)
  const got = Buffer.from(digestHex(secret));
  const want = Buffer.from(stored);
  const match = got.length === want.length && timingSafeEqual(got, want);
  const valid = rec !== undefined && rec.status === 'active' && match;
  sendJSON(res, 200, { valid, scopes: valid ? rec.scopes : [] });
}

export async function apiKeysRotate(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const rec = await load(req, res, params, owner);
  if (rec === null) return;
  sendJSON(res, 200, await issue(rec)); // new secret + hash replaces the old; the old can never verify again
}

export async function apiKeysRevoke(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const rec = await load(req, res, params, owner);
  if (rec === null) return;
  const revoked = { ...rec, status: 'revoked' }; // monotonic + idempotent: revoked is TERMINAL
  await storePut('api_keys_records', String(rec.id), revoked);
  sendJSON(res, 200, publicView(revoked));
}
