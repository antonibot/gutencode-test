import { createHash, timingSafeEqual } from 'node:crypto';
import { getDriver } from './store_factory.js';

// The store FACADE: it owns (de)serialization + the public contract (storeGet/Put/Values/Delete/Do, nextId); the
// DRIVER (store_sqlite.js — the default; store_postgres.js when DATABASE_URL names Postgres), selected once by
// store_factory.getDriver(), owns the connection, the schema, cross-process atomicity, and the reentry guard.
// Acquired at import so the open/schema/fail-loud-ack happen exactly when they did before. runtime.js re-exports
// this surface so domains import it from core/runtime.js unchanged.
// The facade is backend-agnostic: durability and key semantics are identical over SQLite and Postgres.
//
// ASYNC surface: the store contract is `async` so a driver may await I/O — the SQLite driver is sync inside
// (node:sqlite) and its async methods resolve immediately (one microtask, no behaviour change); the Postgres
// driver genuinely awaits. Every CALL SITE awaits storeGet/Put/Values/Delete/Do + nextId; handlers became async.
const _driver = getDriver();

export const db = _driver.db; // the raw backend handle (surface parity; white-box uses only)

export async function nextId(name) {
  return _driver.nextId(name);
}

export async function storeGet(ns, key) {
  const raw = await _driver.get(ns, key);
  return raw === undefined ? undefined : JSON.parse(raw);
}

export async function storePut(ns, key, value) {
  await _driver.put(ns, key, JSON.stringify(value));
}

export async function storeValues(ns) {
  return (await _driver.values(ns)).map((raw) => JSON.parse(raw));
}

export async function storeDelete(ns, key) {
  await _driver.delete(ns, key);
}

// storeDo: ATOMIC read-modify-write of ONE key across PROCESSES. fn(current) -> [next, result]; undefined next =
// leave unwritten. The facade marshals; the driver owns the txn (lock-before-read) + the reentry guard. Mirrors
// python/go do. ×3. The callback fn stays PURE and SYNCHRONOUS — it never awaits, so the driver's reentry guard
// (inDo) is exact even inside an async do(): fn() runs as one atomic sync block. Only the call SITE awaits.
export async function storeDo(ns, key, fn) {
  return _driver.do(ns, key, (rawCur) => {
    const cur = rawCur === undefined ? undefined : JSON.parse(rawCur);
    const [next, result] = fn(cur);
    return [next === undefined ? undefined : JSON.stringify(next), result];
  });
}

// apiKeyResolve: an api-key bearer 'ak_<id>_<secret>' -> its owner subject, or undefined. Lives here (beside the
// store, like python's store.py) so every core-including build carries it without a new module. api_keys_records is
// a domain-owned namespace CORE reads directly for cross-cutting identity — the SAME pattern as rbac_roles (isAdmin)
// / orgs_records (orgRole): core names the NAMESPACE, never the domain. requireIdentity calls this as a FALLBACK
// after a session miss, so every session bearer is byte-unchanged. Constant-time + non-enumerable (ALWAYS one
// compare, a dummy hash on an unknown id). The secret may contain '_' (base64url), so parse to the SECOND
// underscore. A v1 key authenticates AS its owner; scopes stay advisory.
const _apikeyHash = (s) => createHash('sha256').update(s).digest('hex'); // == the api-key record's stored secret_hash
const _APIKEY_DUMMY_HASH = _apikeyHash('apikey-absent-record-filler');   // compared when the key id is unknown

export async function apiKeyResolve(token) {
  if (!token.startsWith('ak_')) return undefined;            // cheap short-circuit: not a key -> stay on the 401 path
  const second = token.indexOf('_', 3);                      // the underscore ending the key id (id starts at index 3)
  if (second < 0) return undefined;                          // no second underscore -> not the ak_<id>_<secret> shape
  const keyId = token.slice(3, second);
  const rec = keyId ? await storeGet('api_keys_records', keyId) : undefined; // empty id -> a miss (dummy compare below)
  const got = Buffer.from(_apikeyHash(token.slice(second + 1)), 'utf8');
  const want = Buffer.from(rec ? rec.secret_hash : _APIKEY_DUMMY_HASH, 'utf8');
  const match = got.length === want.length && timingSafeEqual(got, want);    // ALWAYS one constant-time compare
  if (rec && rec.status === 'active' && match) return rec.owner;
  return undefined;
}
