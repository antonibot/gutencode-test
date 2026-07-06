// secrets_vault — a versioned secret store with a managed version LIFECYCLE, a domain-local ACCESS AUDIT, and an
// at-rest SEAL seam. Matches python/go; durable.
// (1) VERSION IMMUTABILITY: each write creates a NEW version; rotation only ADDS one, so reveal(N) resolves to the
// bytes written at N — UNLESS PRUNED (max_versions), DESTROYED, or DISABLED, each a 404 byte-indistinguishable from
// never-written. The per-name counter bumps atomically through storeDo. (2) NO LEAK: the value is returned ONLY by
// the explicit reveal path. (3) LIFECYCLE: max_versions prunes the OLDEST (bytes deleted via the secure-delete
// store); DESTROY irreversibly removes a version's bytes (tombstoned 'destroyed' -> 404, visible in metadata);
// DISABLE/ENABLE reversibly hide/show a version (bytes kept) — the GCP-SM/OpenBao state model. (4) ADMIN-ONLY:
// EVERY route requires 'admin' (401/403 before any body/path validation, x3). (5) ACCESS AUDIT (domain-local): every
// reveal/put/destroy/disable/enable, success AND failure (403/404), appends {actor, action, name, version, outcome,
// at, source} to secrets_vault_access — NEVER the value; APP_SECRETS_VAULT_AUDIT: off | deny (default) | all;
// GET /access (admin).
//
// AT-REST (opt-in): the value routes through svSeal/svUnseal. DEFAULT (SECRETS_VAULT_KEK unset) is PASSTHROUGH —
// stored bytes are PLAINTEXT (the honest, zero-dep default; secure_delete=ON still scrubs on delete). Set
// SECRETS_VAULT_KEK (base64 32-byte) and every value is AES-256-GCM sealed (per-record 96-bit nonce, name\x1fversion
// AAD, blob "svgcm:<keyver>:<b64(nonce+ct+tag)>") using node stdlib crypto (no new dep). Crypto-shred = destroy the KEK;
// a cloud KMS/HSM is the documented INTEROP upgrade.
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { isAdmin, isStrictInt, nextId, problem, requireIdentity, sendJSON, storeDelete, storeDo, storeGet, storePut, storeValues, testNow } from '../../core/runtime.js';
import { envInt } from '../../parts/env_int.js';
import { paginate } from '../../parts/paginate.js';
import { isWellFormed } from '../../parts/well_formed.js';

// state in store: ns "secrets_vault_meta" name -> {name, current_version, min_version, states} · ns
// "secrets_vault_versions" `${name}\x1f${v}` -> SEALED value · ns "secrets_vault_access" id -> the audit row.

const vkey = (name, version) => `${name}\x1f${version}`; // name well-formed (no separator) -> key can't be forged
const RESERVED_NAMES = new Set(['access']);              // GET /secrets_vault/access is static -> no secret shadows it

// AT-REST SEAM. SECRETS_VAULT_KEK unset -> PASSTHROUGH (identity, plaintext — the honest zero-dep default). Set it and
// every value is AES-256-GCM sealed. SvSealError (wrong/rotated/malformed key, tampered/relocated ciphertext, or a
// value that could not be sealed) surfaces as a 500 at the call site — NEVER plaintext, NEVER garbage.
const SV_SEAL_SCHEME = 'svgcm';                // AES-256-GCM, KEK-direct, per-record 96-bit nonce, name\x1fversion AAD
const SV_SEAL_PREFIX = `${SV_SEAL_SCHEME}:`;   // self-describing blob "svgcm:<keyver>:<b64(nonce+ct+tag)>"

class SvSealError extends Error {}

// svKEK — the at-rest KEK (base64 of 32 bytes in SECRETS_VAULT_KEK) or null if unset (sealing OFF — the byte-unchanged
// default). A malformed key throws LOUD, never a silent plaintext fallback.
function svKEK() {
  const raw = (process.env.SECRETS_VAULT_KEK || '').trim();
  if (!raw) return null;
  const key = Buffer.from(raw, 'base64');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(raw) || key.length !== 32) {
    throw new SvSealError('SECRETS_VAULT_KEK must be base64 of 32 bytes');
  }
  return key;
}

// svKeyver — a NON-secret key identifier (first 8 hex of sha256(key)): self-describing blob + a loud wrong-key error.
const svKeyver = (key) => createHash('sha256').update(key).digest('hex').slice(0, 8);

// svSeal — KEK unset -> passthrough (plaintext default). KEK set -> AES-256-GCM: random 96-bit nonce, AAD =
// name\x1fversion (a blob can NOT be replayed under another slot), blob = "svgcm:<keyver>:<b64(nonce+ciphertext+tag)>".
function svSeal(value, name, version) {
  const key = svKEK();
  if (key === null) return value;
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(vkey(name, version)));
  const ct = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const blob = Buffer.concat([nonce, ct, cipher.getAuthTag()]);
  return `${SV_SEAL_PREFIX}${svKeyver(key)}:${blob.toString('base64')}`;
}

// svUnseal — the inverse. KEK unset -> passthrough. KEK set -> open a seal blob (a wrong/rotated key or a
// relocated/tampered blob throws LOUD, never plaintext); a value with NO seal prefix is legacy plaintext (pre-KEK).
function svUnseal(stored, name, version) {
  const key = svKEK();
  if (key === null) return stored;
  if (!stored.startsWith(SV_SEAL_PREFIX)) return stored; // legacy plaintext (pre-KEK) — read-through
  const rest = stored.slice(SV_SEAL_PREFIX.length);
  const idx = rest.indexOf(':');
  if (idx < 0) throw new SvSealError('malformed seal blob');
  if (rest.slice(0, idx) !== svKeyver(key)) {
    throw new SvSealError('secret sealed under a different key (wrong or rotated SECRETS_VAULT_KEK)');
  }
  const raw = Buffer.from(rest.slice(idx + 1), 'base64');
  if (raw.length < 12 + 16) throw new SvSealError('malformed seal blob');
  const nonce = raw.subarray(0, 12);
  const tag = raw.subarray(raw.length - 16);
  const ct = raw.subarray(12, raw.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(Buffer.from(vkey(name, version)));
  decipher.setAuthTag(tag);
  try {
    return decipher.update(ct, undefined, 'utf8') + decipher.final('utf8');
  } catch {
    throw new SvSealError('secret failed to unseal (wrong key, tampered, or relocated ciphertext)');
  }
}

function svMaxVersions() {
  // SECRETS_VAULT_MAX_VERSIONS bounds a name's retained versions (oldest PRUNED past the cap) — a soft-DoS floor.
  return envInt(process.env.SECRETS_VAULT_MAX_VERSIONS, 100, 1);
}

const svMinVersion = (meta) => (meta.min_version >= 1 ? meta.min_version : 1);

// svStateOf: the lifecycle state of (name, version): active | pruned | destroyed | disabled | unknown. ONLY `active`
// reveals; the other four are all a byte-indistinguishable 404.
function svStateOf(meta, version) {
  if (version < 1 || version > meta.current_version) return 'unknown';
  if (version < svMinVersion(meta)) return 'pruned';
  const s = (meta.states || {})[String(version)];
  return s === 'destroyed' || s === 'disabled' ? s : 'active';
}

async function svAudit(req, actor, action, name, version, outcome) {
  // Domain-local AU-3 access audit. APP_SECRETS_VAULT_AUDIT: off | deny (default — log denials/failures) | all.
  let mode = (process.env.APP_SECRETS_VAULT_AUDIT || '').trim().toLowerCase();
  if (mode !== 'off' && mode !== 'all') mode = 'deny'; // unknown/empty/typo -> fail SAFE to the default
  if (mode === 'off' || (mode === 'deny' && outcome === 'allowed')) return;
  const id = await nextId('secrets_vault_access');
  await storePut('secrets_vault_access', String(id),
    { id, actor, action, name, version, outcome, at: testNow(req), source: req.requestId || '-' });
}

// requireAdminAudited — admin-gate a route AND audit the denial (the subject is known: a 403 resolved the identity).
// A 401 (no identity) is sent by requireIdentity before this -> it is in the core access-log, not the domain audit (x3).
async function requireAdminAudited(req, res, action, params) {
  const subject = await requireIdentity(req, res);
  if (subject === null) return null;
  if (!(await isAdmin(subject))) {
    await svAudit(req, subject, action, (params && params.name) || null, null, 'denied');
    problem(res, 403, 'this operation requires the admin role');
    return null;
  }
  return subject;
}

// svRequireVersion — a REQUIRED positive-integer body `version` (destroy/disable/enable). STRICT (rejects "1"/float/bool).
function svRequireVersion(res, body) {
  if (!body || body.version === undefined) { problem(res, 422, 'version is required'); return null; }
  if (!isStrictInt(body, 'version') || body.version < 1) { problem(res, 422, 'version must be a positive integer'); return null; }
  return body.version;
}

export async function secretsVaultList(req, res, params) {
  if ((await requireAdminAudited(req, res, 'list', params)) === null) return;
  // unscoped-read: admin — lists names only (NEVER values) across all secrets; no per-caller owner field.
  const names = (await storeValues('secrets_vault_meta')).map((m) => m.name).sort(); // names only — NEVER values; stable sort
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(names, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function secretsVaultAccessLog(req, res, params) {
  if ((await requireAdminAudited(req, res, 'audit-read', params)) === null) return;
  // unscoped-read: admin — the access audit is a GLOBAL admin resource (requireAdminAudited is the gate); no per-caller owner field. NEWEST-first; NEVER a value.
  const rows = (await storeValues('secrets_vault_access')).sort((a, b) => b.id - a.id);
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(rows, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function secretsVaultPut(req, res, params, body) {
  const subject = await requireAdminAudited(req, res, 'put', params); // authn -> authz BEFORE validation (401/403 before 422), x3
  if (subject === null) return;
  if (!isWellFormed(params.name)) return problem(res, 422, 'the secret name must be non-empty with no control characters');
  if (RESERVED_NAMES.has(params.name)) return problem(res, 422, `'${params.name}' is a reserved name`);
  if (!body || typeof body.value !== 'string' || body.value === '') return problem(res, 422, 'value is required');
  const mx = svMaxVersions();
  let version = 0;
  let pruned = [];
  await storeDo('secrets_vault_meta', params.name, (meta) => {
    version = (meta ? meta.current_version : 0) + 1; // atomic, per-name, sequential
    const minV = meta ? svMinVersion(meta) : 1;
    const states = meta && meta.states ? { ...meta.states } : {};
    let newMin = version - mx + 1; // keep only the newest mx versions
    if (newMin < minV) newMin = minV;
    pruned = [];
    for (let v = minV; v < newMin; v++) { pruned.push(v); delete states[String(v)]; }
    return [{ name: params.name, current_version: version, min_version: newMin, states }, null];
  });
  let sealed;
  try { sealed = svSeal(body.value, params.name, version); } // AES-256-GCM under SECRETS_VAULT_KEK, else passthrough
  catch (e) { if (e instanceof SvSealError) return problem(res, 500, 'secret could not be sealed'); throw e; } // loud — never store plaintext when a seal was requested
  await storePut('secrets_vault_versions', vkey(params.name, version), sealed); // the immutable, SEALED version row
  for (const v of pruned) await storeDelete('secrets_vault_versions', vkey(params.name, v)); // secure_delete=ON scrubs evicted bytes
  await svAudit(req, subject, 'put', params.name, version, 'allowed');
  sendJSON(res, 201, { name: params.name, version }); // value NEVER echoed
}

export async function secretsVaultGet(req, res, params) {
  const subject = await requireAdminAudited(req, res, 'get', params);
  if (subject === null) return;
  if (!isWellFormed(params.name)) return problem(res, 422, 'the secret name must be non-empty with no control characters');
  const meta = await storeGet('secrets_vault_meta', params.name);
  if (meta === undefined) { await svAudit(req, subject, 'get', params.name, null, 'not_found'); return problem(res, 404, 'secret not found'); }
  // metadata only — NO value. Expose non-active states (disabled/destroyed) >= min_version; active implied, pruned gone.
  const minV = svMinVersion(meta);
  const states = {};
  for (const [k, v] of Object.entries(meta.states || {})) { if (parseInt(k, 10) >= minV) states[k] = v; }
  const out = { name: meta.name, current_version: meta.current_version };
  if (Object.keys(states).length > 0) out.states = states;
  await svAudit(req, subject, 'get', params.name, null, 'allowed');
  sendJSON(res, 200, out);
}

export async function secretsVaultReveal(req, res, params, body) {
  const subject = await requireAdminAudited(req, res, 'reveal', params); // authn -> authz BEFORE validation (version check after auth, x3)
  if (subject === null) return;
  let version = 0;
  if (body && body.version !== undefined) {
    if (!isStrictInt(body, 'version') || body.version < 1) return problem(res, 422, 'version must be a positive integer');
    version = body.version;
  }
  if (!isWellFormed(params.name)) return problem(res, 422, 'the secret name must be non-empty with no control characters');
  const meta = await storeGet('secrets_vault_meta', params.name);
  if (meta === undefined) { await svAudit(req, subject, 'reveal', params.name, version || null, 'not_found'); return problem(res, 404, 'secret not found'); }
  if (version === 0) version = meta.current_version;
  if (svStateOf(meta, version) !== 'active') { // pruned / destroyed / disabled / unknown all -> 404 (byte-indistinguishable)
    await svAudit(req, subject, 'reveal', params.name, version, 'not_found');
    return problem(res, 404, 'secret version not found');
  }
  const value = await storeGet('secrets_vault_versions', vkey(params.name, version));
  if (value === undefined) { await svAudit(req, subject, 'reveal', params.name, version, 'not_found'); return problem(res, 404, 'secret version not found'); }
  let plain;
  try { plain = svUnseal(value, params.name, version); } // AES-256-GCM open under SECRETS_VAULT_KEK, else passthrough
  catch (e) { if (e instanceof SvSealError) return problem(res, 500, 'secret could not be unsealed'); throw e; } // loud — never return plaintext/garbage
  await svAudit(req, subject, 'reveal', params.name, version, 'allowed');
  sendJSON(res, 200, { name: params.name, version, value: plain }); // the ONE value path
}

export async function secretsVaultDestroy(req, res, params, body) {
  const subject = await requireAdminAudited(req, res, 'destroy', params);
  if (subject === null) return;
  const version = svRequireVersion(res, body);
  if (version === null) return;
  if (!isWellFormed(params.name)) return problem(res, 422, 'the secret name must be non-empty with no control characters');
  let outcome = '';
  await storeDo('secrets_vault_meta', params.name, (meta) => {
    if (!meta) { outcome = 'no-secret'; return [undefined, null]; } // undefined -> the row is left unwritten
    const st = svStateOf(meta, version);
    if (st === 'unknown' || st === 'pruned') { outcome = 'no-version'; return [undefined, null]; }
    const states = { ...(meta.states || {}) };
    states[String(version)] = 'destroyed'; // tombstone (idempotent; overrides 'disabled')
    outcome = 'ok';
    return [{ ...meta, states }, null];
  });
  if (outcome !== 'ok') {
    await svAudit(req, subject, 'destroy', params.name, version, 'not_found');
    return problem(res, 404, outcome === 'no-secret' ? 'secret not found' : 'secret version not found');
  }
  await storeDelete('secrets_vault_versions', vkey(params.name, version)); // secure_delete=ON scrubs the plaintext (real revocation)
  await svAudit(req, subject, 'destroy', params.name, version, 'allowed');
  sendJSON(res, 200, { name: params.name, version, state: 'destroyed' });
}

export async function secretsVaultDisable(req, res, params, body) {
  const subject = await requireAdminAudited(req, res, 'disable', params);
  if (subject === null) return;
  const version = svRequireVersion(res, body);
  if (version === null) return;
  if (!isWellFormed(params.name)) return problem(res, 422, 'the secret name must be non-empty with no control characters');
  let outcome = '';
  await storeDo('secrets_vault_meta', params.name, (meta) => {
    if (!meta) { outcome = 'no-secret'; return [undefined, null]; }
    const st = svStateOf(meta, version);
    if (st === 'unknown' || st === 'pruned' || st === 'destroyed') { outcome = 'no-version'; return [undefined, null]; }
    const states = { ...(meta.states || {}) };
    states[String(version)] = 'disabled';
    outcome = 'ok';
    return [{ ...meta, states }, null];
  });
  if (outcome !== 'ok') {
    await svAudit(req, subject, 'disable', params.name, version, 'not_found');
    return problem(res, 404, outcome === 'no-secret' ? 'secret not found' : 'secret version not found');
  }
  await svAudit(req, subject, 'disable', params.name, version, 'allowed');
  sendJSON(res, 200, { name: params.name, version, state: 'disabled' });
}

export async function secretsVaultEnable(req, res, params, body) {
  const subject = await requireAdminAudited(req, res, 'enable', params);
  if (subject === null) return;
  const version = svRequireVersion(res, body);
  if (version === null) return;
  if (!isWellFormed(params.name)) return problem(res, 422, 'the secret name must be non-empty with no control characters');
  let outcome = '';
  await storeDo('secrets_vault_meta', params.name, (meta) => {
    if (!meta) { outcome = 'no-secret'; return [undefined, null]; }
    const st = svStateOf(meta, version);
    if (st === 'active') { outcome = 'ok'; return [undefined, null]; } // already enabled -> idempotent (no write)
    if (st !== 'disabled') { outcome = 'no-version'; return [undefined, null]; } // destroyed/pruned/unknown can't re-enable
    const states = { ...(meta.states || {}) };
    delete states[String(version)]; // remove the 'disabled' mark -> active
    outcome = 'ok';
    return [{ ...meta, states }, null];
  });
  if (outcome !== 'ok') {
    await svAudit(req, subject, 'enable', params.name, version, 'not_found');
    return problem(res, 404, outcome === 'no-secret' ? 'secret not found' : 'secret version not found');
  }
  await svAudit(req, subject, 'enable', params.name, version, 'allowed');
  sendJSON(res, 200, { name: params.name, version, state: 'enabled' });
}
