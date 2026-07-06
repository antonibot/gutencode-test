// settings — settings over a fixed, typed schema, scoped to the AUTHENTICATED identity. The dangerous property is
// TYPE SAFETY + COMPLETENESS: only known keys are writable (unknown -> 422, deny-by-default), each value is
// STRICTLY type-checked against its key's declared type before any write (a string "20", a float 1.5, or a boolean
// true is NOT an int), and a read always returns EVERY known key with the declared default filling any gap. The
// owner is the bearer token's subject (the core requireIdentity seam) — NOT a path param — so a caller only ever
// reads/writes THEIR OWN settings. Deny-by-default (no token -> 401). Store names and shapes match python/go.
import { isStrictInt, problem, requireIdentity, sendJSON, storeGet, storePut } from '../core/runtime.js';

// the schema is POLICY (fixed): key -> {kind, default}. The ONLY writable keys + their types.
const SCHEMA = {
  notifications_enabled: { kind: 'bool', default: true },
  items_per_page: { kind: 'int', default: 20 },
  theme: { kind: 'string', default: 'light' },
};
// state in store: ns "settings_overrides" `${owner}\x1f${key}` -> value (owner = the authenticated subject)

const keyId = (owner, key) => `${owner}\x1f${key}`; // both well-formed -> separator can't be forged

// STRICT type check: a bool is boolean; an int is a STRICT integer literal (isStrictInt rejects 20.0 / "20" /
// true — ×3 with python StrictInt + go's raw-token check); a string is string. `holder`/`key` carry the
// runtime's float-literal marker so 20 and 20.0 are distinguishable.
function typed(kind, holder, key) {
  const value = holder[key];
  if (typeof value === 'boolean') return kind === 'bool';
  if (typeof value === 'number') return kind === 'int' && isStrictInt(holder, key);
  if (typeof value === 'string') return kind === 'string';
  return false;
}

export async function settingsList(req, res) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const out = {};
  for (const [k, spec] of Object.entries(SCHEMA)) {
    const stored = await storeGet('settings_overrides', keyId(owner, k));
    out[k] = stored !== undefined ? stored : spec.default; // COMPLETENESS: every known key present
  }
  sendJSON(res, 200, out);
}

export async function settingsGet(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const spec = SCHEMA[params.key];
  if (spec === undefined) return problem(res, 404, 'setting not found');
  const stored = await storeGet('settings_overrides', keyId(owner, params.key));
  sendJSON(res, 200, { key: params.key, value: stored !== undefined ? stored : spec.default });
}

export async function settingsPut(req, res, params, body) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const spec = SCHEMA[params.key];
  if (spec === undefined) return problem(res, 422, 'unknown setting key'); // deny-by-default
  if (!body || !('value' in body)) return problem(res, 422, 'value is required');
  if (!typed(spec.kind, body, 'value')) {
    return problem(res, 422, `setting '${params.key}' must be of type ${spec.kind}`); // strict, BEFORE any write
  }
  await storePut('settings_overrides', keyId(owner, params.key), body.value);
  sendJSON(res, 200, { key: params.key, value: body.value });
}
