// prompt_registry — a versioned, IMMUTABLE prompt-template store with movable deployment LABELS (rollback) and a
// deterministic {{variable}} render. Matches python/go; durable. PIN-HONESTY: (1) IMMUTABILITY — each POST mints a NEW
// monotonic version per (owner,name) through storeDo; a published version's (template, content_hash) is frozen;
// append-only (no update/delete). (2) LABEL NO-DRIFT — a label is a movable pointer to ONE version; creating versions
// never moves an existing label (no virtual `latest`, no silent default); rollback resolves the old version's EXACT
// content. (3) CONTENT PIN — content_hash = digestHex over the ONE contained template (injective by construction);
// server-derived (a smuggled content_hash is discarded). (4) RENDER — {{var}} from a string->string data map, ASCII
// [A-Za-z0-9_] placeholder (NOT \w), scan the template not the data (x3), single-pass (a value can't inject a 2nd var;
// a self-ref terminates), missing var -> 422, data values CONTAINED before substitution, rendered output bounded (the
// amplification cap). (5) OWNER-SCOPED — owner = requireIdentity; the composite key `${owner}\x1f${name}` stops
// cross-owner clobber; not-yours == 404. Names/labels are isWellFormed (control-char-free) THEN makeWellFormed
// (UTF-8-safe key + echo). Same names + DECISIONS in all three languages.
import { intParam, isStrictInt, problem, requireIdentity, sendJSON, storeDo, storeGet, storePut, storeValues, testNow } from '../core/runtime.js';
import { digestHex } from '../parts/digest.js';
import { envInt } from '../parts/env_int.js';
import { paginate } from '../parts/paginate.js';
import { isWellFormed, makeWellFormed } from '../parts/well_formed.js';

const PROMPTS = 'prompt_registry_prompts';   // `${owner}\x1f${name}` -> { owner, name, latest_version, labels, created_at }
const VERSIONS = 'prompt_registry_versions'; // `${owner}\x1f${name}\x1f${version}` -> { owner, name, version, template, content_hash, created_at }
const PLACEHOLDER = /\{\{([A-Za-z0-9_]+)\}\}/g; // ASCII-explicit -> x3 parity with py/go

const maxVersions = () => envInt(process.env.PROMPT_REGISTRY_MAX_VERSIONS, 1000, 1); // reject past cap (preserve pins)
const maxLabels = () => envInt(process.env.PROMPT_REGISTRY_MAX_LABELS, 50, 1);
const maxTemplateBytes = () => envInt(process.env.PROMPT_REGISTRY_MAX_TEMPLATE_BYTES, 65536, 1);
const maxRenderedBytes = () => envInt(process.env.PROMPT_REGISTRY_MAX_RENDERED_BYTES, 262144, 1); // amplification cap

const pkey = (owner, name) => `${owner}\x1f${name}`; // owner-partitioned: B can't clobber A's name
const vkey = (owner, name, version) => `${owner}\x1f${name}\x1f${version}`;

// render — scan the TEMPLATE for {{key}} (never iterate data -> deterministic x3); a placeholder with no data value
// -> ok:false (a 422). Single-pass (a substituted value is not re-scanned -> a self-ref terminates). Object.hasOwn
// guards prototype keys. The caller has already CONTAINED the data values.
function render(template, data) {
  let ok = true;
  const out = template.replace(PLACEHOLDER, (_m, key) => {
    if (!Object.hasOwn(data, key)) { ok = false; return ''; }
    return data[key];
  });
  return { out, ok };
}

const publicVersion = (rec) => ({ name: rec.name, version: rec.version, template: rec.template, content_hash: rec.content_hash, created_at: rec.created_at });

// cleanName — isWellFormed (reject a control char < 0x20 so the \x1f key separator can't be forged) -> 422; then
// makeWellFormed (contain a lone surrogate so the key + echo are UTF-8-safe). Returns null on reject (already responded).
function cleanName(res, raw, what) {
  if (!isWellFormed(raw)) { problem(res, 422, `the ${what} must be non-empty with no control characters`); return null; }
  return makeWellFormed(raw);
}

export async function promptRegistryCreateVersion(req, res, params, body) {
  const owner = await requireIdentity(req, res); // authenticated mutation (no/invalid token -> 401)
  if (owner === null) return;
  const name = cleanName(res, params.name, 'prompt name');
  if (name === null) return;
  if (!body || typeof body.template !== 'string') return problem(res, 422, 'template is required'); // the ONLY field read (allowlist)
  if (body.template === '') return problem(res, 422, 'template is required');
  const template = makeWellFormed(body.template); // CONTAIN before hash/store (a lone surrogate would throw on hash)
  if (Buffer.byteLength(template, 'utf8') > maxTemplateBytes()) return problem(res, 422, 'template is too large');
  const content_hash = digestHex(template); // server-DERIVED pin over the ONE contained string (injective)
  const created_at = testNow(req);
  const mx = maxVersions();
  let version = 0;
  let over = false;
  await storeDo(PROMPTS, pkey(owner, name), (p) => {
    if (!p) { version = 1; return [{ owner, name, latest_version: 1, labels: {}, created_at }, null]; }
    if (p.latest_version >= mx) { over = true; return [undefined, null]; } // reject past cap (preserve pins; never prune)
    version = p.latest_version + 1;
    return [{ ...p, latest_version: version }, null];
  });
  if (over) return problem(res, 422, 'too many versions');
  // the immutable version row, written AFTER the do; a crash leaves a benign gap the read-side check turns into a 404.
  await storePut(VERSIONS, vkey(owner, name, version), { owner, name, version, template, content_hash, created_at });
  sendJSON(res, 201, { name, version, content_hash, created_at });
}

export async function promptRegistryGetVersion(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const name = cleanName(res, params.name, 'prompt name');
  if (name === null) return;
  const version = intParam(params.version); // STRICT path int: null for "1.0"/"abc" (matches IntPath)
  if (version === null) return problem(res, 422, 'invalid version');
  // unbounded-safe: a single immutable version by key; OWNER-scoped (the key includes owner -> not-yours == 404).
  const rec = await storeGet(VERSIONS, vkey(owner, name, version));
  if (rec === undefined) return problem(res, 404, 'prompt version not found');
  sendJSON(res, 200, publicVersion(rec));
}

export async function promptRegistryListPrompts(req, res) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  // read-scope: owner — ONLY the caller's own prompts (owner FIELD == caller); sorted by name (stable x3); BOUNDED
  // through paginate (a stranger gets an empty page, never 403).
  const rows = (await storeValues(PROMPTS)).filter((p) => p.owner === owner).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const views = rows.map((p) => ({ name: p.name, latest_version: p.latest_version }));
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(views, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function promptRegistryGetPrompt(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const name = cleanName(res, params.name, 'prompt name');
  if (name === null) return;
  const p = await storeGet(PROMPTS, pkey(owner, name));
  if (p === undefined) return problem(res, 404, 'prompt not found');
  // version_count == latest_version (append-only); latest_version is read-only metadata, NOT a render target.
  sendJSON(res, 200, { name: p.name, latest_version: p.latest_version, version_count: p.latest_version, labels: p.labels || {}, created_at: p.created_at });
}

export async function promptRegistrySetLabel(req, res, params, body) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const name = cleanName(res, params.name, 'prompt name');
  if (name === null) return;
  const label = cleanName(res, params.label, 'label');
  if (label === null) return;
  if (!body || body.version === undefined) return problem(res, 422, 'version is required');
  if (!isStrictInt(body, 'version') || body.version < 1) return problem(res, 422, 'version must be a positive integer'); // rejects "1"/float/bool/>2^53
  const version = body.version;
  if ((await storeGet(PROMPTS, pkey(owner, name))) === undefined) return problem(res, 404, 'prompt not found'); // not-yours/missing -> 404
  if ((await storeGet(VERSIONS, vkey(owner, name, version))) === undefined) return problem(res, 422, 'version does not exist'); // the immutable ROW must exist
  const mx = maxLabels();
  let outcome = 'ok';
  await storeDo(PROMPTS, pkey(owner, name), (p) => {
    if (!p) { outcome = 'no-prompt'; return [undefined, null]; }
    const labels = { ...(p.labels || {}) };
    if (!Object.hasOwn(labels, label) && Object.keys(labels).length >= mx) { outcome = 'too-many'; return [undefined, null]; } // a NEW label past cap is rejected; MOVING is fine
    labels[label] = version; // one-to-one: setting MOVES the label
    return [{ ...p, labels }, null];
  });
  if (outcome === 'no-prompt') return problem(res, 404, 'prompt not found');
  if (outcome === 'too-many') return problem(res, 422, 'too many labels');
  sendJSON(res, 200, { name, label, version });
}

export async function promptRegistryRender(req, res, params, body) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const name = cleanName(res, params.name, 'prompt name');
  if (name === null) return;
  const hasVersion = body && body.version !== undefined;
  const hasLabel = body && body.label !== undefined;
  if (hasVersion === hasLabel) return problem(res, 422, 'provide exactly one of version or label'); // no silent default
  let version;
  if (hasLabel) {
    if (typeof body.label !== 'string') return problem(res, 422, 'invalid label');
    const label = cleanName(res, body.label, 'label');
    if (label === null) return;
    const p = await storeGet(PROMPTS, pkey(owner, name));
    if (p === undefined) return problem(res, 404, 'prompt not found');
    version = (p.labels || {})[label];
    if (version === undefined) return problem(res, 404, 'label not found'); // an unset label -> 404 (no silent fallback)
  } else {
    if (!isStrictInt(body, 'version') || body.version < 1) return problem(res, 422, 'version must be a positive integer');
    version = body.version;
  }
  const rec = await storeGet(VERSIONS, vkey(owner, name, version));
  if (rec === undefined) return problem(res, 404, 'prompt version not found');
  // data is string->string: a numeric/bool value is 422 (no coercion x3); CONTAIN each value BEFORE substitution.
  const data = {};
  if (body.data !== undefined) {
    if (typeof body.data !== 'object' || body.data === null || Array.isArray(body.data) || !Object.values(body.data).every((v) => typeof v === 'string')) {
      return problem(res, 422, 'data must be an object of string values');
    }
    for (const k of Object.keys(body.data)) data[k] = makeWellFormed(body.data[k]);
  }
  const { out, ok } = render(rec.template, data);
  if (!ok) return problem(res, 422, 'template variable not provided');
  if (Buffer.byteLength(out, 'utf8') > maxRenderedBytes()) return problem(res, 422, 'rendered output is too large'); // RENDER-THEN-VALIDATE: bound the output
  sendJSON(res, 200, { name, version, content_hash: rec.content_hash, rendered: out });
}
