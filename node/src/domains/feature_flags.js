// feature_flags — deterministic percentage rollout via stable hash bucketing. The dangerous property is STABLE
// BUCKETING: a subject's bucket is a fixed function of (key, subject) through the digest part, so evaluation is
// DETERMINISTIC and MONOTONIC under rollout increase (raising the percentage only ADMITS more subjects — no
// flapping). rollout 0..100; bucket 0..99; enabled iff bucket < rollout. Matches python/go; durable.
//
// WRITES ARE ADMIN-ONLY: a feature flag is a control-plane kill-switch — an anonymous flip is a live P0.
// create + setRollout call requireAdmin FIRST in the handler (the runtime already parsed the body): no token 401,
// non-admin 403, resolved BEFORE the strict validation, ×3. READS (get, evaluate) stay OPEN: evaluate is the
// runtime hot path consuming apps call per request, so it MUST NOT be admin.
import { isStrictInt, problem, requireAdmin, sendJSON, storeDo, storeGet, storePut } from '../core/runtime.js';
import { digestHex } from '../parts/digest.js';
import { isWellFormed } from '../parts/well_formed.js';

// state in store: ns "feature_flags_records" key -> {key, rollout}

function bucket(key, subject) {
  // first 32 bits of sha256(key:subject) mod 100 — fixed per (key, subject), identical x3
  return parseInt(digestHex(key, subject).slice(0, 8), 16) % 100;
}

// STRICT: an integer literal 0..100 (isStrictInt rejects 5.0 / "5" / true — ×3 with python StrictInt + go)
const validRollout = (holder, key) => isStrictInt(holder, key) && holder[key] >= 0 && holder[key] <= 100;

export async function featureFlagsCreate(req, res, params, body) {
  if ((await requireAdmin(req, res)) === null) return; // AUTH (runtime already parsed the body); strict checks follow, ×3
  if (!body || !isWellFormed(body.key)) return problem(res, 422, 'invalid body');
  let rollout = 0;
  if (body.rollout !== undefined) {
    if (!validRollout(body, 'rollout')) return problem(res, 422, 'rollout must be an integer 0..100');
    rollout = body.rollout;
  }
  const rec = { key: body.key, rollout };
  // claim-once via the storeDo seam: a get-then-put RACES — two concurrent creates of one key both pass the check
  // and the second overwrites the first. storeDo holds the write lock across read+write; first writer wins -> 409.
  const created = await storeDo('feature_flags_records', body.key, (cur) => (cur === undefined ? [rec, true] : [undefined, false]));
  if (!created) return problem(res, 409, 'flag key taken');
  sendJSON(res, 201, rec);
}

async function load(req, res, params) {
  if (!isWellFormed(params.key)) {
    problem(res, 422, 'the flag key must be non-empty with no control characters');
    return null;
  }
  const flag = await storeGet('feature_flags_records', params.key);
  if (flag === undefined) {
    problem(res, 404, 'flag not found');
    return null;
  }
  return flag;
}

export async function featureFlagsGet(req, res, params) {
  // read-scope: global — app-global flag config (admins set the rollout via require_admin; any caller reads the flag state).
  const flag = await load(req, res, params);
  if (flag !== null) sendJSON(res, 200, flag);
}

export async function featureFlagsSetRollout(req, res, params, body) {
  if ((await requireAdmin(req, res)) === null) return; // AUTH FIRST (path+body): a no-token request is 401 before any 422/404, ×3
  if (!body || !validRollout(body, 'rollout')) return problem(res, 422, 'rollout must be an integer 0..100');
  const flag = await load(req, res, params);
  if (flag === null) return;
  const updated = { ...flag, rollout: body.rollout };
  await storePut('feature_flags_records', flag.key, updated);
  sendJSON(res, 200, updated);
}

export async function featureFlagsEvaluate(req, res, params) {
  // read-scope: global — deterministic flag evaluation for a caller-supplied subject; app-global config, no per-owner data.
  const flag = await load(req, res, params);
  if (flag === null) return;
  const subject = new URL(req.url, 'http://localhost').searchParams.get('subject') || '';
  if (!isWellFormed(subject)) return problem(res, 422, 'the subject query parameter is required');
  sendJSON(res, 200, { key: flag.key, subject, enabled: bucket(flag.key, subject) < flag.rollout });
}
