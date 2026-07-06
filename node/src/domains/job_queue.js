// jobs — the async job QUEUE: enqueue background work; a trusted worker pool CLAIMS the next ready job (an exclusive
// lease), then COMPLETEs or FAILs it; a failed job retries with deterministic backoff until dead-lettered. Dangerous
// properties, all proven (same ×3 as jobs.py / jobs.go):
// (1) AT-MOST-ONCE CLAIM: a ready job is leased to AT MOST ONE worker — the claim is a single-key storeDo-CAS, so two
//     workers racing the same job cannot both win (I-CLAIM-ONCE). The pick is the lowest-id ready job, sorted BEFORE
//     the CAS (storeValues is rowid order, not stable ×3).
// (2) COMPLETION-AUTH (the fencing token): claim mints a rotating lease_token; complete/fail REQUIRE it and the CAS
//     asserts token==current AND status==running — a STALE worker cannot complete/reset the new claimant's job
//     (I-COMPLETE-AUTH). Acquire-exclusivity is NOT release-safety.
// (3) BOUNDED RETRY: delivered at most max_attempts times whether the failure is EXPLICIT (fail) or a CRASH (lease
//     lapses, job reclaimed) — attempts increments at CLAIM, and BOTH the fail path AND the reclaim path dead-letter
//     at attempts>=max (I-RETRY-BOUNDED).
// (4) DETERMINISTIC BACKOFF: run_at = now + min(base * 2^min(attempts,30), cap) — no jitter, identical ×3
//     (I-BACKOFF-DET); 2**shift (NOT a bit-shift — node 1<<31 is negative) with the exponent clamped.
// (5) OWNER-SCOPED reads: enqueue stamps owner from the authenticated subject (never a body field); get/list return
//     ONLY the caller's jobs, a cross-owner id is 404. claim/complete/fail are the trusted SERVICE seam.
// (6) PAYLOAD CONTAINED: the opaque payload is ×3-safe via well_formed.sanitizeJson (lone surrogate -> U+FFFD, the
//     2^53 ceiling) — durable storage never crashes serialization nor diverges ×3 (I-PAYLOAD-SAFE).
// State: the durable store (ns 'job_queue_records', key String(id)); at-least-once delivery. See INTEROP.md for the
// SQS / River / BullMQ / Sidekiq mapping.
import { intParam, isStrictInt, nextId, problem, requireIdentity, requireService, sendJSON, storeDo, storeGet, storePut, storeValues, testNow } from '../core/runtime.js';
import { scopedKey } from '../parts/digest.js';
import { envInt } from '../parts/env_int.js';
import { paginate } from '../parts/paginate.js';
import { isWellFormed, makeWellFormed, sanitizeJson } from '../parts/well_formed.js';

const JOB_QUEUE_NS = 'job_queue_records';
const JOB_QUEUE_SEQ = 'job_queue_job';
const JOB_QUEUE_LEASE_ROUTE = '/job_queue/lease';
const JOB_QUEUE_MAX_ATTEMPTS_CAP = 1000; // a per-job max_attempts override is clamped to [1, this] — the hard delivery bound
const JOB_QUEUE_DELAY_CAP = 31536000;    // a delay is clamped to [0, 1 year]
const JOB_QUEUE_SHIFT_CAP = 30;          // 2^30 ceiling on the backoff exponent so base*2^attempt stays < 2^53

const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

const JOB_QUEUE_DEFAULT_MAX_ATTEMPTS = envInt(process.env.JOB_QUEUE_MAX_ATTEMPTS, 20, 1, JOB_QUEUE_MAX_ATTEMPTS_CAP);
const JOB_QUEUE_BACKOFF_BASE = envInt(process.env.JOB_QUEUE_BACKOFF_BASE_SECONDS, 2, 1, 3600);
const JOB_QUEUE_BACKOFF_CAP = envInt(process.env.JOB_QUEUE_BACKOFF_CAP_SECONDS, 3600, JOB_QUEUE_BACKOFF_BASE, 86400);
const JOB_QUEUE_VISIBILITY = envInt(process.env.JOB_QUEUE_VISIBILITY_SECONDS, 300, 1, 86400);

function backoff(attempts) {
  // min(base * 2^min(attempts,30), cap) — deterministic, no jitter; 2**shift NOT a bit-shift (node 1<<31 is negative)
  const shift = Math.min(attempts, JOB_QUEUE_SHIFT_CAP);
  return Math.min(JOB_QUEUE_BACKOFF_BASE * (2 ** shift), JOB_QUEUE_BACKOFF_CAP);
}

function claimable(rec, now) {
  return (rec.status === 'queued' && rec.run_at <= now) || (rec.status === 'running' && rec.lease_until <= now);
}

function publicView(rec) {
  // owner-facing — every field EXCEPT lease_token (the worker's fencing capability, returned only by claim)
  return { id: rec.id, owner: rec.owner, kind: rec.kind, payload: rec.payload, queue: rec.queue, status: rec.status,
    attempts: rec.attempts, max_attempts: rec.max_attempts, run_at: rec.run_at, lease_until: rec.lease_until,
    created_at: rec.created_at, updated_at: rec.updated_at, last_error: rec.last_error };
}

export async function jobsEnqueue(req, res, params, body) {
  const owner = await requireIdentity(req, res); // PARSE done by the runtime; AUTH before SEMANTIC
  if (owner === null) return;
  if (!body || typeof body.kind !== 'string' || !isWellFormed(body.kind)) return problem(res, 422, 'kind must be non-empty with no control characters');
  const queue = body.queue === undefined ? 'default' : body.queue;
  if (typeof queue !== 'string' || !isWellFormed(queue)) return problem(res, 422, 'queue must be non-empty with no control characters');
  let payload = {};
  if (body.payload !== undefined && body.payload !== null) {
    if (typeof body.payload !== 'object' || Array.isArray(body.payload)) return problem(res, 422, 'payload must be an object');
    const [sp, msg] = sanitizeJson('payload', body.payload); // opaque + ×3-safe (surrogate -> U+FFFD, 2^53 ceiling)
    if (msg) return problem(res, 422, msg);
    payload = sp;
  }
  let maxAttempts = JOB_QUEUE_DEFAULT_MAX_ATTEMPTS;
  if (body.max_attempts !== undefined && body.max_attempts !== null) {
    // strict int + range-CHECK (reject, not silently clamped); rejects 5.0/"5"/>2^53 ×3
    if (!isStrictInt(body, 'max_attempts') || body.max_attempts < 1 || body.max_attempts > JOB_QUEUE_MAX_ATTEMPTS_CAP) return problem(res, 422, 'max_attempts must be between 1 and 1000');
    maxAttempts = body.max_attempts;
  }
  let delay = 0;
  if (body.delay_seconds !== undefined && body.delay_seconds !== null) {
    if (!isStrictInt(body, 'delay_seconds') || body.delay_seconds < 0 || body.delay_seconds > JOB_QUEUE_DELAY_CAP) return problem(res, 422, 'delay_seconds must be between 0 and 31536000');
    delay = body.delay_seconds;
  }
  const now = testNow(req);
  const jid = await nextId(JOB_QUEUE_SEQ);
  const rec = { id: jid, owner, kind: body.kind, payload, queue, status: 'queued', attempts: 0,
    max_attempts: maxAttempts, run_at: now + delay, lease_until: 0, lease_token: '', created_at: now,
    updated_at: now, last_error: '' }; // owner/id/status/run_at/lease_* server-set, never the body
  await storePut(JOB_QUEUE_NS, String(jid), rec);
  sendJSON(res, 201, publicView(rec));
}

export async function jobsClaim(req, res) {
  // mutation-auth: service — the worker pool is a trusted SERVICE, not an end user; gated by core.requireService.
  if (requireService(req, res) === null) return;
  const now = testNow(req);
  // unbounded-safe: + unscoped-read: scans ALL jobs across owners to pick the lowest-id ready one — a trusted
  // SERVICE-pool operation, not a per-user read; O(n) store-swap-at-scale limit (a ready-index is the v2 upgrade).
  // Sort REQUIRED: storeValues is rowid order, not stable ×3, and the manifest asserts the exact claimed job.
  const candidates = (await storeValues(JOB_QUEUE_NS)).filter((j) => claimable(j, now)).sort((a, b) => a.id - b.id);
  for (const cand of candidates) {
    const claimed = await storeDo(JOB_QUEUE_NS, String(cand.id), (cur) => {
      if (cur === undefined || !claimable(cur, now)) return [undefined, null]; // vanished, or another worker took it -> skip
      if (cur.attempts >= cur.max_attempts) {
        return [{ ...cur, status: 'dead', lease_token: '', lease_until: 0, updated_at: now }, null]; // dead-letter, NOT a claim
      }
      const attempts = cur.attempts + 1;
      const token = scopedKey(JOB_QUEUE_LEASE_ROUTE, String(cur.id), String(attempts)); // deterministic ×3, rotates each (re)claim
      const c = { ...cur, status: 'running', attempts, lease_until: now + JOB_QUEUE_VISIBILITY, lease_token: token, updated_at: now };
      return [c, c];
    });
    if (claimed) { sendJSON(res, 200, { ...publicView(claimed), lease_token: claimed.lease_token }); return; }
  }
  res.writeHead(204); res.end(); // nothing ready (the worker polls again)
}

async function jobsFinish(req, res, params, body, mutate) {
  // AUTH (requireService) is done by the CALLER so the mutation-auth declaration + the service call share a handler
  const id = intParam(params.job_id);
  if (id === null) return problem(res, 422, 'invalid job id'); // non-int path -> 422 (parity with python IntPath)
  if (!body || typeof body.lease_token !== 'string') return problem(res, 422, 'lease_token is required');
  const errMsg = (body.error !== undefined && typeof body.error === 'string') ? makeWellFormed(body.error) : '';
  const now = testNow(req);
  let outcome = 'not_found';
  let result = null;
  await storeDo(JOB_QUEUE_NS, String(id), (cur) => {
    if (cur === undefined) { outcome = 'not_found'; return [undefined, null]; }
    if (cur.status !== 'running' || cur.lease_token !== body.lease_token) { outcome = 'conflict'; return [undefined, null]; } // stale/wrong token -> fenced
    const next = mutate(cur, errMsg, now);
    outcome = 'ok'; result = next;
    return [next, null];
  });
  if (outcome === 'not_found') return problem(res, 404, 'job not found');
  if (outcome === 'conflict') return problem(res, 409, 'job is not held under this lease');
  sendJSON(res, 200, publicView(result));
}

export async function jobsComplete(req, res, params, body) {
  // mutation-auth: service — only the trusted worker pool finishes a job, and only under the CURRENT lease token.
  if (requireService(req, res) === null) return;
  return jobsFinish(req, res, params, body, (cur, errMsg, now) => ({ ...cur, status: 'done', lease_token: '', updated_at: now }));
}

export async function jobsFail(req, res, params, body) {
  // mutation-auth: service — only the lease holder may fail a job; a failed job retries (backoff) or dead-letters.
  if (requireService(req, res) === null) return;
  return jobsFinish(req, res, params, body, (cur, errMsg, now) => {
    if (cur.attempts >= cur.max_attempts) return { ...cur, status: 'dead', lease_token: '', last_error: errMsg, updated_at: now }; // bound -> dead-letter
    return { ...cur, status: 'queued', lease_token: '', run_at: now + backoff(cur.attempts), last_error: errMsg, updated_at: now }; // deterministic backoff
  });
}

export async function jobsGet(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const id = intParam(params.job_id);
  if (id === null) return problem(res, 422, 'invalid job id');
  const rec = await storeGet(JOB_QUEUE_NS, String(id));
  if (rec === undefined || rec.owner !== owner) return problem(res, 404, 'job not found'); // cross-owner -> 404 (existence never leaks)
  sendJSON(res, 200, publicView(rec));
}

export async function jobsList(req, res) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  // SCOPED read: only the caller's jobs (filtered on the authenticated owner FIELD), id-sorted, then a BOUNDED page.
  const mine = (await storeValues(JOB_QUEUE_NS)).filter((j) => j.owner === owner).sort((a, b) => a.id - b.id).map(publicView);
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(mine, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}
