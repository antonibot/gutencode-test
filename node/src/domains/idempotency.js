// idempotency — replay-safe writes per the IETF Idempotency-Key shape (the Stripe pattern). The dangerous
// property is EXACTLY-ONCE: same key + same body returns the STORED response (the side effect never re-runs);
// same key + a different body is a 409; no key means no deduplication (opt-in, per the standard). The claim is
// ONE atomic read-modify-write through storeDo — two processes racing the same key produce exactly one winner;
// the loser is served the winner's stored response. Durable: a replay works after a restart.
import { isStrictInt, nextId, problem, requireIdentity, sendJSON, storeGet } from '../core/runtime.js';
import { digestHex, scopedKey } from '../parts/digest.js';
import { claimOnce } from '../parts/idempotent_claim.js';
import { isWellFormed } from '../parts/well_formed.js';

// state in store: seq "idempotency_payment" · ns "idempotency_keys" SCOPED-key -> {id, amount, body_hash, caller}.
// The store key is SCOPED TO THE CALLER (scopedKey below) so an Idempotency-Key is PRIVATE to its caller.

const ROUTE = 'POST /idempotency/payments'; // the route discriminator (per-route slot, GAP-6)

// body_hash = the FULL request body fingerprint (here the one field amount) — the SAME-KEY-DIFFERENT-BODY guard,
// SEPARATE from the lookup key. A copier whose body gains fields MUST add them here.
const digest = (amount) => digestHex('amount', amount); // the central canonical fingerprint (digest part)

export async function idempotencyPay(req, res, params, body) {
  // identity: the caller must be AUTHENTICATED (deny-by-default, no token -> 401) BEFORE validation and before the
  // Idempotency-Key. The Idempotency-Key is a DEDUPE token, NOT identity — kept ON TOP of authn AND the dedup slot is
  // SCOPED TO THE CALLER (the key is private to its caller).
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  if (!body || !isStrictInt(body, 'amount') || body.amount < 1) {
    return problem(res, 422, 'amount must be a positive integer');
  }
  const key = req.headers['idempotency-key'];
  if (key === undefined) {
    // no key -> no dedupe; every request is a fresh side effect
    return sendJSON(res, 201, { id: await nextId('idempotency_payment'), amount: body.amount });
  }
  // an Idempotency-Key is a SINGLE opaque token; node comma-joins duplicate headers into one string, so count the
  // raw header lines and REJECT >1 (deterministic + IDENTICAL ×3 — go/python also reject), never dedupe on the
  // ambiguous joined value.
  let nKeys = 0;
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i].toLowerCase() === 'idempotency-key') nKeys += 1;
  }
  if (nKeys > 1) {
    return problem(res, 422, 'Idempotency-Key must be a single value');
  }
  if (!isWellFormed(key)) {
    return problem(res, 422, 'Idempotency-Key must be non-empty with no control characters');
  }
  const h = digest(body.amount);
  const scoped = scopedKey(ROUTE, caller, key); // the central caller-scoped, collision-safe slot (digest part)
  let prior = await storeGet('idempotency_keys', scoped); // fast path: a settled key never mints
  if (prior === undefined) {
    // mint BEFORE the claim (a race loser's id is a gap), then claim atomically via the central part
    const rec = { id: await nextId('idempotency_payment'), amount: body.amount, body_hash: h, caller };
    prior = await claimOnce('idempotency_keys', scoped, rec);
  }
  if (prior.caller !== caller) {
    // DEFENSE-IN-DEPTH: the scoped key already isolates callers; a stored-caller mismatch is structurally impossible,
    // so if it ever happens (collision / regression) REFUSE rather than cross-replay.
    return problem(res, 409, 'idempotency key is not owned by this caller');
  }
  if (prior.body_hash !== h) {
    return problem(res, 409, 'idempotency key reused with a different body');
  }
  // first call and every replay: the SAME response
  sendJSON(res, 201, { id: prior.id, amount: prior.amount });
}
