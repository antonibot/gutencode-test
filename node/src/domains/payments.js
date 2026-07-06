// payments — a provider-agnostic payment-INTENT lifecycle (authorize · retrieve · capture/void/refund), with two
// dangerous properties proven:
// (1) EXACTLY-ONCE AUTHORIZATION: the intent id is DERIVED — id = scopedKey('POST /payments', caller,
// Idempotency-Key) — a caller-private, deterministic slot; the claim is ONE atomic read-modify-write through
// storeDo (via claimOnce), so two processes racing the same key authorize ONE intent. The same key with a DIFFERENT
// body is a 409. The amount is CAPPED at 2^53-1 so the per-intent balance sums this domain will run can never lose
// float precision / wrap int64 (the money-conservation ×3 floor).
// (2) OWNER ISOLATION: an intent belongs to its authorizing caller (the core requireIdentity seam). The store slot
// is the composite '<caller>\x1f<id>', so a by-id get for another caller's intent lands in a DIFFERENT slot -> 404,
// byte-indistinguishable from missing; the list is owner-FIELD-filtered.
// Every route requires the AUTHENTICATED caller — an anonymous authorize is money fabrication; no token -> 401.
// Store names and the intent shape match the python/go impls.
import { isStrictInt, problem, requireIdentity, sendJSON, storeDo, storeGet, storeValues } from '../core/runtime.js';
import { isCurrency } from '../parts/currency.js';
import { digestHex, scopedKey } from '../parts/digest.js';
import { claimOnce } from '../parts/idempotent_claim.js';
import { paginate } from '../parts/paginate.js';
import { isWellFormed } from '../parts/well_formed.js';

const NS = 'payments_intents';
const ROUTE = 'POST /payments'; // the route discriminator (per-route caller-private derived id/slot)
const MAX_AMOUNT = Number.MAX_SAFE_INTEGER; // 2^53-1 — the cross-language-safe amount ceiling (no float-precision/int64 sum overflow)
// state in store: ns "payments_intents" composite key "<caller>\x1f<id>" -> the intent record (field names match py/go):
// {id, caller, status, amount, currency, amount_captured, amount_voided, amount_refunded, refunds, body_hash}.

const digest = (amount, currency) => digestHex('amount', amount, 'currency', currency); // the central body fingerprint

// the PUBLIC projection — the internal caller/body_hash/refunds bookkeeping never leaves the store.
const publicOut = (p) => ({ id: p.id, status: p.status, amount: p.amount, currency: p.currency,
  amount_captured: p.amount_captured, amount_voided: p.amount_voided, amount_refunded: p.amount_refunded });

export async function paymentsAuthorize(req, res, params, body) {
  // requireIdentity FIRST (the runtime already parsed the body, so a no-token caller is 401 here); strict
  // validation follows, matching python's Depends order and go's decode-then-auth precedence ×3.
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  // amount: a strict integer in [1, MAX_AMOUNT] (the cap rejects an overflow-prone amount); currency: a CLOSED ISO set
  if (!body || !isStrictInt(body, 'amount') || body.amount < 1 || body.amount > MAX_AMOUNT ||
      !isWellFormed(body.currency) || !isCurrency(body.currency)) {
    return problem(res, 422, 'invalid body');
  }
  const key = req.headers['idempotency-key'];
  if (key === undefined) return problem(res, 422, 'Idempotency-Key header is required'); // DERIVED id: no key, no id
  // a SINGLE opaque token; node comma-joins duplicate headers, so count the raw header lines and REJECT >1 (×3 parity)
  let nKeys = 0;
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i].toLowerCase() === 'idempotency-key') nKeys += 1;
  }
  if (nKeys > 1) return problem(res, 422, 'Idempotency-Key must be a single value');
  if (!isWellFormed(key)) return problem(res, 422, 'Idempotency-Key must be non-empty with no control characters');
  const h = digest(body.amount, body.currency);
  const piId = scopedKey(ROUTE, caller, key); // the deterministic, caller-private intent id
  const slot = `${caller}\x1f${piId}`;        // the owner-composite store slot (cross-caller -> 404)
  let prior = await storeGet(NS, slot);             // fast path: a settled key never re-authorizes
  if (prior === undefined) {
    const rec = { id: piId, caller, status: 'authorized', amount: body.amount, currency: body.currency,
      amount_captured: 0, amount_voided: 0, amount_refunded: 0, refunds: [], body_hash: h };
    prior = await claimOnce(NS, slot, rec); // ONE atomic claim per slot (no double-authorize under a race)
  }
  if (prior.caller !== caller) {
    // DEFENSE-IN-DEPTH: the composite slot isolates callers; a mismatch is structurally impossible, so REFUSE.
    return problem(res, 409, 'idempotency key is not owned by this caller');
  }
  if (prior.body_hash !== h) return problem(res, 409, 'idempotency key reused with a different body');
  sendJSON(res, 201, publicOut(prior));
}

export async function paymentsList(req, res) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  // SCOPED read: only the caller's OWN intents (owner-FIELD-filtered — the comparison runs on the STORED owner
  // field, never a client value), then a BOUNDED page over that stable-ordered set via the shared paginate part.
  const mine = (await storeValues(NS)).filter((p) => p.caller === caller);
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(mine, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items.map(publicOut), next_cursor: next });
}

export async function paymentsGet(req, res, params) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const id = params.payment_id;
  if (!isWellFormed(id)) return problem(res, 422, 'the payment id must be non-empty with no control characters');
  const rec = await storeGet(NS, `${caller}\x1f${id}`);
  if (rec === undefined) return problem(res, 404, 'payment not found'); // not-yours == not-found
  sendJSON(res, 200, publicOut(rec));
}

// ── the lifecycle TRANSITIONS — each is ONE atomic read-modify-write through storeDo. The state read, the
// conservation check, and the write ALL happen INSIDE the callback against `cur` (NEVER a value read before storeDo —
// the latent-RMW class no gate catches), so two processes racing a transition serialize and the loser sees the
// already-transitioned intent (no double-capture / void-after-capture race).

export async function paymentsCapture(req, res, params, body) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const id = params.payment_id;
  if (!isWellFormed(id)) return problem(res, 422, 'the payment id must be non-empty with no control characters');
  if (!body || !isStrictInt(body, 'amount') || body.amount < 1 || body.amount > MAX_AMOUNT) {
    return problem(res, 422, 'invalid body'); // a strict, capped, REQUIRED amount (full capture = the authorized amount)
  }
  let code = 0;
  let rec;
  await storeDo(NS, `${caller}\x1f${id}`, (cur) => {
    if (cur === undefined) { code = 404; return [undefined, null]; }
    if (cur.status !== 'authorized') { code = 409; return [undefined, null]; } // capture-after-capture / after-void
    if (body.amount > cur.amount) { code = 422; return [undefined, null]; }    // over-capture
    cur.status = 'captured';
    cur.amount_captured = body.amount;
    cur.amount_voided = cur.amount - body.amount; // CONSERVATION: the uncaptured remainder is released
    rec = cur;
    return [cur, null];
  });
  if (code === 404) return problem(res, 404, 'payment not found');
  if (code === 409) return problem(res, 409, 'payment is not in the authorized state');
  if (code === 422) return problem(res, 422, 'capture amount must not exceed the authorized amount');
  sendJSON(res, 200, publicOut(rec));
}

export async function paymentsVoid(req, res, params) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const id = params.payment_id;
  if (!isWellFormed(id)) return problem(res, 422, 'the payment id must be non-empty with no control characters');
  let code = 0;
  let rec;
  await storeDo(NS, `${caller}\x1f${id}`, (cur) => {
    if (cur === undefined) { code = 404; return [undefined, null]; }
    if (cur.status !== 'authorized') { code = 409; return [undefined, null]; } // void-after-capture / double-void
    cur.status = 'voided';
    cur.amount_voided = cur.amount; // CONSERVATION: the full authorization is released
    rec = cur;
    return [cur, null];
  });
  if (code === 404) return problem(res, 404, 'payment not found');
  if (code === 409) return problem(res, 409, 'payment is not in the authorized state');
  sendJSON(res, 200, publicOut(rec));
}

export async function paymentsRefund(req, res, params, body) {
  // a refund is idempotent on its Idempotency-Key (a retried refund must NOT double-refund) — UNLIKE capture/void,
  // which are one-time transitions idempotent by the status check. The dedup scan + the conservation check + the
  // append ALL happen inside the ONE storeDo callback (never a pre-read), so a racing retry / over-refund is refused.
  // The key is scoped BY CONSTRUCTION to the owner-composite slot (a cross-caller refund 404s before it is consulted).
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const id = params.payment_id;
  if (!isWellFormed(id)) return problem(res, 422, 'the payment id must be non-empty with no control characters');
  if (!body || !isStrictInt(body, 'amount') || body.amount < 1 || body.amount > MAX_AMOUNT) {
    return problem(res, 422, 'invalid body');
  }
  const key = req.headers['idempotency-key'];
  if (key === undefined) return problem(res, 422, 'Idempotency-Key header is required');
  let nKeys = 0;
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i].toLowerCase() === 'idempotency-key') nKeys += 1;
  }
  if (nKeys > 1) return problem(res, 422, 'Idempotency-Key must be a single value');
  if (!isWellFormed(key)) return problem(res, 422, 'Idempotency-Key must be non-empty with no control characters');
  let code = 0;
  let detail = '';
  let rec;
  await storeDo(NS, `${caller}\x1f${id}`, (cur) => {
    if (cur === undefined) { code = 404; return [undefined, null]; }
    if (cur.status !== 'captured') { // refund-before-capture / after-void -> 409
      code = 409; detail = 'payment must be captured before it can be refunded';
      return [undefined, null];
    }
    for (const rf of cur.refunds) { // idempotent: a settled refund key returns the stored intent
      if (rf.key === key) {
        if (rf.amount !== body.amount) {
          code = 409; detail = 'idempotency key reused with a different refund amount';
          return [undefined, null];
        }
        rec = cur; // same key + amount -> the unchanged intent (no double-refund)
        return [undefined, null];
      }
    }
    const sum = cur.refunds.reduce((s, rf) => s + rf.amount, 0);
    if (sum + body.amount > cur.amount_captured) { code = 422; return [undefined, null]; } // over-refund
    cur.refunds = [...cur.refunds, { key, amount: body.amount }];
    cur.amount_refunded = cur.amount_refunded + body.amount; // CONSERVATION: Σrefunds <= captured
    rec = cur;
    return [cur, null];
  });
  if (code === 404) return problem(res, 404, 'payment not found');
  if (code === 409) return problem(res, 409, detail);
  if (code === 422) return problem(res, 422, 'refund amount would exceed the captured amount');
  sendJSON(res, 200, publicOut(rec));
}
