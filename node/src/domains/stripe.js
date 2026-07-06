// stripe — Stripe-shape payments with two dangerous properties, both proven:
// (1) NO DOUBLE-CHARGE: charge creation is idempotent on the Idempotency-Key; the claim is ONE atomic
// read-modify-write through storeDo, so two processes racing the same key produce one charge. Key reuse with a
// DIFFERENT body is a 409 (real Stripe behavior). (2) ONLY STRIPE CAN SPEAK: the webhook verifies
// 'Stripe-Signature: t=,v1=' — HMAC over the RAW request bytes via the central signing part, inside a replay
// window from the test-clock seam; tampered/forged/stale is a 400, deny-by-default. The endpoint secret is
// env-backed. Store names and shapes match the python/go impls; charges are durable across restart.
//
// TWO routes, TWO auth models: stripeCharge is the server-side charge API and requires the AUTHENTICATED
// caller (the core requireIdentity seam) — anonymous is charge fabrication + idempotency-key griefing; no token
// 401. stripeWebhook is authed by the Stripe HMAC, NOT a session (see its `mutation-auth: signature` declaration).
import { isStrictInt, nextId, problem, requireIdentity, sendJSON, storeGet, testNow } from '../core/runtime.js';
import { isCurrency } from '../parts/currency.js';
import { digestHex, scopedKey } from '../parts/digest.js';
import { claimOnce } from '../parts/idempotent_claim.js';
import { stripeVerify } from '../parts/signing.js';
import { isWellFormed } from '../parts/well_formed.js';

// one or more ACTIVE endpoint secrets (comma-separated) — verify against EACH for zero-downtime rotation; empty
// entries dropped (an empty secret = a forgeable empty-key HMAC); no secret configured -> [] -> every webhook denied.
// UNSET falls back to the demo default (dev); a present-but-BLANK value resolves to NO active secret (deny) — never the
// public placeholder — so blanking the env to disable the endpoint can't leave it open (×3-identical with py/go).
const _rawSecret = 'STRIPE_WEBHOOK_SECRET' in process.env ? process.env.STRIPE_WEBHOOK_SECRET : 'whsec_demo_change_me';
const SECRETS = _rawSecret.split(',').map((s) => s.trim()).filter(Boolean);
const TOLERANCE = 300; // seconds; the signature replay window
const ROUTE = 'POST /stripe/charges'; // the route discriminator (per-route caller-scoped slot)
// state in store: seq "stripe_charge" · ns "stripe_charges" SCOPED-key -> {id, amount, currency, status, body_hash, caller}.
// The store key is SCOPED TO THE CALLER via scopedKey so an Idempotency-Key is PRIVATE to its caller.

const digest = (amount, currency) => digestHex('amount', amount, 'currency', currency); // the central fingerprint (digest part)

export async function stripeCharge(req, res, params, body) {
  // requireIdentity: the server-side charge API is for an AUTHENTICATED caller — anonymous is charge
  // fabrication + idempotency-key griefing. The runtime already parsed the body, so a no-token caller is 401 here;
  // strict validation follows, matching python's Depends order and go's decode-then-auth precedence ×3.
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  if (!body || !isStrictInt(body, 'amount') || body.amount < 1 || !isWellFormed(body.currency) ||
      !isCurrency(body.currency)) { // a CLOSED ISO-4217 set, not just well-formed
    return problem(res, 422, 'invalid body');
  }
  const key = req.headers['idempotency-key'];
  if (key === undefined) {
    // no key -> no dedupe (opt-in, per the standard)
    return sendJSON(res, 201, { id: `ch_${await nextId('stripe_charge')}`, amount: body.amount,
                                currency: body.currency, status: 'succeeded' });
  }
  // an Idempotency-Key is a SINGLE opaque token; node comma-joins duplicate headers into one string, so count the raw
  // header lines and REJECT >1 (deterministic + IDENTICAL ×3 — go/python also reject), never dedupe on the joined value.
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
  const h = digest(body.amount, body.currency);
  const scoped = scopedKey(ROUTE, caller, key); // caller-scoped, collision-safe slot
  let prior = await storeGet('stripe_charges', scoped); // fast path: a settled key never mints
  if (prior === undefined) {
    // mint BEFORE the claim (a race loser's id is a gap), then charge once per key via the central part
    const rec = { id: `ch_${await nextId('stripe_charge')}`, amount: body.amount, currency: body.currency,
                  status: 'succeeded', body_hash: h, caller };
    prior = await claimOnce('stripe_charges', scoped, rec);
  }
  if (prior.caller !== caller) {
    // DEFENSE-IN-DEPTH: the scoped slot already isolates callers; a stored-caller mismatch is structurally impossible,
    // so if it ever happens (collision / regression) REFUSE rather than cross-replay.
    return problem(res, 409, 'idempotency key is not owned by this caller');
  }
  if (prior.body_hash !== h) {
    return problem(res, 409, 'idempotency key reused with a different body');
  }
  sendJSON(res, 201, { id: prior.id, amount: prior.amount, currency: prior.currency, status: prior.status });
}

export async function stripeWebhook(req, res, params, body, raw) {
  // mutation-auth: signature — INTENTIONALLY not requireIdentity. This route is authenticated by the Stripe HMAC
  // over the RAW request body (verified below via the central signing part), NOT by a session: Stripe sends no
  // bearer token, so requireIdentity would reject every real delivery with a 401. The signature IS the identity —
  // only the holder of the endpoint secret can produce a valid 'Stripe-Signature', deny-by-default.
  const header = req.headers['stripe-signature'];
  if (header === undefined) return problem(res, 422, 'Stripe-Signature header is required');
  // `raw` is the EXACT request bytes the router captured — Stripe signs the raw body, never a re-serialization
  if (!SECRETS.some((s) => stripeVerify(s, header, raw, testNow(req), TOLERANCE))) {
    return problem(res, 400, 'invalid signature'); // tampered / forged / stale / no active secret -> reject
  }
  sendJSON(res, 200, { received: true });
}
