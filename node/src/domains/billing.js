// billing — subscription billing where over/under-charging is impossible by construction, scoped to the
// AUTHENTICATED owner. The amount is DERIVED from a fixed plan catalog (the accepted input carries no amount, so
// a client-supplied amount is simply never read); an unknown plan is rejected 422, deny-by-default. The owner is
// the bearer token's subject (the core requireIdentity seam), NOT a client field — so a caller only ever
// reads/cancels THEIR OWN subscriptions (another owner's is 404, indistinguishable from missing). The lifecycle is
// MONOTONIC: active -> canceled only; cancel is idempotent and writes a TERMINAL value, so concurrent cancels
// converge and a canceled subscription can never return to active. Deny-by-default (no token -> 401). Store
// namespaces and the record shape match the python/go impls; a cancellation survives a restart.
import { intParam, nextId, problem, requireIdentity, sendJSON, storeGet, storePut } from '../core/runtime.js';

// the plan catalog is POLICY (fixed, code-reviewed): plan -> monthly price in cents — the ONLY source of amounts
const PLANS = { free: 0, pro: 2000, enterprise: 10000 };
// state in store: seq "billing_sub" · ns "billing_subs" String(id) -> {id, owner, plan, status, amount}

export async function billingSubscribe(req, res, params, body) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  if (!body || typeof body.plan !== 'string') {
    return problem(res, 422, 'invalid body');
  }
  if (!(body.plan in PLANS)) {
    return problem(res, 422, 'unknown plan'); // unknown plan -> deny-by-default (never silently subscribe/bill)
  }
  const sid = await nextId('billing_sub'); // atomic, durable; a crash before the put loses the id (a gap)
  // the amount comes from the catalog ALONE — body.amount is never read; the owner is the authenticated subject
  const sub = { id: sid, owner, plan: body.plan, status: 'active', amount: PLANS[body.plan] };
  await storePut('billing_subs', String(sid), sub); // the WHOLE record in ONE atomic write
  sendJSON(res, 201, sub);
}

export async function billingGet(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const sid = intParam(params.sub_id);
  if (sid === null) return problem(res, 422, 'invalid subscription id'); // non-numeric/5.0 -> 422
  const sub = await storeGet('billing_subs', String(sid));
  if (sub === undefined || sub.owner !== owner) return problem(res, 404, 'subscription not found'); // owner-scoped
  sendJSON(res, 200, sub);
}

export async function billingCancel(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  const sid = intParam(params.sub_id);
  if (sid === null) return problem(res, 422, 'invalid subscription id');
  const sub = await storeGet('billing_subs', String(sid));
  if (sub === undefined || sub.owner !== owner) return problem(res, 404, 'subscription not found'); // owner-scoped
  // rmw-safe: monotonic + idempotent — "canceled" is TERMINAL, so this write converges under any interleaving —
  // two concurrent cancels write the same value, and nothing ever writes "active" back
  const canceled = { ...sub, status: 'canceled' };
  await storePut('billing_subs', String(sid), canceled);
  sendJSON(res, 200, canceled);
}
