// ledger — double-entry: every tx balances (sum == 0, >= 2 entries) else 422; append-only (no update/delete
// route); balances DERIVED never stored. ADMIN-ONLY: both routes require the 'admin' role (the core
// requireAdmin seam) — no token 401, non-admin 403, resolved BEFORE the strict validation, ×3. Validation is STRICT
// via isStrictInt (the runtime's float-literal reviver rejects "100"/100.0/100.5/true/null -> 422) and runs AFTER
// auth and BEFORE the id mint. The WHOLE balanced transaction is ONE atomic row. Store names match the python/go impls.
import { intParam, isStrictInt, nextId, problem, requireAdmin, sendJSON, storePut, storeValues } from '../core/runtime.js';

export async function ledgerPost(req, res, params, body) {
  if ((await requireAdmin(req, res)) === null) return; // AUTH (runtime already parsed the body); strict checks follow, ×3
  if (!body || !Array.isArray(body.entries)) return problem(res, 422, 'invalid body');
  if (body.entries.length < 2) return problem(res, 422, 'double-entry requires >= 2 entries');
  let sum = 0;
  for (const e of body.entries) {
    if (!e || typeof e !== 'object' || !isStrictInt(e, 'account_id') || !isStrictInt(e, 'amount')) {
      return problem(res, 422, 'invalid body');
    }
    sum += e.amount;
  }
  if (sum !== 0) return problem(res, 422, 'transaction does not balance');
  const tid = await nextId('ledger_tx'); // atomic, durable; a crash before the put below loses the id (a harmless gap)
  const entries = body.entries.map((e) => ({ account_id: e.account_id, amount: e.amount }));
  await storePut('ledger_tx', String(tid), { id: tid, entries }); // the WHOLE balanced tx in ONE atomic write
  sendJSON(res, 201, { id: tid, entries });
}

export async function ledgerBalance(req, res, params) {
  if ((await requireAdmin(req, res)) === null) return; // ADMIN-ONLY: a balance reveals financial position (AUTH before path-422)
  const id = intParam(params.account_id);
  if (id === null) return problem(res, 422, 'invalid account id'); // non-numeric/5.0 -> 422, never account NaN
  // unbounded-safe: scalar aggregate — sums the account's entries into a single balance, returns no collection; the O(n) scan is the documented store-swap-at-scale limit (a running-balance row is the Postgres upgrade).
  const derived = (await storeValues('ledger_tx'))
    .flatMap((tx) => tx.entries)
    .filter((e) => e.account_id === id)
    .reduce((a, e) => a + e.amount, 0); // DERIVED from the stored transactions, never stored
  sendJSON(res, 200, { account_id: id, balance: derived });
}
