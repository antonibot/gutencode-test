// CENTRAL idempotent_claim part — the STATEFUL claim-or-replay composition every exactly-once domain shares
// (idempotency keys, stripe charges, single-use codes): write the record ONLY if the key is unclaimed, and
// ALWAYS return the settled winner — in one atomic cross-process transaction over storeDo. Two processes racing
// the same key get the SAME winner; the loser's record is simply never written. Same contract as
// idempotent_claim.py / idempotent_claim.go, proven by the shared sequences + the two-process race block.
import { storeDo } from '../core/runtime.js';

// claimOnce atomically writes rec if ns/key is unclaimed and returns it; else returns the existing winner.
export async function claimOnce(ns, key, rec) {
  return storeDo(ns, key, (cur) => (cur !== undefined ? [undefined, cur] : [rec, rec]));
}
