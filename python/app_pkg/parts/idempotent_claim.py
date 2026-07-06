"""CENTRAL idempotent_claim part — the STATEFUL claim-or-replay composition every exactly-once domain shares
(idempotency keys, stripe charges, single-use codes): write the record ONLY if the key is unclaimed, and ALWAYS
return the settled winner — in one atomic cross-process transaction over the store's `do` seam. Two processes
racing the same key get the SAME winner; the loser's record is simply never written. The claim and the write
are ONE atomic step, so a racing loser can never overwrite the settled winner."""
from ..core import store


def claim_once(ns: str, key: str, rec):
    """Atomically: if ns/key is unclaimed, write rec and return it; else return the existing winner untouched."""
    return store.do(ns, key, lambda cur: ((None, cur) if cur is not None else (rec, rec)))
