// Package idempotent_claim — the STATEFUL claim-or-replay composition every exactly-once domain shares
// (idempotency keys, stripe charges, single-use codes): write the record ONLY if the key is unclaimed, and
// ALWAYS return the settled winner — in one atomic cross-process transaction over (*KV).Do. Two processes
// racing the same key get the SAME winner; the loser's record is simply never written. Same contract as
// idempotent_claim.py / idempotent_claim.js, proven by the shared sequences + the two-process race block.
package idempotent_claim

import "app/internal/core"

// ClaimOnce atomically writes rec if key is unclaimed and returns it; else returns the existing winner untouched.
func ClaimOnce[V any](kv *core.KV[string, V], key string, rec V) V {
	var winner V
	kv.Do(key, func(cur V, exists bool) (V, bool) {
		if exists {
			winner = cur
			return cur, false
		}
		winner = rec
		return rec, true
	})
	return winner
}
