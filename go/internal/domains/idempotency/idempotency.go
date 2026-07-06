// Package idempotency — replay-safe writes per the IETF Idempotency-Key shape (the Stripe pattern). The
// dangerous property is EXACTLY-ONCE: same key + same body returns the STORED response (the side effect never
// re-runs); same key + a different body is a 409; no key means no deduplication (opt-in, per the standard).
// The claim is ONE atomic read-modify-write through (*KV).Do — two processes racing the same key produce
// exactly one winner; the loser is served the winner's stored response. Durable: a replay works after restart.
package idempotency

import (
	"net/http"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/idempotent_claim"
	"app/internal/parts/well_formed"
)

type idempotencyRec struct {
	Id       int    `json:"id"`
	Amount   int    `json:"amount"`
	BodyHash string `json:"body_hash"`
	Caller   string `json:"caller"` // the OWNING caller — the dedup slot is private to it (defense-in-depth)
}

var idempotencyKeys = core.NewKV[string, idempotencyRec]("idempotency_keys")

const idempotencyRoute = "POST /idempotency/payments" // the route discriminator (per-route slot, GAP-6)

func idempotencyDigest(amount int) string {
	// body_hash = the FULL request body fingerprint (here the one field amount) — the SAME-KEY-DIFFERENT-BODY guard,
	// SEPARATE from the lookup key. A copier whose body gains fields MUST add them here.
	return digest.DigestHex("amount", amount) // the central canonical fingerprint (digest part)
}

func IdempotencyPay(w http.ResponseWriter, r *http.Request) {
	// identity: the caller must be AUTHENTICATED (deny-by-default, no token -> 401) BEFORE decode and before the
	// Idempotency-Key. The Idempotency-Key is a DEDUPE token, NOT identity — kept ON TOP of authn AND the dedup slot
	// is SCOPED TO THE CALLER (the key is private to its caller).
	caller, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	// decode FIRST: DecodeJSON enforces the body cap (413) and drains the stream before any reply
	in, ok := core.DecodeJSON[struct {
		Amount *int `json:"amount"`
	}](w, r)
	if !ok {
		return
	}
	if in.Amount == nil || *in.Amount < 1 || *in.Amount > core.MaxSafeInt { // bounded to the ×3-safe range
		core.WriteProblem(w, 422, "amount must be a positive integer")
		return
	}
	key, hasKey := r.Header["Idempotency-Key"]
	if !hasKey { // no key -> no dedupe; every request is a fresh side effect
		pid := core.NextID("idempotency_payment")
		core.WriteJSON(w, 201, map[string]any{"id": pid, "amount": *in.Amount})
		return
	}
	if len(key) > 1 { // an Idempotency-Key is a SINGLE opaque token; duplicate headers are ambiguous -> reject (×3 parity)
		core.WriteProblem(w, 422, "Idempotency-Key must be a single value")
		return
	}
	k := key[0] // exactly one value (hasKey -> len>=1; duplicates rejected above)
	if !well_formed.IsWellFormed(k) { // a PRESENT key must be a well-formed identifier
		core.WriteProblem(w, 422, "Idempotency-Key must be non-empty with no control characters")
		return
	}
	digestVal := idempotencyDigest(*in.Amount)
	scoped := digest.ScopedKey(idempotencyRoute, caller, k) // the central caller-scoped, collision-safe slot (digest part)
	prior, settled := idempotencyKeys.Get(scoped) // fast path: a settled key never mints
	if !settled {
		// mint BEFORE the claim (a race loser's id is a gap), then claim atomically via the central part
		rec := idempotencyRec{Id: core.NextID("idempotency_payment"), Amount: *in.Amount, BodyHash: digestVal, Caller: caller}
		prior = idempotent_claim.ClaimOnce(idempotencyKeys, scoped, rec)
	}
	if prior.Caller != caller {
		// DEFENSE-IN-DEPTH: the scoped key already isolates callers; a stored-caller mismatch is structurally
		// impossible, so if it ever happens (collision / regression) REFUSE rather than cross-replay.
		core.WriteProblem(w, 409, "idempotency key is not owned by this caller")
		return
	}
	if prior.BodyHash != digestVal {
		core.WriteProblem(w, 409, "idempotency key reused with a different body")
		return
	}
	// first call and every replay: the SAME response
	core.WriteJSON(w, 201, map[string]any{"id": prior.Id, "amount": prior.Amount})
}
