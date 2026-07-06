// Package payments — a provider-agnostic payment-INTENT lifecycle (authorize · retrieve · capture/void/refund),
// with two dangerous properties proven:
// (1) EXACTLY-ONCE AUTHORIZATION: the intent id is DERIVED — id = digest.ScopedKey("POST /payments", caller,
// Idempotency-Key) — a caller-private, deterministic slot; the claim is ONE atomic read-modify-write through
// (*KV).Do (via idempotent_claim), so two processes racing the same key authorize ONE intent. The same key with a
// DIFFERENT body is a 409. The amount is CAPPED at 2^53-1 so the per-intent balance sums this domain will run can
// never wrap int64 / lose Node float precision (the money-conservation ×3 floor).
// (2) OWNER ISOLATION: an intent belongs to its authorizing caller (core.RequireIdentity). The store slot is the
// composite "<caller>\x1f<id>", so a by-id get for another caller's intent lands in a DIFFERENT slot -> 404,
// byte-indistinguishable from missing; the list is owner-FIELD-filtered.
// Every route requires the AUTHENTICATED caller — an anonymous authorize is money fabrication; no token -> 401.
// Store names and the intent shape match the python/node impls.
package payments

import (
	"encoding/json"
	"net/http"

	"app/internal/core"
	"app/internal/parts/currency"
	"app/internal/parts/digest"
	"app/internal/parts/idempotent_claim"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

const paymentsRoute = "POST /payments" // the route discriminator (per-route caller-private derived id/slot)
const maxAmount = (1 << 53) - 1        // the cross-language-safe amount ceiling (Node exact-int + no int64 sum-wrap)

var paymentsKV = core.NewKV[string, paymentIntent]("payments_intents")

type paymentRefund struct {
	Key    string `json:"key"`
	Amount int    `json:"amount"`
}

type paymentIntent struct {
	Id             string          `json:"id"`
	Caller         string          `json:"caller"` // the OWNING caller — the composite slot is private to it
	Status         string          `json:"status"`
	Amount         int             `json:"amount"`
	Currency       string          `json:"currency"`
	AmountCaptured int             `json:"amount_captured"`
	AmountVoided   int             `json:"amount_voided"`
	AmountRefunded int             `json:"amount_refunded"`
	Refunds        []paymentRefund `json:"refunds"`
	BodyHash       string          `json:"body_hash"`
}

func paymentsDigest(amount int, currency string) string {
	return digest.DigestHex("amount", amount, "currency", currency) // the central canonical body fingerprint
}

// paymentOut is the PUBLIC projection — the internal caller/body_hash/refunds bookkeeping never leaves the store.
func paymentOut(p paymentIntent) map[string]any {
	return map[string]any{"id": p.Id, "status": p.Status, "amount": p.Amount, "currency": p.Currency,
		"amount_captured": p.AmountCaptured, "amount_voided": p.AmountVoided, "amount_refunded": p.AmountRefunded}
}

func PaymentsAuthorize(w http.ResponseWriter, r *http.Request) {
	// PARSE -> AUTH -> SEMANTIC: DecodeJSON (raw) FIRST (413/422 + drains the body), THEN RequireIdentity (no token
	// 401), THEN the strict per-field validation — so a no-token ill-typed body is 401, identical to python ×3.
	raw, ok := core.DecodeJSON[json.RawMessage](w, r)
	if !ok {
		return
	}
	subject, ok := core.RequireIdentity(w, r) // AUTH: authorizing an intent needs an authenticated caller
	if !ok {
		return
	}
	var in struct {
		Amount   json.RawMessage `json:"amount"`
		Currency *string         `json:"currency"`
	}
	if json.Unmarshal(raw, &in) != nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	// amount is RequireIntRaw'd on the RAW bytes so a quoted "100" / 100.5 / true / null / missing all reject; the
	// cap rejects an amount that would overflow the per-intent balance sums (parity with python StrictInt+le ×3).
	amount, amok := core.RequireIntRaw(in.Amount)
	if !amok || amount < 1 || amount > maxAmount || in.Currency == nil || !well_formed.IsWellFormed(*in.Currency) ||
		!currency.IsCurrency(*in.Currency) { // a CLOSED ISO-4217 set, not just well-formed
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	key, hasKey := r.Header["Idempotency-Key"]
	if !hasKey { // REQUIRED: the intent id is DERIVED from the key (no key, no id)
		core.WriteProblem(w, 422, "Idempotency-Key header is required")
		return
	}
	if len(key) > 1 { // a SINGLE opaque token; duplicate headers are ambiguous -> reject (×3 parity)
		core.WriteProblem(w, 422, "Idempotency-Key must be a single value")
		return
	}
	k := key[0]
	if !well_formed.IsWellFormed(k) {
		core.WriteProblem(w, 422, "Idempotency-Key must be non-empty with no control characters")
		return
	}
	bodyHash := paymentsDigest(amount, *in.Currency)
	piID := digest.ScopedKey(paymentsRoute, subject, k) // the deterministic, caller-private intent id
	slot := subject + "\x1f" + piID                     // the owner-composite store slot (cross-caller -> 404)
	prior, settled := paymentsKV.Get(slot)              // fast path: a settled key never re-authorizes
	if !settled {
		rec := paymentIntent{Id: piID, Caller: subject, Status: "authorized", Amount: amount,
			Currency: *in.Currency, AmountCaptured: 0, AmountVoided: 0, AmountRefunded: 0,
			Refunds: []paymentRefund{}, BodyHash: bodyHash}
		prior = idempotent_claim.ClaimOnce(paymentsKV, slot, rec) // ONE atomic claim per slot (no double-authorize)
	}
	if prior.Caller != subject {
		// DEFENSE-IN-DEPTH: the composite slot isolates callers; a mismatch is structurally impossible, so REFUSE.
		core.WriteProblem(w, 409, "idempotency key is not owned by this caller")
		return
	}
	if prior.BodyHash != bodyHash {
		core.WriteProblem(w, 409, "idempotency key reused with a different body")
		return
	}
	core.WriteJSON(w, 201, paymentOut(prior))
}

func PaymentsList(w http.ResponseWriter, r *http.Request) {
	subject, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	// SCOPED read: only the caller's OWN intents (owner-FIELD-filtered — the comparison runs on the STORED owner
	// field, never a client value), then a BOUNDED page over that stable-ordered set via the shared paginate part.
	mine := []paymentIntent{}
	for _, p := range paymentsKV.All() {
		if p.Caller == subject {
			mine = append(mine, p)
		}
	}
	q := r.URL.Query()
	page, next, valid := paginate.Paginate(mine, q.Get("cursor"), q.Get("limit"))
	if !valid {
		core.WriteProblem(w, 422, "invalid cursor or limit")
		return
	}
	results := []map[string]any{}
	for _, p := range page {
		results = append(results, paymentOut(p))
	}
	var nc any
	if next != "" {
		nc = next
	}
	core.WriteJSON(w, 200, map[string]any{"results": results, "next_cursor": nc})
}

func PaymentsGet(w http.ResponseWriter, r *http.Request) {
	subject, ok := core.RequireIdentity(w, r) // AUTH before path-422: a no-token control-char probe is 401, ×3
	if !ok {
		return
	}
	id := r.PathValue("payment_id")
	if !well_formed.IsWellFormed(id) {
		core.WriteProblem(w, 422, "the payment id must be non-empty with no control characters")
		return
	}
	rec, found := paymentsKV.Get(subject + "\x1f" + id)
	if !found {
		core.WriteProblem(w, 404, "payment not found") // not-yours == not-found: another caller's intent is elsewhere
		return
	}
	core.WriteJSON(w, 200, paymentOut(rec))
}

// ── the lifecycle TRANSITIONS — each is ONE atomic read-modify-write through (*KV).Do. The state read, the
// conservation check, and the write ALL happen INSIDE the callback against `cur` (NEVER a value read before Do — the
// latent-RMW class no gate catches), so two processes racing a transition serialize and the loser sees the
// already-transitioned intent (no double-capture / void-after-capture race). ────────────────────────────────────

func PaymentsCapture(w http.ResponseWriter, r *http.Request) {
	raw, ok := core.DecodeJSON[json.RawMessage](w, r) // PARSE -> AUTH -> SEMANTIC (body required: {amount})
	if !ok {
		return
	}
	subject, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	id := r.PathValue("payment_id")
	if !well_formed.IsWellFormed(id) {
		core.WriteProblem(w, 422, "the payment id must be non-empty with no control characters")
		return
	}
	var in struct {
		Amount json.RawMessage `json:"amount"`
	}
	if json.Unmarshal(raw, &in) != nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	amount, amok := core.RequireIntRaw(in.Amount)
	if !amok || amount < 1 || amount > maxAmount { // a strict, capped, REQUIRED amount (full = the authorized amount)
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	code := 0
	var rec paymentIntent
	paymentsKV.Do(subject+"\x1f"+id, func(cur paymentIntent, exists bool) (paymentIntent, bool) {
		if !exists {
			code = 404
			return cur, false
		}
		if cur.Status != "authorized" { // capture-after-capture / after-void -> 409
			code = 409
			return cur, false
		}
		if amount > cur.Amount { // over-capture -> 422
			code = 422
			return cur, false
		}
		cur.Status = "captured"
		cur.AmountCaptured = amount
		cur.AmountVoided = cur.Amount - amount // CONSERVATION: the uncaptured remainder is released
		rec = cur
		return cur, true
	})
	switch code {
	case 404:
		core.WriteProblem(w, 404, "payment not found")
		return
	case 409:
		core.WriteProblem(w, 409, "payment is not in the authorized state")
		return
	case 422:
		core.WriteProblem(w, 422, "capture amount must not exceed the authorized amount")
		return
	}
	core.WriteJSON(w, 200, paymentOut(rec))
}

func PaymentsVoid(w http.ResponseWriter, r *http.Request) {
	subject, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	id := r.PathValue("payment_id")
	if !well_formed.IsWellFormed(id) {
		core.WriteProblem(w, 422, "the payment id must be non-empty with no control characters")
		return
	}
	code := 0
	var rec paymentIntent
	paymentsKV.Do(subject+"\x1f"+id, func(cur paymentIntent, exists bool) (paymentIntent, bool) {
		if !exists {
			code = 404
			return cur, false
		}
		if cur.Status != "authorized" { // void-after-capture / double-void -> 409
			code = 409
			return cur, false
		}
		cur.Status = "voided"
		cur.AmountVoided = cur.Amount // CONSERVATION: the full authorization is released
		rec = cur
		return cur, true
	})
	switch code {
	case 404:
		core.WriteProblem(w, 404, "payment not found")
		return
	case 409:
		core.WriteProblem(w, 409, "payment is not in the authorized state")
		return
	}
	core.WriteJSON(w, 200, paymentOut(rec))
}

func PaymentsRefund(w http.ResponseWriter, r *http.Request) {
	// a refund is idempotent on its Idempotency-Key (a retried refund must NOT double-refund) — UNLIKE capture/void,
	// which are one-time transitions idempotent by the status check. The dedup scan + the conservation check + the
	// append ALL happen inside the ONE Do() callback (never a pre-read), so a racing retry / over-refund is refused.
	// The key is scoped BY CONSTRUCTION to the owner-composite slot (a cross-caller refund 404s before it is consulted).
	raw, ok := core.DecodeJSON[json.RawMessage](w, r)
	if !ok {
		return
	}
	subject, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	id := r.PathValue("payment_id")
	if !well_formed.IsWellFormed(id) {
		core.WriteProblem(w, 422, "the payment id must be non-empty with no control characters")
		return
	}
	var in struct {
		Amount json.RawMessage `json:"amount"`
	}
	if json.Unmarshal(raw, &in) != nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	amount, amok := core.RequireIntRaw(in.Amount)
	if !amok || amount < 1 || amount > maxAmount {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	key, hasKey := r.Header["Idempotency-Key"]
	if !hasKey {
		core.WriteProblem(w, 422, "Idempotency-Key header is required")
		return
	}
	if len(key) > 1 {
		core.WriteProblem(w, 422, "Idempotency-Key must be a single value")
		return
	}
	k := key[0]
	if !well_formed.IsWellFormed(k) {
		core.WriteProblem(w, 422, "Idempotency-Key must be non-empty with no control characters")
		return
	}
	code := 0
	detail := ""
	var rec paymentIntent
	paymentsKV.Do(subject+"\x1f"+id, func(cur paymentIntent, exists bool) (paymentIntent, bool) {
		if !exists {
			code = 404
			return cur, false
		}
		if cur.Status != "captured" { // refund-before-capture / after-void -> 409
			code = 409
			detail = "payment must be captured before it can be refunded"
			return cur, false
		}
		for _, rf := range cur.Refunds { // idempotent: a settled refund key returns the stored intent
			if rf.Key == k {
				if rf.Amount != amount {
					code = 409
					detail = "idempotency key reused with a different refund amount"
					return cur, false
				}
				rec = cur // same key + amount -> the unchanged intent (no double-refund)
				return cur, false
			}
		}
		sum := 0
		for _, rf := range cur.Refunds {
			sum += rf.Amount
		}
		if sum+amount > cur.AmountCaptured { // over-refund -> 422
			code = 422
			return cur, false
		}
		cur.Refunds = append(cur.Refunds, paymentRefund{Key: k, Amount: amount})
		cur.AmountRefunded += amount // CONSERVATION: Σrefunds <= captured
		rec = cur
		return cur, true
	})
	switch code {
	case 404:
		core.WriteProblem(w, 404, "payment not found")
		return
	case 409:
		core.WriteProblem(w, 409, detail)
		return
	case 422:
		core.WriteProblem(w, 422, "refund amount would exceed the captured amount")
		return
	}
	core.WriteJSON(w, 200, paymentOut(rec))
}
