// Package billing — subscription billing where over/under-charging is impossible by construction, scoped to the
// AUTHENTICATED owner. The amount is DERIVED from a fixed plan catalog (the decoded input has no amount field, so
// a client-supplied amount cannot even be expressed); an unknown plan is rejected 422, deny-by-default. The owner
// is the bearer token's subject (core.RequireIdentity), NOT a client field — so a caller only ever reads/cancels
// THEIR OWN subscriptions (another owner's is 404, indistinguishable from missing). The lifecycle is MONOTONIC:
// active -> canceled only; cancel is idempotent and writes a TERMINAL value, so concurrent cancels converge and a
// canceled subscription can never return to active. Deny-by-default (no token -> 401). Store namespaces and the
// record shape match the python/node impls; a cancellation survives a restart.
package billing

import (
	"net/http"
	"strconv"

	"app/internal/core"
)

// the plan catalog is POLICY (fixed, code-reviewed): plan -> monthly price in cents — the ONLY source of amounts
var billingPlans = map[string]int{"free": 0, "pro": 2000, "enterprise": 10000}

type billingSub struct {
	Id     int    `json:"id"`
	Owner  string `json:"owner"`
	Plan   string `json:"plan"`
	Status string `json:"status"`
	Amount int    `json:"amount"`
}

var billingSubs = core.NewKV[string, billingSub]("billing_subs")

func BillingSubscribe(w http.ResponseWriter, r *http.Request) {
	// decode FIRST: DecodeJSON enforces the body cap (413) and drains the stream before any reply (incl. a 401).
	in, ok := core.DecodeJSON[struct {
		Plan *string `json:"plan"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if in.Plan == nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	amount, known := billingPlans[*in.Plan]
	if !known { // unknown plan -> deny-by-default (never silently subscribe/bill)
		core.WriteProblem(w, 422, "unknown plan")
		return
	}
	sid := core.NextID("billing_sub") // atomic, durable; a crash before the write loses the id (a gap)
	// the amount comes from the catalog ALONE — nothing to smuggle; the owner is the authenticated subject, not input
	sub := billingSub{Id: sid, Owner: owner, Plan: *in.Plan, Status: "active", Amount: amount}
	billingSubs.Set(strconv.Itoa(sid), sub) // the WHOLE record in ONE atomic write
	core.WriteJSON(w, 201, sub)
}

func BillingGet(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	sid, err := strconv.Atoi(r.PathValue("sub_id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid subscription id") // non-numeric id -> 422, never a silent miss
		return
	}
	sub, exists := billingSubs.Get(strconv.Itoa(sid))
	if !exists || sub.Owner != owner { // owner-scoped: another owner's sub is 404, never revealed
		core.WriteProblem(w, 404, "subscription not found")
		return
	}
	core.WriteJSON(w, 200, sub)
}

func BillingCancel(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	sid, err := strconv.Atoi(r.PathValue("sub_id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid subscription id")
		return
	}
	sub, exists := billingSubs.Get(strconv.Itoa(sid))
	if !exists || sub.Owner != owner { // owner-scoped: you cannot cancel another owner's subscription
		core.WriteProblem(w, 404, "subscription not found")
		return
	}
	// rmw-safe: monotonic + idempotent — "canceled" is TERMINAL, so this write converges under any interleaving —
	// two concurrent cancels write the same value, and nothing ever writes "active" back
	sub.Status = "canceled"
	billingSubs.Set(strconv.Itoa(sid), sub)
	core.WriteJSON(w, 200, sub)
}
