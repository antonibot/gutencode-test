// Package stripe — Stripe-shape payments with two dangerous properties, both proven:
// (1) NO DOUBLE-CHARGE: charge creation is idempotent on the Idempotency-Key; the claim is ONE atomic
// read-modify-write through (*KV).Do, so two processes racing the same key produce one charge. Key reuse with a
// DIFFERENT body is a 409 (real Stripe behavior). (2) ONLY STRIPE CAN SPEAK: the webhook verifies
// 'Stripe-Signature: t=,v1=' — HMAC over the RAW request bytes via the central signing part, inside a replay
// window from the test-clock seam; tampered/forged/stale is a 400, deny-by-default. The endpoint secret is
// env-backed. Store names and shapes match the python/node impls; charges are durable across restart.
//
// TWO routes, TWO auth models: StripeCharge is the server-side charge API and requires the AUTHENTICATED
// caller (core.RequireIdentity) — anonymous is charge fabrication + idempotency-key griefing. It is body-only, so
// the precedence is PARSE -> AUTH -> SEMANTIC: DecodeJSON (raw) FIRST (413/422 + drains the body), THEN
// RequireIdentity (no token 401), THEN the strict per-field validation — identical to python's Depends order ×3.
// StripeWebhook is authed by the Stripe HMAC, NOT a session (see its `mutation-auth: signature` declaration).
package stripe

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"app/internal/core"
	"app/internal/parts/currency"
	"app/internal/parts/digest"
	"app/internal/parts/idempotent_claim"
	"app/internal/parts/signing"
	"app/internal/parts/well_formed"
)

// stripeActiveSecrets reads STRIPE_WEBHOOK_SECRET and splits it into ACTIVE endpoint secrets, dropping empty entries
// (an empty secret would be a forgeable empty-key HMAC) — verify against EACH for zero-downtime rotation. UNSET falls
// back to the demo default (dev); a present-but-BLANK value resolves to NO active secret -> deny (never the public
// placeholder), so blanking the env to disable the endpoint can't leave it open (×3-identical with py/node).
func stripeActiveSecrets() []string {
	raw, ok := os.LookupEnv("STRIPE_WEBHOOK_SECRET")
	if !ok {
		raw = core.EnvOr("STRIPE_WEBHOOK_SECRET", "whsec_demo_change_me") // UNSET -> demo default (the literal stays behind EnvOr)
	}
	out := []string{}
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

var (
	stripeSecrets   = stripeActiveSecrets()
	stripeTolerance = int64(300) // seconds; the replay window
	stripeCharges   = core.NewKV[string, stripeCharge]("stripe_charges")
)

const stripeRoute = "POST /stripe/charges" // the route discriminator (per-route caller-scoped slot)

type stripeCharge struct {
	Id       string `json:"id"`
	Amount   int    `json:"amount"`
	Currency string `json:"currency"`
	Status   string `json:"status"`
	BodyHash string `json:"body_hash"`
	Caller   string `json:"caller"` // the OWNING caller — the dedup slot is private to it (defense-in-depth)
}

func stripeDigest(amount int, currency string) string {
	return digest.DigestHex("amount", amount, "currency", currency) // the central canonical fingerprint (digest part)
}

func StripeCharge(w http.ResponseWriter, r *http.Request) {
	// PARSE: decode the body as raw JSON FIRST — DecodeJSON enforces the body cap (413) and drains the stream before
	// any reply (replying, incl. a 401, before the body is read aborts the connection). Per-field type checks are
	// SEMANTIC and run AFTER auth, exactly like python's pydantic — so a no-token ill-typed body is 401, ×3.
	raw, ok := core.DecodeJSON[json.RawMessage](w, r)
	if !ok {
		return
	}
	subject, ok := core.RequireIdentity(w, r) // AUTH: server-side charge API needs an authenticated caller
	if !ok {
		return
	}
	// SEMANTIC: amount is RequireIntRaw'd on the RAW bytes so a QUOTED "100" / 100.5 / true / null / missing are all
	// rejected (json.Number would have accepted "100" as 100, diverging from python StrictInt + node isStrictInt).
	var in struct {
		Amount   json.RawMessage `json:"amount"`
		Currency *string         `json:"currency"`
	}
	if json.Unmarshal(raw, &in) != nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	amount, amok := core.RequireIntRaw(in.Amount)
	if !amok || amount < 1 || in.Currency == nil || !well_formed.IsWellFormed(*in.Currency) ||
		!currency.IsCurrency(*in.Currency) { // a CLOSED ISO-4217 set, not just well-formed
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	key, hasKey := r.Header["Idempotency-Key"]
	if !hasKey { // no key -> no dedupe (opt-in, per the standard)
		cid := core.NextID("stripe_charge")
		core.WriteJSON(w, 201, map[string]any{"id": fmt.Sprintf("ch_%d", cid), "amount": amount,
			"currency": *in.Currency, "status": "succeeded"})
		return
	}
	if len(key) > 1 { // an Idempotency-Key is a SINGLE opaque token; duplicate headers are ambiguous -> reject (×3 parity)
		core.WriteProblem(w, 422, "Idempotency-Key must be a single value")
		return
	}
	k := key[0] // exactly one value (hasKey -> len>=1; duplicates rejected above)
	if !well_formed.IsWellFormed(k) {
		core.WriteProblem(w, 422, "Idempotency-Key must be non-empty with no control characters")
		return
	}
	digestVal := stripeDigest(amount, *in.Currency)
	scoped := digest.ScopedKey(stripeRoute, subject, k) // caller-scoped, collision-safe slot
	prior, settled := stripeCharges.Get(scoped)         // fast path: a settled key never mints
	if !settled {
		// mint BEFORE the claim (a race loser's id is a gap), then charge once per key via the central part
		rec := stripeCharge{Id: fmt.Sprintf("ch_%d", core.NextID("stripe_charge")), Amount: amount,
			Currency: *in.Currency, Status: "succeeded", BodyHash: digestVal, Caller: subject}
		prior = idempotent_claim.ClaimOnce(stripeCharges, scoped, rec)
	}
	if prior.Caller != subject {
		// DEFENSE-IN-DEPTH: the scoped slot already isolates callers; a stored-caller mismatch is structurally
		// impossible, so if it ever happens (collision / regression) REFUSE rather than cross-replay.
		core.WriteProblem(w, 409, "idempotency key is not owned by this caller")
		return
	}
	if prior.BodyHash != digestVal {
		core.WriteProblem(w, 409, "idempotency key reused with a different body")
		return
	}
	core.WriteJSON(w, 201, map[string]any{"id": prior.Id, "amount": prior.Amount,
		"currency": prior.Currency, "status": prior.Status})
}

func StripeWebhook(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: signature — INTENTIONALLY not RequireIdentity. This route is authenticated by the Stripe HMAC
	// over the RAW request body (verified below via the central signing part), NOT by a session: Stripe sends no
	// bearer token, so RequireIdentity would reject every real delivery with a 401. The signature IS the identity —
	// only the holder of the endpoint secret can produce a valid 'Stripe-Signature', deny-by-default.
	raw, err := io.ReadAll(r.Body) // the EXACT event bytes — Stripe signs the raw body (capped by the server wrap)
	if err != nil {
		core.WriteProblem(w, 413, "request body too large")
		return
	}
	header := r.Header.Get("Stripe-Signature")
	if header == "" {
		core.WriteProblem(w, 422, "Stripe-Signature header is required")
		return
	}
	verified := false
	for _, s := range stripeSecrets { // try EACH active secret (zero-downtime rotation); empty list -> deny
		if signing.StripeVerify(s, header, string(raw), core.TestNow(r), stripeTolerance) {
			verified = true
			break
		}
	}
	if !verified {
		core.WriteProblem(w, 400, "invalid signature") // tampered / forged / stale / no active secret -> reject
		return
	}
	core.WriteJSON(w, 200, map[string]any{"received": true})
}
