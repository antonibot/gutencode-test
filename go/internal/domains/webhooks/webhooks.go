// Package webhooks — Standard-Webhooks signing (outbound WebhookSend) + verification with REPLAY-DEDUP (inbound
// WebhookVerify). Calls the CENTRAL signing part (never re-inlines HMAC); the msg seq, the sent log,
// and the inbound seen-set live in the durable store seam (same names as the python/node impls); the
// clock comes from core.TestNow (a `now` param counts only under APP_TEST_CLOCK=1).
//
// DANGEROUS PROPERTY: delivery integrity at a trust boundary — a forgery, a REPLAY, or a silently-dropped
// ROTATED delivery is takeover-class. (1) MULTI-SECRET ROTATION: WebhookSend signs with EVERY active secret
// (space-joined); WebhookVerify accepts a delivery matching ANY active secret. (2) INBOUND REPLAY-DEDUP
// (exactly-once): a same-id 2nd verify inside the window is flagged a DUPLICATE so the consumer skips it.
//
// TWO routes, TWO auth models: WebhookSend is ADMIN-ONLY (core.RequireAdmin) — signing with the SERVER secret
// means an open route is signature forgery; no token 401, a non-admin 403, resolved BEFORE the payload check (×3).
// WebhookVerify is intentionally PUBLIC (see its `mutation-auth: public` declaration).
package webhooks

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/signing"
)

const whTolerance = 300                       // seconds; replay window
const whVerifyRoute = "POST /webhooks/verify" // the dedup-slot discriminator — route + the matched-secret label

// whActiveSecrets reads WEBHOOK_SECRETS into ACTIVE signing secrets (NEWLINE-separated; ASCII-trimmed, empties dropped)
// — sign with EACH / verify against ANY for zero-downtime ROTATION. UNSET falls back to the demo default; a present-but-
// BLANK value resolves to NO active secret -> deny (never the placeholder). The trim is the ASCII whitespace bytes ONLY
// (NOT strings.TrimSpace's unicode.IsSpace set): a stdlib trim DIVERGES ×3 (JS .trim() strips U+FEFF/BOM, py/go strip
// U+0085/NEL), so a contaminated secret would key to a different HMAC per runtime — ASCII-only is byte-identical ×3.
func whActiveSecrets() []string {
	raw, ok := os.LookupEnv("WEBHOOK_SECRETS")
	if !ok {
		raw = core.EnvOr("WEBHOOK_SECRETS", "whsec_demo_change_me") // UNSET -> demo default (the literal stays behind EnvOr)
	}
	out := []string{}
	for _, p := range strings.Split(raw, "\n") {
		if p = strings.Trim(p, " \t\r\n\v\f"); p != "" { // ASCII whitespace ONLY (identical ×3)
			out = append(out, p)
		}
	}
	return out
}

var whSecrets = whActiveSecrets()

type whMessage struct {
	Id        string `json:"id"`
	Timestamp int64  `json:"timestamp"`
	Payload   string `json:"payload"`
}

type whSeenRec struct {
	Id string `json:"id"`
	Ts int64  `json:"ts"`
}

var whSent = core.NewKV[string, whMessage]("webhooks_sent")
var whSeen = core.NewKV[string, whSeenRec]("webhooks_seen") // the inbound replay-dedup set (durable-forever; no reaper)

func WebhookSend(w http.ResponseWriter, r *http.Request) {
	// ADMIN-ONLY: authn -> authz FIRST (query-param POST, no body to drain), so a no-token caller is 401 and a
	// non-admin is 403 BEFORE the payload check — never the "payload required" 422, identical ×3 with python/node.
	if _, ok := core.RequireAdmin(w, r); !ok {
		return
	}
	payload := r.URL.Query().Get("payload")
	if payload == "" {
		core.WriteProblem(w, 422, "payload required")
		return
	}
	timestamp := core.TestNow(r)
	id := fmt.Sprintf("msg_%d", core.NextID("webhooks_msg"))
	whSent.Set(id, whMessage{Id: id, Timestamp: timestamp, Payload: payload})
	sigs := make([]string, len(whSecrets)) // sign with ALL active secrets (rotation): a receiver on any active secret accepts
	for i, s := range whSecrets {
		sigs[i] = signing.SignV1(s, id, timestamp, payload)
	}
	core.WriteJSON(w, 201, map[string]any{
		"id": id, "timestamp": timestamp, "payload": payload, "signature": strings.Join(sigs, " "),
	})
}

func WebhookVerify(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: public — INTENTIONALLY unauthenticated (a stateless + dedup HMAC check; no session caller). The
	// PUBLIC {valid} shape leaks no reason (a reason-oracle is a signing oracle — SW spec). The dedup WRITE is BEHIND
	// the signature gate (only a validly-signed event reaches it), so a no-secret caller cannot pump the seen-set.
	in, ok := core.DecodeJSON[struct {
		Id        *string `json:"id"`
		Timestamp *int64  `json:"timestamp"`
		Payload   *string `json:"payload"`
		Signature *string `json:"signature"`
	}](w, r)
	if !ok {
		return
	}
	if in.Id == nil || in.Timestamp == nil || in.Payload == nil || in.Signature == nil ||
		*in.Timestamp > core.MaxSafeInt || *in.Timestamp < -core.MaxSafeInt { // ts bounded to the ×3-safe range
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	now := core.TestNow(r)
	verified := false
	for _, secret := range whSecrets { // multi-secret: accept if ANY active secret verifies (rotation)
		if signing.VerifyV1(secret, *in.Id, *in.Timestamp, *in.Payload, *in.Signature, now, whTolerance) {
			verified = true
			break
		}
	}
	if !verified {
		core.WriteJSON(w, 200, map[string]bool{"valid": false, "duplicate": false}) // forged/stale -> nothing to dedup
		return
	}
	// INBOUND REPLAY-DEDUP, scoped to the EVENT IDENTITY (route + event id) — NOT which secret matched. The matched
	// secret is CALLER-CONTROLLABLE: a sender broadcasts one candidate per active secret, so presenting only another
	// secret's candidate would flip a per-secret slot and replay the SAME event as new during a rotation. Any active
	// secret authenticates the same event, so the secret has no role in the dedup key. Fast-path a lockless Get; reserve
	// the write lock (Do) for a genuinely-new id; Do re-checks atomically (a concurrent first-race -> exactly one writer).
	slot := digest.ScopedKey(whVerifyRoute, "wh", *in.Id)
	if _, seen := whSeen.Get(slot); seen {
		core.WriteJSON(w, 200, map[string]bool{"valid": true, "duplicate": true})
		return
	}
	duplicate := false
	whSeen.Do(slot, func(cur whSeenRec, exists bool) (whSeenRec, bool) {
		if exists {
			duplicate = true // a concurrent first won the claim -> THIS request is the duplicate
			return cur, false
		}
		return whSeenRec{Id: *in.Id, Ts: *in.Timestamp}, true // claim it (first delivery)
	})
	core.WriteJSON(w, 200, map[string]bool{"valid": true, "duplicate": duplicate})
}
