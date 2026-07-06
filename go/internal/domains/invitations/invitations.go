// Package invitations — invite + accept with single-use, expiring tokens. The dangerous property is
// ACCEPT-AT-MOST-ONCE-AND-NEVER-EXPIRED: the token is server-minted and unguessable; accepting is an atomic
// single-use consume through (*KV).Do (two processes racing one token yield one acceptance + one 409), and
// expiry beats availability — an expired token is 410 even if never used. The expiry comes from the test-clock
// seam. Tokens are durable. Store names and shapes match python/node.
//
// TWO routes, TWO auth models: InvitationsCreate requires identity (core.RequireIdentity) and STAMPS the
// inviter = the authenticated caller, derived from the bearer token and NEVER a client-supplied body field. The
// precedence is PARSE -> AUTH -> SEMANTIC, identical ×3: the body is decoded as raw JSON FIRST (drains the stream +
// 413/422), THEN auth runs, THEN strict per-field validation — so an unauthenticated ill-typed body is 401, never a
// 422 that leaks the body shape. InvitationsAccept is intentionally PUBLIC (see its `mutation-auth: public`
// declaration): the 192-bit single-use capability token IS the credential.
package invitations

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"app/internal/core"
	"app/internal/parts/env_int"
	"app/internal/parts/well_formed"
)

var invitationsTTL = int64(env_int.EnvInt(core.EnvOr("INVITATIONS_TTL", ""), 604800))

type invitationsRec struct {
	Token     string `json:"token"`
	Email     string `json:"email"`
	Inviter   string `json:"inviter"`
	Status    string `json:"status"`
	ExpiresAt int64  `json:"expires_at"`
}

var invitationsTokens = core.NewKV[string, invitationsRec]("invitations_tokens")

func InvitationsCreate(w http.ResponseWriter, r *http.Request) {
	// PARSE FIRST: DecodeJSON enforces the body cap (413) and drains the stream — replying (incl. a 401) before the
	// body is read aborts the connection mid-upload. Identity is checked NEXT, before any semantic validation, so an
	// unauthenticated ill-typed body is 401 (not a 422 that leaks the shape). Strict ttl check runs AFTER auth. (×3)
	in, ok := core.DecodeJSON[struct {
		Email *string         `json:"email"`
		Ttl   json.RawMessage `json:"ttl"`
	}](w, r)
	if !ok {
		return
	}
	inviter, ok := core.RequireIdentity(w, r) // authenticated mutation (no/invalid token -> 401), BEFORE validation
	if !ok {
		return
	}
	if in.Email == nil || !well_formed.IsWellFormed(*in.Email) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	ttl := invitationsTTL
	if in.Ttl != nil {
		v, valid := core.RequireIntRaw(in.Ttl) // STRICT: integer literal only — rejects "100"/100.5/true (×3 with python StrictInt)
		if !valid || v < 1 || v > 31536000 {
			core.WriteProblem(w, 422, "ttl must be an integer between 1 and 31536000")
			return
		}
		ttl = int64(v)
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		panic("invitations: randomness unavailable") // an unguessable token is the whole point — fail loud
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	// inviter derived from the token, never client-set — a smuggled `inviter` body field cannot override it.
	rec := invitationsRec{Token: token, Email: *in.Email, Inviter: inviter, Status: "pending", ExpiresAt: core.TestNow(r) + ttl}
	invitationsTokens.Set(token, rec)
	core.WriteJSON(w, 201, rec)
}

func InvitationsAccept(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: public — INTENTIONALLY unauthenticated. The 192-bit single-use capability token IS the
	// credential: accept consumes a token a recipient already holds (typically while logged OUT), so requiring a
	// session would break the invite flow. The token's secrecy + single-use/expiry are the authorization.
	token := r.PathValue("token")
	if !well_formed.IsWellFormed(token) {
		core.WriteProblem(w, 422, "the token must be non-empty with no control characters")
		return
	}
	now := core.TestNow(r)
	outcome := ""
	var accepted invitationsRec
	invitationsTokens.Do(token, func(rec invitationsRec, exists bool) (invitationsRec, bool) {
		if !exists {
			outcome = "unknown"
			return rec, false
		}
		if now > rec.ExpiresAt {
			outcome = "expired" // expiry beats availability — even a pending token is gone
			return rec, false
		}
		if rec.Status == "accepted" {
			outcome = "used"
			return rec, false
		}
		rec.Status = "accepted"
		accepted = rec
		outcome = "ok" // atomic single-use: the FIRST accept wins
		return rec, true
	})
	switch outcome {
	case "unknown":
		core.WriteProblem(w, 404, "invitation not found")
	case "expired":
		core.WriteProblem(w, 410, "invitation expired")
	case "used":
		core.WriteProblem(w, 409, "invitation already accepted")
	default:
		core.WriteJSON(w, 200, accepted)
	}
}
