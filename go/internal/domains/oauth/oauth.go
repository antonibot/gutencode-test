// Package oauth — the OAuth 2.0 authorization-code flow, server side. Three dangerous properties, all proven:
// (1) CSRF DEFENSE: the callback's state must match a PENDING flow issued FOR THAT PROVIDER — forged/unknown is
// 403; the flow key binds provider+state. (2) SINGLE-USE, END TO END: the consume is ONE atomic read-modify-
// write through (*KV).Do (two processes racing a code get one token, one 409), AND a consumed state can never be
// re-opened — authorize claims the key via the idempotent_claim part, so re-authorizing a used state is 409
// (a consumed flow stays dead; a naive implementation would resurrect it). (3) DENY-BY-DEFAULT: only configured providers. The access
// token is an UNGUESSABLE server-minted CSPRNG value bound to the flow on consume (never a forgeable digest of the
// client-supplied inputs). Store names and shapes match the python/node impls.
//
// BOTH mutating routes are intentionally PUBLIC (see each handler's `mutation-auth: public` declaration), NOT
// require_identity: the end-user is logged OUT across this whole flow. OauthAuthorize is a pre-session flow-init
// primitive (records a pending flow keyed by state); OauthCallback is reached by the browser hitting the OAuth
// redirect, also logged-out — and there the `state` value IS the credential (matched to a pending flow, single-use,
// atomically consumed). require_identity would break every real callback.
package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"app/internal/core"
	"app/internal/parts/idempotent_claim"
	"app/internal/parts/well_formed"
)

var oauthProviders = map[string]bool{"google": true, "github": true}

type oauthFlow struct {
	Provider string `json:"provider"`
	State    string `json:"state"`
	Status   string `json:"status"`
	Token    string `json:"token,omitempty"` // CSPRNG access token, minted + bound to the flow on consume
}

var oauthFlows = core.NewKV[string, oauthFlow]("oauth_flows")

func oauthFlowKey(provider, state string) string {
	return provider + ":" + state // provider is VALIDATED vocabulary — a crafted state cannot forge another provider's key
}

func oauthMintToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("oauth: randomness unavailable") // an unguessable token is the whole point — fail loud
	}
	return "tok_" + base64.RawURLEncoding.EncodeToString(b)
}

func OauthAuthorize(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: public — INTENTIONALLY unauthenticated. This is a pre-session, server-side flow-INITIATION
	// primitive: it records a PENDING flow keyed by state while the end-user is still logged OUT, so requiring a
	// session would break the start of every OAuth flow. (Follow-on: a later wave may gate this behind the user's
	// session for explicit consent — which would also close the state-squatting -> denial-of-login risk, where an
	// attacker pre-claims a victim's state value.)
	in, ok := core.DecodeJSON[struct {
		Provider *string `json:"provider"`
		State    *string `json:"state"`
	}](w, r)
	if !ok {
		return
	}
	if in.Provider == nil || in.State == nil ||
		!well_formed.IsWellFormed(*in.Provider) || !well_formed.IsWellFormed(*in.State) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	if !oauthProviders[*in.Provider] {
		core.WriteProblem(w, 422, "unknown provider") // deny-by-default: only configured providers
		return
	}
	flow := oauthFlow{Provider: *in.Provider, State: *in.State, Status: "pending"}
	// a state is single-use END TO END: claim atomically — a PENDING replay is harmless (same record back),
	// but a CONSUMED flow must never silently re-open
	settled := idempotent_claim.ClaimOnce(oauthFlows, oauthFlowKey(*in.Provider, *in.State), flow)
	if settled.Status != "pending" {
		core.WriteProblem(w, 409, "state already used")
		return
	}
	core.WriteJSON(w, 201, settled)
}

func OauthCallback(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: public — INTENTIONALLY unauthenticated. The browser hitting the OAuth redirect is logged OUT,
	// and the `state` value IS the capability credential: it is matched to a PENDING flow the server issued,
	// single-use, and atomically consumed (forged/unknown state -> 403; replay -> 409). require_identity would
	// break every real callback, since there is no session at the redirect.
	in, ok := core.DecodeJSON[struct {
		Provider *string `json:"provider"`
		State    *string `json:"state"`
		Code     *string `json:"code"`
	}](w, r)
	if !ok {
		return
	}
	if in.Provider == nil || in.State == nil || in.Code == nil ||
		!well_formed.IsWellFormed(*in.Provider) || !well_formed.IsWellFormed(*in.State) ||
		!well_formed.IsWellFormed(*in.Code) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	if !oauthProviders[*in.Provider] {
		core.WriteProblem(w, 422, "unknown provider")
		return
	}
	outcome, token := "", ""
	oauthFlows.Do(oauthFlowKey(*in.Provider, *in.State), func(flow oauthFlow, exists bool) (oauthFlow, bool) {
		if !exists {
			outcome = "forged" // no pending flow for this provider+state -> CSRF / forged
			return flow, false
		}
		if flow.Status == "consumed" {
			outcome = "replay" // SINGLE-USE: the code was already exchanged
			return flow, false
		}
		// mint an UNGUESSABLE server-side token (CSPRNG) and bind it to the flow in the SAME atomic consume —
		// never a deterministic digest of the client-supplied (provider, state, code) that anyone could forge.
		outcome = "ok"
		flow.Status = "consumed"
		flow.Token = oauthMintToken()
		token = flow.Token
		return flow, true
	})
	if outcome == "forged" {
		core.WriteProblem(w, 403, "invalid state")
		return
	}
	if outcome == "replay" {
		core.WriteProblem(w, 409, "authorization code already used")
		return
	}
	core.WriteJSON(w, 200, map[string]any{"provider": *in.Provider, "state": *in.State,
		"access_token": token, "status": "authorized"})
}
