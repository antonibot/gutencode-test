// Package users — profiles + lifecycle, separate from auth credentials. (1) HANDLE UNIQUENESS: a handle is
// claimed exactly once via the idempotent_claim part — two processes racing the same handle create ONE user; a
// duplicate create is 409, never a silent overwrite. (2) MONOTONIC LIFECYCLE: deactivation is a terminal-value
// write — idempotent, race-convergent, never reversed. (3) IDENTITY: both mutations require the core
// RequireIdentity seam. CREATE is AUTHENTICATED-SELF (handle == caller, else 403 — closes handle-squatting):
// the precedence is PARSE -> AUTH -> SEMANTIC, identical ×3 — the body is decoded FIRST (only malformed JSON / a
// 413 fails here), THEN RequireIdentity (401), THEN the strict field validation (422), THEN the handle==caller
// authz (403); so a no-token caller with an otherwise-422 body that still decodes (e.g. {}) gets 401, never 422.
// DEACTIVATE is SELF-OR-ADMIN (path-only) — RequireIdentity FIRST (401), THEN the self-or-admin authz (403,
// before the path-422/404), exactly like the rbac admin pattern. (4) AUTHENTICATED READ: GET /{handle}
// requires a valid session (401 first, before the path-422/404) — visible to logged-in callers, not the anonymous
// public. Store names and shapes match python/node; durable.
package users

import (
	"net/http"

	"app/internal/core"
	"app/internal/parts/idempotent_claim"
	"app/internal/parts/well_formed"
)

type usersProfile struct {
	Id          int    `json:"id"`
	Handle      string `json:"handle"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
}

var usersProfiles = core.NewKV[string, usersProfile]("users_profiles")

func UsersCreate(w http.ResponseWriter, r *http.Request) {
	// PARSE: decode the body FIRST (enforces the 413 cap + drains the stream; only malformed JSON fails here) —
	// field-level checks are SEMANTIC and run AFTER auth, exactly like python's pydantic, so a no-token ill-shaped
	// (but still-decodable) body is 401, never a 422 that leaks the body shape. (×3 parity)
	in, ok := core.DecodeJSON[struct {
		Handle      *string `json:"handle"`
		DisplayName *string `json:"display_name"`
	}](w, r)
	if !ok {
		return
	}
	caller, ok := core.RequireIdentity(w, r) // AUTH (401), before any semantic validation
	if !ok {
		return
	}
	if in.Handle == nil || !well_formed.IsWellFormed(*in.Handle) || in.DisplayName == nil || *in.DisplayName == "" {
		core.WriteProblem(w, 422, "invalid body") // SEMANTIC field validation, after auth (mirrors python order)
		return
	}
	if *in.Handle != caller {
		core.WriteProblem(w, 403, "you may only create your own handle") // AUTHENTICATED-SELF: closes handle-squatting
		return
	}
	if _, taken := usersProfiles.Get(*in.Handle); taken {
		core.WriteProblem(w, 409, "handle taken") // fast path: a settled handle never mints (ids stay contiguous)
		return
	}
	// mint BEFORE the claim (a race loser's id is a gap), then claim the handle atomically — exactly one winner
	rec := usersProfile{Id: core.NextID("users_user"), Handle: *in.Handle,
		DisplayName: *in.DisplayName, Status: "active"}
	settled := idempotent_claim.ClaimOnce(usersProfiles, *in.Handle, rec)
	if settled.Id != rec.Id {
		core.WriteProblem(w, 409, "handle taken") // the handle has an owner — never silently overwrite
		return
	}
	core.WriteJSON(w, 201, settled)
}

func usersLookup(w http.ResponseWriter, r *http.Request) (usersProfile, bool) {
	handle := r.PathValue("handle")
	if !well_formed.IsWellFormed(handle) {
		core.WriteProblem(w, 422, "the handle must be non-empty with no control characters")
		return usersProfile{}, false
	}
	user, exists := usersProfiles.Get(handle)
	if !exists {
		core.WriteProblem(w, 404, "user not found")
		return usersProfile{}, false
	}
	return user, true
}

func UsersGet(w http.ResponseWriter, r *http.Request) {
	// AUTHENTICATED READ: visible to any logged-in caller (RequireIdentity 401 first, before the path-422/404),
	// not the anonymous public; any authenticated caller may look up any handle. Returns only public fields.
	if _, ok := core.RequireIdentity(w, r); !ok {
		return
	}
	if user, ok := usersLookup(w, r); ok {
		core.WriteJSON(w, 200, user)
	}
}

func UsersDeactivate(w http.ResponseWriter, r *http.Request) {
	caller, ok := core.RequireIdentity(w, r) // AUTH first (path-only: 401 before path-422/404), ×3
	if !ok {
		return
	}
	handle := r.PathValue("handle")
	// SELF-OR-ADMIN: the account owner OR a core admin may deactivate; anyone else is 403, resolved BEFORE the
	// well-formed/404 path checks (authn -> authz -> path/semantic), exactly as the rbac admin pattern orders it.
	if caller != handle && !core.IsAdmin(caller) {
		core.WriteProblem(w, 403, "you may only deactivate your own account")
		return
	}
	user, ok := usersLookup(w, r)
	if !ok {
		return
	}
	// monotonic + idempotent: "deactivated" is TERMINAL — concurrent calls converge, nothing reactivates
	user.Status = "deactivated"
	usersProfiles.Set(user.Handle, user)
	core.WriteJSON(w, 200, user)
}
