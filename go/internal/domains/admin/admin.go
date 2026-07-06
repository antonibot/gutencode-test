// Package admin — the guarded admin surface. (1) DENY-BY-DEFAULT GUARD: every route requires a valid admin
// bearer token compared CONSTANT-TIME against the env-backed secret; a missing/wrong token is 401 and an
// unauthorized mutation records NOTHING. (2) APPEND-ONLY: authorized actions get a monotonic id; no update or
// delete route exists. Self-contained — no sibling-domain import. Matches python/node; durable. Ordering note:
// structural validation (422) runs before the auth guard (401), mirroring the python framework's param/body
// validation happening before the handler.
package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"app/internal/core"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

var adminToken = core.EnvOr("ADMIN_TOKEN", "admin_dev_token_change_me") // env-backed, rotatable

type adminAction struct {
	Id     int    `json:"id"`
	Action string `json:"action"`
	Target string `json:"target"`
}

var adminActions = core.NewKV[string, adminAction]("admin_actions")

// identity-exempt: a break-glass ADMIN token (constant-time vs the env ADMIN_TOKEN), NOT a user session — the
// header parse here IS the admin-secret check, by design. Wave B migrates this to RequireIdentity + an admin role.
// deny-by-default: a Bearer that does not constant-time-match the admin secret is rejected (same 401 for no
// header / wrong scheme / wrong token — non-enumerable). Compare FIXED-LENGTH sha256 digests of both sides so the
// compare is length-independent too (no length leak — the length-safe CT compare, identical ×3 with python/node).
func adminAuthorized(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	token := ""
	if strings.HasPrefix(header, "Bearer ") {
		token = strings.TrimPrefix(header, "Bearer ")
	}
	a := sha256.Sum256([]byte(token))
	b := sha256.Sum256([]byte(adminToken))
	return hmac.Equal(a[:], b[:])
}

func AdminRecord(w http.ResponseWriter, r *http.Request) {
	in, ok := core.DecodeJSON[struct {
		Action *string `json:"action"`
		Target *string `json:"target"`
	}](w, r)
	if !ok {
		return
	}
	if in.Action == nil || !well_formed.IsWellFormed(*in.Action) || in.Target == nil || !well_formed.IsWellFormed(*in.Target) {
		core.WriteProblem(w, 422, "invalid body") // 422 before the guard (parity with the framework ordering)
		return
	}
	if !adminAuthorized(r) {
		core.WriteProblem(w, 401, "admin authorization required") // GUARD: never reaches the store unauthorized
		return
	}
	aid := core.NextID("admin_action")
	rec := adminAction{Id: aid, Action: *in.Action, Target: *in.Target}
	adminActions.Set(strconv.Itoa(aid), rec) // append-only
	core.WriteJSON(w, 201, rec)
}

func AdminList(w http.ResponseWriter, r *http.Request) {
	if !adminAuthorized(r) {
		core.WriteProblem(w, 401, "admin authorization required") // GUARD PRESERVED — the trail is admin-only
		return
	}
	// unscoped-read: admin — the action trail is GLOBAL by design (every action, not per-caller); the admin guard
	// above is the explicit privileged gate. No per-caller owner field — the whole trail is the resource.
	actions := []adminAction{}
	for _, a := range adminActions.All() {
		actions = append(actions, a)
	}
	sort.Slice(actions, func(i, j int) bool { return actions[i].Id < actions[j].Id }) // stable id order, identical ×3
	q := r.URL.Query()
	page, next, ok := paginate.Paginate(actions, q.Get("cursor"), q.Get("limit")) // bound the full admin-only list
	if !ok {
		core.WriteProblem(w, 422, "invalid cursor or limit")
		return
	}
	var nc any
	if next != "" {
		nc = next
	}
	core.WriteJSON(w, 200, map[string]any{"results": page, "next_cursor": nc})
}

func AdminGet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("action_id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid action id") // 422 before the guard (parity with the framework ordering)
		return
	}
	if !adminAuthorized(r) {
		core.WriteProblem(w, 401, "admin authorization required")
		return
	}
	rec, exists := adminActions.Get(strconv.Itoa(id))
	if !exists {
		core.WriteProblem(w, 404, "action not found")
		return
	}
	core.WriteJSON(w, 200, rec)
}
