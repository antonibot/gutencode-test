// Package rbac — access control, deny-by-default (OWASP ASVS V8 / NIST RBAC): RBAC (subject -> roles ->
// permissions, fixed policy, least-privilege union) + FLAT ACL relation tuples (exact (subject,relation,object)
// match; no wildcard/hierarchy/userset-rewrite — a documented divergence; NIST Core/Flat RBAC is a valid level).
// Every route is deny-by-default authenticated (401). DECISION reads (/can,/check) are CALLER-SCOPED. MUTATIONS
// (/roles,/relations) are ADMIN-GATED (ARBAC — caller must hold the 'admin' role; prod bootstrap is out-of-band,
// the only auto-admin is the test seam, inert in prod) so no caller self-escalates. The grantee/relation/object
// stay free identifiers (well_formed key-forgery wall on \x1f). Atomic via Do; identical ×3, restart-durable.
package rbac

import (
	"net/http"
	"os"
	"strconv"
	"strings"

	"app/internal/core"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

// the role policy is POLICY (fixed, code-reviewed), not per-request state — so it stays a constant.
var rbacRolePerms = map[string][]string{
	"admin":  {"read", "write", "delete"},
	"editor": {"read", "write"},
	"viewer": {"read"},
}

// the relation tuple stored AS the value (self-describing) so listing can filter via All(); the composite key
// still guarantees one row per exact tuple, and the existence check (Get's ok bool) is unchanged.
type rbacTuple struct {
	Subject  string `json:"subject"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// durable state: subject -> assigned roles, and "subject\x1frelation\x1fobject" -> the tuple (one row per tuple).
var (
	rbacRoles = core.NewKV[string, []string]("rbac_roles")
	rbacRel   = core.NewKV[string, rbacTuple]("rbac_rel")
)

// the decision-audit record (Path-2, domain-local — the authz component owns its own log).
type rbacDecision struct {
	Id      int    `json:"id"`
	Subject string `json:"subject"`
	Kind    string `json:"kind"`
	Action  string `json:"action"`
	Object  string `json:"object"`
	Result  string `json:"result"`
	Reason  string `json:"reason"`
	Ts      int64  `json:"ts"`
}

var rbacDecisions = core.NewKV[string, rbacDecision]("rbac_decisions")

// rbacAudit appends a decision record. APP_RBAC_AUDIT: "off" | "deny" (default — log denials, the ASVS 16.3.2 L2
// MUST) | "all". Append-only, ordered by a monotonic id, ts via the clock seam. Mutations are not audited here.
func rbacAudit(r *http.Request, subject, kind, action, object, result, reason string) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("APP_RBAC_AUDIT")))
	if mode != "off" && mode != "all" { // unknown / empty / typo -> fail SAFE to the documented "deny" default
		mode = "deny"
	}
	if mode == "off" || (mode == "deny" && result != "deny") {
		return
	}
	id := core.NextID("rbac_decision")
	rbacDecisions.Set(strconv.Itoa(id), rbacDecision{Id: id, Subject: subject, Kind: kind, Action: action,
		Object: object, Result: result, Reason: reason, Ts: core.TestNow(r)})
}

func rbacRelKey(subject, relation, object string) string {
	return strings.Join([]string{subject, relation, object}, "\x1f") // unit separator joins the tuple into ONE exact key
}

// the CENTRAL identifier rule (well_formed part): non-empty, no control characters. For rbac this is also key
// forgery protection — the unit separator is the tuple-key delimiter, so a name carrying it could forge the key
// of a DIFFERENT tuple. Rejected at the door, identically in all three languages.
func rbacWellFormed(values ...string) bool {
	for _, v := range values {
		if !well_formed.IsWellFormed(v) {
			return false
		}
	}
	return true
}

// the ADMIN check is the CORE seam (core.IsAdmin): rbac is the management SURFACE that WRITES roles, core owns the
// cross-cutting NOTION (it reads rbac_roles) so non-rbac admin-only domains gate WITHOUT importing rbac (the
// boundary rule: domains -> core only). The ARBAC rule, the out-of-band prod bootstrap, and the inert test admin
// all live there — ONE definition for the whole app.

func RbacAssign(w http.ResponseWriter, r *http.Request) {
	caller, ok := core.RequireIdentity(w, r) // authn -> authz -> validation: auth+admin BEFORE decode (×3)
	if !ok {
		return
	}
	if !core.IsAdmin(caller) { // ARBAC: only an admin may assign roles (a non-admin can't self-escalate)
		rbacAudit(r, caller, "assign", "", "", "deny", "not-admin") // audit the denied attempt (ASVS L2)
		core.WriteProblem(w, 403, "rbac administration requires the admin role")
		return
	}
	in, ok := core.DecodeJSON[struct {
		Subject *string `json:"subject"`
		Role    *string `json:"role"`
	}](w, r)
	if !ok {
		return
	}
	if in.Subject == nil || in.Role == nil || !rbacWellFormed(*in.Subject, *in.Role) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	if _, known := rbacRolePerms[*in.Role]; !known {
		rbacAudit(r, caller, "assign", *in.Role, *in.Subject, "deny", "unknown-role")
		core.WriteJSON(w, 201, map[string]any{"allowed": false}) // unknown role -> deny, loudly (never silently grant)
		return
	}
	// ATOMIC append via the Do seam (a bare Get-then-Set RACES); the callback is pure + idempotent (re-assigning
	// the same role returns write=false).
	rbacRoles.Do(*in.Subject, func(cur []string, exists bool) ([]string, bool) {
		// unbounded-safe: a subject's role list is DEDUP'D (the loop below no-ops a duplicate) to a FINITE, CLOSED role
		// vocabulary (named privileges from a small fixed set, not free-form), so it can never grow unbounded — no
		// ring-buffer needed.
		for _, role := range cur {
			if role == *in.Role {
				return cur, false // already present -> no write
			}
		}
		return append(cur, *in.Role), true
	})
	rbacAudit(r, caller, "assign", *in.Role, *in.Subject, "grant", "ok") // admin-event trail (all mode)
	core.WriteJSON(w, 201, map[string]any{"allowed": true})
}

func RbacCan(w http.ResponseWriter, r *http.Request) {
	caller, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	permission := r.URL.Query().Get("permission")
	if !rbacWellFormed(permission) {
		core.WriteProblem(w, 422, "permission is required")
		return
	}
	// caller-scoped + deny-by-default: allowed iff some role ASSIGNED TO THE CALLER grants the permission
	roles, _ := rbacRoles.Get(caller)
	allowed := false
	for _, role := range roles {
		for _, perm := range rbacRolePerms[role] {
			if perm == permission {
				allowed = true
			}
		}
	}
	res, reason := "deny", "deny-by-default"
	if allowed {
		res, reason = "allow", "role-union"
	}
	rbacAudit(r, caller, "can", permission, "", res, reason)
	core.WriteJSON(w, 200, map[string]any{"allowed": allowed})
}

func RbacGrant(w http.ResponseWriter, r *http.Request) {
	caller, ok := core.RequireIdentity(w, r) // authn -> authz -> validation: auth+admin BEFORE decode (×3)
	if !ok {
		return
	}
	if !core.IsAdmin(caller) { // ARBAC: only an admin may write relation tuples
		rbacAudit(r, caller, "grant", "", "", "deny", "not-admin") // audit the denied attempt (ASVS L2)
		core.WriteProblem(w, 403, "rbac administration requires the admin role")
		return
	}
	in, ok := core.DecodeJSON[struct {
		Subject  *string `json:"subject"`
		Relation *string `json:"relation"`
		Object   *string `json:"object"`
	}](w, r)
	if !ok {
		return
	}
	if in.Subject == nil || in.Relation == nil || in.Object == nil ||
		!rbacWellFormed(*in.Subject, *in.Relation, *in.Object) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	rbacRel.Set(rbacRelKey(*in.Subject, *in.Relation, *in.Object),
		rbacTuple{Subject: *in.Subject, Relation: *in.Relation, Object: *in.Object})
	rbacAudit(r, caller, "grant", *in.Relation, *in.Subject, "grant", "ok") // admin-event trail (all mode)
	core.WriteJSON(w, 201, map[string]any{"allowed": true})
}

func RbacCheck(w http.ResponseWriter, r *http.Request) {
	caller, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	relation, object := q.Get("relation"), q.Get("object")
	if !rbacWellFormed(relation, object) {
		core.WriteProblem(w, 422, "relation and object are required")
		return
	}
	// caller-scoped + deny-by-default: the EXACT (caller, relation, object) tuple must exist (no wildcard/prefix)
	_, found := rbacRel.Get(rbacRelKey(caller, relation, object))
	res, reason := "deny", "deny-by-default"
	if found {
		res, reason = "allow", "tuple-match"
	}
	rbacAudit(r, caller, "check", relation, object, res, reason)
	core.WriteJSON(w, 200, map[string]any{"allowed": found})
}

func RbacRevokeRole(w http.ResponseWriter, r *http.Request) {
	caller, ok := core.RequireIdentity(w, r) // authn -> authz -> validation: auth+admin BEFORE decode (×3)
	if !ok {
		return
	}
	if !core.IsAdmin(caller) { // ARBAC: only an admin may revoke
		rbacAudit(r, caller, "revoke-role", "", "", "deny", "not-admin") // audit the denied attempt (ASVS L2)
		core.WriteProblem(w, 403, "rbac administration requires the admin role")
		return
	}
	in, ok := core.DecodeJSON[struct {
		Subject *string `json:"subject"`
		Role    *string `json:"role"`
	}](w, r)
	if !ok {
		return
	}
	if in.Subject == nil || in.Role == nil || !rbacWellFormed(*in.Subject, *in.Role) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	// ATOMIC remove via the Do seam; idempotent — removing an absent role is a no-op that returns removed:false.
	removed := false
	rbacRoles.Do(*in.Subject, func(cur []string, exists bool) ([]string, bool) {
		next := make([]string, 0, len(cur))
		for _, role := range cur {
			if role == *in.Role {
				removed = true
			} else {
				next = append(next, role)
			}
		}
		return next, removed // write the filtered slice only when something was removed
	})
	rbacAudit(r, caller, "revoke-role", *in.Role, *in.Subject, "revoke", "ok") // admin-event trail (all mode)
	core.WriteJSON(w, 200, map[string]any{"removed": removed})
}

func RbacRevokeRelation(w http.ResponseWriter, r *http.Request) {
	caller, ok := core.RequireIdentity(w, r) // authn -> authz -> validation: auth+admin BEFORE decode (×3)
	if !ok {
		return
	}
	if !core.IsAdmin(caller) { // ARBAC: only an admin may revoke a relation tuple
		rbacAudit(r, caller, "revoke-relation", "", "", "deny", "not-admin") // audit the denied attempt (ASVS L2)
		core.WriteProblem(w, 403, "rbac administration requires the admin role")
		return
	}
	in, ok := core.DecodeJSON[struct {
		Subject  *string `json:"subject"`
		Relation *string `json:"relation"`
		Object   *string `json:"object"`
	}](w, r)
	if !ok {
		return
	}
	if in.Subject == nil || in.Relation == nil || in.Object == nil ||
		!rbacWellFormed(*in.Subject, *in.Relation, *in.Object) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	key := rbacRelKey(*in.Subject, *in.Relation, *in.Object)
	_, existed := rbacRel.Get(key) // best-effort was-present signal
	rbacRel.Delete(key)            // idempotent: no-op if the tuple is absent
	rbacAudit(r, caller, "revoke-relation", *in.Relation, *in.Subject, "revoke", "ok") // admin-event trail (all mode)
	core.WriteJSON(w, 200, map[string]any{"removed": existed})
}

func RbacListRoles(w http.ResponseWriter, r *http.Request) {
	caller, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	target := q.Get("subject")
	if target == "" {
		target = caller // default to the caller's own roles
	}
	if target != caller && !core.IsAdmin(caller) { // listing another subject's roles is an admin op
		rbacAudit(r, caller, "list-roles", "", "", "deny", "not-admin") // ASVS L2 — audit the denied list attempt
		core.WriteProblem(w, 403, "rbac administration requires the admin role")
		return
	}
	if !rbacWellFormed(target) {
		core.WriteProblem(w, 422, "subject is required")
		return
	}
	roles, _ := rbacRoles.Get(target)
	page, next, valid := paginate.Paginate(roles, q.Get("cursor"), q.Get("limit"))
	if !valid {
		core.WriteProblem(w, 422, "invalid cursor or limit")
		return
	}
	var nc any
	if next != "" {
		nc = next
	}
	core.WriteJSON(w, 200, map[string]any{"results": page, "next_cursor": nc})
}

func RbacListRelations(w http.ResponseWriter, r *http.Request) {
	caller, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	subject, object := q.Get("subject"), q.Get("object")
	// a caller may list THEIR OWN forward tuples; another subject's tuples or the inverse (object=) is an admin op.
	selfOK := subject != "" && subject == caller && object == ""
	if !selfOK && !core.IsAdmin(caller) {
		rbacAudit(r, caller, "list-relations", "", "", "deny", "not-admin") // ASVS L2 — audit the denied list attempt
		core.WriteProblem(w, 403, "rbac administration requires the admin role")
		return
	}
	if subject != "" && !rbacWellFormed(subject) {
		core.WriteProblem(w, 422, "invalid subject")
		return
	}
	if object != "" && !rbacWellFormed(object) {
		core.WriteProblem(w, 422, "invalid object")
		return
	}
	if subject == "" && object == "" {
		core.WriteProblem(w, 422, "a subject or object filter is required") // never an unbounded full dump
		return
	}
	filtered := []rbacTuple{}
	for _, t := range rbacRel.All() { // rowid-stable order, identical ×3
		if (subject == "" || t.Subject == subject) && (object == "" || t.Object == object) {
			filtered = append(filtered, t)
		}
	}
	page, next, valid := paginate.Paginate(filtered, q.Get("cursor"), q.Get("limit"))
	if !valid {
		core.WriteProblem(w, 422, "invalid cursor or limit")
		return
	}
	var nc any
	if next != "" {
		nc = next
	}
	core.WriteJSON(w, 200, map[string]any{"results": page, "next_cursor": nc})
}

func RbacListDecisions(w http.ResponseWriter, r *http.Request) {
	caller, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if !core.IsAdmin(caller) { // the decision log is admin-only (it reveals every subject's decisions)
		rbacAudit(r, caller, "list-decisions", "", "", "deny", "not-admin") // ASVS L2 — audit the denied list attempt
		core.WriteProblem(w, 403, "rbac administration requires the admin role")
		return
	}
	q := r.URL.Query()
	subject := q.Get("subject")
	if subject != "" && !rbacWellFormed(subject) {
		core.WriteProblem(w, 422, "invalid subject")
		return
	}
	rows := []rbacDecision{}
	for _, d := range rbacDecisions.All() { // rowid order == monotonic id order, stable
		if subject == "" || d.Subject == subject {
			rows = append(rows, d)
		}
	}
	page, next, valid := paginate.Paginate(rows, q.Get("cursor"), q.Get("limit"))
	if !valid {
		core.WriteProblem(w, 422, "invalid cursor or limit")
		return
	}
	var nc any
	if next != "" {
		nc = next
	}
	core.WriteJSON(w, 200, map[string]any{"results": page, "next_cursor": nc})
}
