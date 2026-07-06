// orgs listing + self-leave (R2/R3) — the paginated reads (list-my-orgs, the member roster, pending invitations) and
// self-leave. Same package as orgs.go: it shares the orgs structs/constants/helpers (orgsManager, orgsAuthLoad,
// orgsMemberScoped, orgsMembers, orgsRecords, orgsAudit). Every collection read routes through the bounded paginate
// seam IN-HANDLER. Parity-exact with python/node.
package orgs

import (
	"net/http"
	"os"
	"strconv"
	"strings"

	"app/internal/core"
	"app/internal/parts/env_int"
	"app/internal/parts/paginate"
)

// ── the domain-local decision-audit infrastructure (shared by every orgs.go handler; here to keep orgs.go ≤ 400 LOC) ──
// the domain-local decision log (Path-2: the authz surface owns its own trail).
type orgsDecision struct {
	Id      int    `json:"id"`
	Subject string `json:"subject"`
	Kind    string `json:"kind"`
	Target  string `json:"target"`
	Org     string `json:"org"`
	Result  string `json:"result"`
	Reason  string `json:"reason"`
	Ts      int64  `json:"ts"`
}

var orgsDecisions = core.NewKV[string, orgsDecision]("orgs_decisions")

// orgsDenyAuditBudget — how many DENY rows one subject may append per window before the audit-write becomes a no-op
// (the deny-audit flood wall): generous so a real attack leaves a forensic trail while an attacker can no longer
// pump orgs_decisions unbounded. Env-tunable; floored at 1.
func orgsDenyAuditBudget() (int, int64) {
	return env_int.EnvInt(os.Getenv("ORGS_DENY_AUDIT_LIMIT"), 50, 1), int64(env_int.EnvInt(os.Getenv("ORGS_DENY_AUDIT_WINDOW"), 3600, 1))
}

// orgsAudit appends a decision record. APP_ORGS_AUDIT: "off" | "deny" (DEFAULT — every authz DENIAL + successful ownership/membership MUTATION: ASVS 7.1.3/7.2.2) | "all". Append-only, monotonic id; ts via the clock seam.
func orgsAudit(r *http.Request, subject, kind, target, org, result, reason string) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("APP_ORGS_AUDIT")))
	if mode != "off" && mode != "all" {
		mode = "deny" // unknown / empty / typo -> fail SAFE to the documented "deny" default
	}
	if mode == "off" {
		return
	}
	now := core.TestNow(r)
	if result == "deny" {
		// THROTTLE the DENY-audit write per (ORG, subject) (deny-audit flood + cross-org isolation): the key includes the
		// ORG (\x1f-joined, un-forgeable) so noise an attacker generates on a DECOY org can NOT blind a VICTIM org's
		// trail — each org keeps its own first-N forensic denials. The deny-audit CALL still precedes the 403 in the
		// source (the denial audit still fires) — a RUNTIME budget INSIDE orgsAudit. Success audits are NEVER throttled.
		limit, window := orgsDenyAuditBudget()
		if !core.Throttle("orgs:deny-audit:"+org+"\x1f"+subject, limit, window, now) {
			return // over budget for this (org, subject) in the window -> no-op (bounded growth)
		}
	}
	id := core.NextID("orgs_decision")
	orgsDecisions.Set(strconv.Itoa(id), orgsDecision{Id: id, Subject: subject, Kind: kind, Target: target,
		Org: org, Result: result, Reason: reason, Ts: now})
}

// orgsNextCursor marshals an empty next-cursor as JSON null (parity with python None / node null).
func orgsNextCursor(next string) any {
	if next == "" {
		return nil
	}
	return next
}

// OrgsListMine — MY orgs: those the caller OWNS or is an ACTIVE member of. Authenticated (the authenticated-read wall); caller-scoped.
func OrgsListMine(w http.ResponseWriter, r *http.Request) {
	caller, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	mine := []orgsRecord{}
	for _, rec := range orgsRecords.All() { // rowid order, stable + identical ×3
		if role, _ := core.OrgRole(rec.Slug, caller); rec.Owner == caller || role != "" {
			mine = append(mine, rec)
		}
	}
	page, next, valid := paginate.Paginate(mine, r.URL.Query().Get("cursor"), r.URL.Query().Get("limit"))
	if !valid {
		core.WriteProblem(w, 422, "invalid cursor or limit")
		return
	}
	core.WriteJSON(w, 200, map[string]any{"results": page, "next_cursor": orgsNextCursor(next)})
}

// OrgsListMembers — MEMBER-SCOPED roster (non-member 404 byte-identical to a missing slug, like OrgsGet) = the DERIVED
// owner (no membership row) + every ACTIVE member; PENDING invites NOT listed.
func OrgsListMembers(w http.ResponseWriter, r *http.Request) {
	org, _, ok := orgsMemberScoped(w, r)
	if !ok {
		return
	}
	roster := []map[string]any{{"handle": org.Owner, "role": orgsRoleOwner}}
	for _, m := range orgsMembers.All() {
		if m.Org == org.Slug && m.Status == orgsActive {
			roster = append(roster, map[string]any{"handle": m.Handle, "role": m.Role})
		}
	}
	page, next, valid := paginate.Paginate(roster, r.URL.Query().Get("cursor"), r.URL.Query().Get("limit"))
	if !valid {
		core.WriteProblem(w, 422, "invalid cursor or limit")
		return
	}
	core.WriteJSON(w, 200, map[string]any{"results": page, "next_cursor": orgsNextCursor(next)})
}

// OrgsListInvites — MANAGER-only (owner|admin): the PENDING invites (handle, role, invite_exp) ONLY — NEVER the secret.
func OrgsListInvites(w http.ResponseWriter, r *http.Request) {
	org, _, ok := orgsManager(w, r, orgsRoleOwner, orgsRoleAdmin)
	if !ok {
		return
	}
	invites := []map[string]any{}
	for _, m := range orgsMembers.All() {
		if m.Org == org.Slug && m.Status == orgsPending {
			invites = append(invites, map[string]any{"handle": m.Handle, "role": m.Role, "invite_exp": m.InviteExp})
		}
	}
	page, next, valid := paginate.Paginate(invites, r.URL.Query().Get("cursor"), r.URL.Query().Get("limit"))
	if !valid {
		core.WriteProblem(w, 422, "invalid cursor or limit")
		return
	}
	core.WriteJSON(w, 200, map[string]any{"results": page, "next_cursor": orgsNextCursor(next)})
}

// OrgsLeave — SELF-leave, MEMBER-SCOPED (authn -> load(404) -> ACTIVE membership). A NON-member (or already-left) is 404
// BYTE-IDENTICAL to a missing slug (no existence leak via 200/404; no no-op 'leave' audit firehose).
// The OWNER cannot leave (records-owner) -> 409 (never-ownerless, mirroring owner-not-removable; audited though 409 is exempt).
func OrgsLeave(w http.ResponseWriter, r *http.Request) {
	org, caller, ok := orgsAuthLoad(w, r)
	if !ok {
		return
	}
	if role, _ := core.OrgRole(org.Slug, caller); role == "" {
		core.WriteProblem(w, 404, "org not found") // not a member -> same 404 as a missing org (no existence leak, no no-op audit)
		return
	}
	if caller == org.Owner {
		orgsAudit(r, caller, "leave", caller, org.Slug, "deny", "owner-cannot-leave")
		core.WriteProblem(w, 409, "the owner cannot leave (transfer ownership first)")
		return
	}
	orgsMembers.Delete(orgsMemberKey(org.Slug, caller)) // only a real ACTIVE member reaches here
	orgsAudit(r, caller, "leave", caller, org.Slug, "leave", "ok")
	core.WriteJSON(w, 200, map[string]any{"slug": org.Slug, "handle": caller, "left": true})
}
