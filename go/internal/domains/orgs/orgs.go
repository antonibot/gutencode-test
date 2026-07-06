// Package orgs — organizations / workspaces, the ownership root, with MULTI-MEMBER roles. The python docstring carries the
// FULL design; this Go header is the terse mirror (parity-exact); listing + self-leave are in listing.go. (1) SLUG UNIQUE
// via idempotent_claim (409). (2) NEVER OWNERLESS: owner STAMPED FROM THE TOKEN, EXACTLY ONE owner, transfer is the only
// move (old owner -> admin); archival monotonic; an owner can't be removed nor LEAVE (409). (3) ROLE-GOVERNED MEMBERSHIP,
// PENDING UNTIL ACCEPTED: org_role gates every op (add/remove/archive + list-invitations need owner|admin, transfer owner-
// only, non-member 403); add_member INVITES (a single-use token), the role conferred ONLY on ACCEPT. Reads are MEMBER/
// caller-scoped (non-member 404 == missing). IDENTITY: deny-by-default (401); authn -> not-found -> authz ->
// validation ×3 (the rbac pattern); orgs WRITES the membership store, core owns the NOTION (OrgRole reads it). ns "orgs_members"
// "<slug>\x1f<handle>" -> {org,handle,role,status}(+secret_hash,invite_exp); orgs_records {id,slug,owner,status}.
package orgs

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/env_int"
	"app/internal/parts/idempotent_claim"
	"app/internal/parts/well_formed"
)

type orgsRecord struct {
	Id     int    `json:"id"`
	Slug   string `json:"slug"`
	Owner  string `json:"owner"`
	Status string `json:"status"`
}

// orgsMember — the membership record (JSON keys MATCH python/node); a role is conferred ONLY when Status=="active".
type orgsMember struct {
	Org        string `json:"org"`
	Handle     string `json:"handle"`
	Role       string `json:"role"`
	Status     string `json:"status"`
	SecretHash string `json:"secret_hash,omitempty"`
	InviteExp  int64  `json:"invite_exp,omitempty"`
}

const (
	orgsRoleOwner  = "owner"
	orgsRoleAdmin  = "admin"
	orgsRoleMember = "member"
	orgsPending    = "pending" // an invite is PENDING until ACCEPTED
	orgsActive     = "active"  // only an ACTIVE member has a role (OrgRole returns it)
	orgsRemoved    = "removed" // a SOFT-delete tombstone: OrgRole grants only status=="active", so it is inert
)

var orgsRecords = core.NewKV[string, orgsRecord]("orgs_records")
var orgsMembers = core.NewKV[string, orgsMember]("orgs_members") // the store the core OrgRole seam reads (orgs WRITES it)

type orgsOutboxRec struct { // the delivery outbox "<slug>\x1f<handle>" -> the single-use invite token (drained by the email worker); orgs-private
	To    string `json:"to"`
	Kind  string `json:"kind"`
	Token string `json:"token"`
	Org   string `json:"org"`
}

var orgsOutbox = core.NewKV[string, orgsOutboxRec]("orgs_outbox")

func orgsMemberKey(slug, handle string) string { return slug + "\x1f" + handle } // \x1f un-forgeable (well_formed names)

func orgsRandURL(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func orgsInviteTTL() int64 {
	return int64(env_int.EnvInt(core.EnvOr("ORGS_INVITE_TTL_SECONDS", ""), 604800, 1)) // 7 days; floored at 1s
}

func orgsDeliverInvite(slug, handle, token string) { // token reaches the invitee, never the inviter; key is \x1f-joined (un-forgeable, NOT ':') so a "<victim>:<x>" owner can't clobber another org's delivery row
	orgsOutbox.Set(slug+"\x1f"+handle, orgsOutboxRec{To: handle, Kind: "org-invite", Token: token, Org: slug})
}

// orgsDecision / orgsAudit / orgsDenyAuditBudget / envInt live in listing.go (same package) to keep this file ≤ the
// 400-LOC budget — the decision-audit infrastructure is shared by every handler here.

func orgsManager(w http.ResponseWriter, r *http.Request, allowed ...string) (orgsRecord, string, bool) { // authz chokepoint: authn(401) -> slug-validate(422) -> load(404) -> org_role ∈ allowed(403), BEFORE body decode (×3 with _manage_dep)
	caller, ok := core.RequireIdentity(w, r)
	if !ok {
		return orgsRecord{}, "", false
	}
	slug := r.PathValue("slug")
	if !well_formed.IsWellFormed(slug) {
		core.WriteProblem(w, 422, "the slug must be non-empty with no control characters")
		return orgsRecord{}, "", false
	}
	org, exists := orgsRecords.Get(slug)
	if !exists {
		core.WriteProblem(w, 404, "org not found")
		return orgsRecord{}, "", false
	}
	role, _ := core.OrgRole(slug, caller)
	for _, a := range allowed {
		if role == a {
			return org, caller, true
		}
	}
	orgsAudit(r, caller, "manage", "", slug, "deny", "not-a-manager") // ASVS 7.1.3: log the failed authz
	core.WriteProblem(w, 403, "this operation requires an org owner or admin")
	return orgsRecord{}, "", false
}

func OrgsCreate(w http.ResponseWriter, r *http.Request) {
	in, ok := core.DecodeJSON[struct { // body-only POST: DecodeJSON FIRST (413+drains), THEN auth (no-token clean body -> 401), THEN validation. Owner = the TOKEN, not the body.
		Slug *string `json:"slug"`
	}](w, r)
	if !ok {
		return
	}
	caller, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if in.Slug == nil || !well_formed.IsWellFormed(*in.Slug) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	if _, taken := orgsRecords.Get(*in.Slug); taken {
		core.WriteProblem(w, 409, "slug taken") // fast path: a settled slug never mints
		return
	}
	rec := orgsRecord{Id: core.NextID("orgs_org"), Slug: *in.Slug, Owner: caller, Status: "active"}
	settled := idempotent_claim.ClaimOnce(orgsRecords, *in.Slug, rec)
	if settled.Id != rec.Id {
		core.WriteProblem(w, 409, "slug taken") // lost the race — never overwrite the winner
		return
	}
	orgsAudit(r, caller, "create", *in.Slug, *in.Slug, "create", "ok") // SINGLE-SOURCE: owner DERIVED from orgs_records.owner, NO 'owner' row (two owners impossible)
	core.WriteJSON(w, 201, settled)
}

func orgsLoad(w http.ResponseWriter, r *http.Request) (orgsRecord, bool) {
	slug := r.PathValue("slug")
	if !well_formed.IsWellFormed(slug) {
		core.WriteProblem(w, 422, "the slug must be non-empty with no control characters")
		return orgsRecord{}, false
	}
	org, exists := orgsRecords.Get(slug)
	if !exists {
		core.WriteProblem(w, 404, "org not found")
		return orgsRecord{}, false
	}
	return org, true
}

func orgsAuthLoad(w http.ResponseWriter, r *http.Request) (orgsRecord, string, bool) { // shared READ/leave prologue: authn(401) -> slug-validate+load(422/404)
	caller, ok := core.RequireIdentity(w, r)
	if !ok {
		return orgsRecord{}, "", false
	}
	org, ok := orgsLoad(w, r)
	if !ok {
		return orgsRecord{}, "", false
	}
	return org, caller, true
}

func orgsMemberScoped(w http.ResponseWriter, r *http.Request) (orgsRecord, string, bool) { // RequireIdentity + load + ACTIVE-membership wall; non-member 404 == missing. Shared by get + list-members.
	caller, ok := core.RequireIdentity(w, r)
	if !ok {
		return orgsRecord{}, "", false
	}
	org, ok := orgsLoad(w, r)
	if !ok {
		return orgsRecord{}, "", false
	}
	if role, _ := core.OrgRole(org.Slug, caller); role == "" {
		core.WriteProblem(w, 404, "org not found") // not a member -> same 404 as a missing org (existence never leaks)
		return orgsRecord{}, "", false
	}
	return org, caller, true
}

func OrgsGet(w http.ResponseWriter, r *http.Request) {
	org, _, ok := orgsMemberScoped(w, r)
	if !ok {
		return
	}
	core.WriteJSON(w, 200, org)
}

func OrgsTransfer(w http.ResponseWriter, r *http.Request) {
	org, caller, ok := orgsManager(w, r, orgsRoleOwner) // ONLY the current owner may transfer (authz before decode)
	if !ok {
		return
	}
	in, ok := core.DecodeJSON[struct {
		Owner *string `json:"owner"`
	}](w, r)
	if !ok {
		return
	}
	if in.Owner == nil || !well_formed.IsWellFormed(*in.Owner) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	// SINGLE-KEY ATOMIC Do() re-asserting the caller is STILL owner INSIDE the lock (orgsManager was pre-lock; the F1 two-owner race) -> loser 409.
	newOwner := *in.Owner
	var result orgsRecord
	transferred := false
	orgsRecords.Do(org.Slug, func(cur orgsRecord, exists bool) (orgsRecord, bool) {
		if !exists || cur.Owner != caller {
			return cur, false // ownership changed concurrently (or vanished) -> don't write
		}
		cur.Owner = newOwner
		result = cur
		transferred = true
		return cur, true
	})
	if !transferred {
		core.WriteProblem(w, 409, "ownership changed concurrently")
		return
	}
	// the NEW owner is DERIVED (tombstone any row they had); the OLD owner is demoted to an ACTIVE 'admin' (already
	// proven). BOTH go through the Do() seam so they SERIALIZE with a concurrent OrgsRemoveMember(caller) on the SAME
	// member key — deterministic last-writer-wins, no resurrection of a hard-deleted row (invariant I18).
	orgsMembers.Do(orgsMemberKey(org.Slug, newOwner), func(cur orgsMember, exists bool) (orgsMember, bool) {
		if !exists {
			return cur, false
		}
		cur.Status = orgsRemoved
		return cur, true
	})
	if newOwner != caller {
		orgsMembers.Do(orgsMemberKey(org.Slug, caller), func(cur orgsMember, exists bool) (orgsMember, bool) {
			return orgsMember{Org: org.Slug, Handle: caller, Role: orgsRoleAdmin, Status: orgsActive}, true
		})
	}
	orgsAudit(r, caller, "transfer", newOwner, org.Slug, "transfer", "ok") // the OWNERSHIP-CHANGE event (highest value)
	core.WriteJSON(w, 200, result)
}

func OrgsArchive(w http.ResponseWriter, r *http.Request) {
	org, caller, ok := orgsManager(w, r, orgsRoleOwner, orgsRoleAdmin) // owner|admin may archive
	if !ok {
		return
	}
	// monotonic + idempotent: "archived" is TERMINAL. Do() reads the CURRENT record IN the lock -> a concurrent transfer's owner change is PRESERVED.
	var result orgsRecord
	found := false
	orgsRecords.Do(org.Slug, func(cur orgsRecord, exists bool) (orgsRecord, bool) {
		if !exists {
			return cur, false
		}
		cur.Status = "archived"
		result = cur
		found = true
		return cur, true
	})
	if !found {
		core.WriteProblem(w, 404, "org not found")
		return
	}
	orgsAudit(r, caller, "archive", org.Slug, org.Slug, "archive", "ok")
	core.WriteJSON(w, 200, result)
}

func OrgsAddMember(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	_, caller, ok := orgsManager(w, r, orgsRoleOwner, orgsRoleAdmin) // owner|admin only (authz before decode)
	if !ok {
		return
	}
	in, ok := core.DecodeJSON[struct {
		Handle *string `json:"handle"`
		Role   *string `json:"role"`
	}](w, r)
	if !ok {
		return
	}
	if in.Handle == nil || !well_formed.IsWellFormed(*in.Handle) || in.Role == nil || !well_formed.IsWellFormed(*in.Role) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	if *in.Role != orgsRoleAdmin && *in.Role != orgsRoleMember {
		// ownership moves ONLY via transfer — a manager can never mint a second owner through add-member
		orgsAudit(r, caller, "add-member", *in.Handle, slug, "deny", "role-not-assignable")
		core.WriteProblem(w, 403, "role must be 'admin' or 'member' (ownership transfers only)")
		return
	}
	// INVITE: PENDING until the invitee ACCEPTS the single-use token (the escalation fix); re-inviting an ACTIVE member re-sets the role (no token). ONE atomic Do(); token minted OUTSIDE.
	now := core.TestNow(r)
	token := orgsRandURL(9) + "." + orgsRandURL(24)
	secretHash, exp := digest.DigestHex(token), now+orgsInviteTTL()
	resultStatus := ""
	orgsMembers.Do(orgsMemberKey(slug, *in.Handle), func(cur orgsMember, exists bool) (orgsMember, bool) {
		if exists && cur.Status == orgsActive {
			resultStatus = orgsActive // already proven -> just (re)set the role, no token
			cur.Role = *in.Role
			return cur, true
		}
		resultStatus = orgsPending // new or still-pending -> (re)issue a single-use invite
		return orgsMember{Org: slug, Handle: *in.Handle, Role: *in.Role, Status: orgsPending,
			SecretHash: secretHash, InviteExp: exp}, true
	})
	if resultStatus == orgsPending {
		orgsDeliverInvite(slug, *in.Handle, token) // the token reaches the invitee, never the inviter
		orgsAudit(r, caller, "invite", *in.Handle, slug, "ok", "pending")
	} else {
		orgsAudit(r, caller, "add-member", *in.Handle, slug, "grant", "ok")
	}
	core.WriteJSON(w, 201, map[string]any{"slug": slug, "handle": *in.Handle, "role": *in.Role, "status": resultStatus})
}

func OrgsAccept(w http.ResponseWriter, r *http.Request) {
	// ACCEPT a pending invite — keyed on the CALLER (== invited handle), so a token for X is redeemable only by X. SINGLE-USE + const-time + unexpired via Do() (mirrors auth consume). Wrong secret 403, absent 404, expired 410.
	org, caller, ok := orgsAuthLoad(w, r)
	if !ok {
		return
	}
	in, ok := core.DecodeJSON[struct {
		Token *string `json:"token"`
	}](w, r)
	if !ok {
		return
	}
	if in.Token == nil || !well_formed.IsWellFormed(*in.Token) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	now := core.TestNow(r)
	outcome := "missing"
	// no invite for this caller (or already active) -> 404; expired -> 410; wrong secret -> 403 (no activate, no consume).
	orgsMembers.Do(orgsMemberKey(org.Slug, caller), func(cur orgsMember, exists bool) (orgsMember, bool) {
		if !exists || cur.Status != orgsPending {
			outcome = "missing"
			return cur, false
		}
		if now >= cur.InviteExp {
			outcome = "expired"
			return cur, false
		}
		if cur.SecretHash == "" || !hmac.Equal([]byte(digest.DigestHex(*in.Token)), []byte(cur.SecretHash)) {
			outcome = "badtoken"
			return cur, false
		}
		outcome = "ok"
		return orgsMember{Org: org.Slug, Handle: caller, Role: cur.Role, Status: orgsActive}, true // activate + clear secret
	})
	deny := map[string][3]any{ // outcome -> {status, audit-reason, detail}; every denial is audited-before-refuse
		"missing":  {404, "no-pending-invite", "invitation not found"},
		"expired":  {410, "invite-expired", "invitation expired"},
		"badtoken": {403, "invalid-token", "invalid invitation token"},
	}
	if d, bad := deny[outcome]; bad {
		orgsAudit(r, caller, "accept", caller, org.Slug, "deny", d[1].(string))
		core.WriteProblem(w, d[0].(int), d[2].(string))
		return
	}
	member, _ := orgsMembers.Get(orgsMemberKey(org.Slug, caller))
	orgsAudit(r, caller, "accept", caller, org.Slug, "accept", "ok")
	core.WriteJSON(w, 200, map[string]any{"slug": org.Slug, "handle": caller, "role": member.Role, "status": orgsActive})
}

func OrgsRemoveMember(w http.ResponseWriter, r *http.Request) {
	org, caller, ok := orgsManager(w, r, orgsRoleOwner, orgsRoleAdmin) // owner|admin only (authz before path validation)
	if !ok {
		return
	}
	handle := r.PathValue("handle")
	if !well_formed.IsWellFormed(handle) {
		core.WriteProblem(w, 422, "the member handle must be non-empty with no control characters")
		return
	}
	if handle == org.Owner {
		orgsAudit(r, caller, "remove-member", handle, org.Slug, "deny", "owner-not-removable")
		core.WriteProblem(w, 403, "the owner cannot be removed (transfer ownership first)") // never ownerless
		return
	}
	// SOFT delete: tombstone the row (status="removed") through the Do() seam — NOT a hard Delete. This SERIALIZES
	// with a concurrent transfer-demotion on the SAME member key (deterministic last-writer-wins), so a confirmed-
	// removed member can never be resurrected by the demotion's write (invariant I18). OrgRole grants only
	// status=="active", so the tombstone is inert. Removing an absent member is a no-op.
	orgsMembers.Do(orgsMemberKey(org.Slug, handle), func(cur orgsMember, exists bool) (orgsMember, bool) {
		if !exists {
			return cur, false
		}
		cur.Status = orgsRemoved
		return cur, true
	})
	orgsAudit(r, caller, "remove-member", handle, org.Slug, "remove", "ok")
	core.WriteJSON(w, 200, map[string]any{"slug": org.Slug, "handle": handle, "removed": true})
}
