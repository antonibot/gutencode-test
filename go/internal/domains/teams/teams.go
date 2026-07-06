// Package teams — teams within an org, with role-bearing membership, AUTHORIZED AGAINST ORG MEMBERSHIP.
// (1) SET MEMBERSHIP: the member list is a SET keyed by handle — adding an existing member UPDATES their role
// (idempotent upsert, never a duplicate), removing is idempotent (a non-member is a no-op), deterministic (sorted by
// handle). Whole team in ONE atomic put. (2) ORG BINDING set once at creation, never changed. (3) ORG-SCOPED AUTHZ
// — every route authorizes against the caller's role IN THE TEAM'S ORG (the core OrgRole seam, which reads the
// orgs_members store orgs writes). MUTATIONS require an owner|admin (creating a team under an org you don't manage
// is 403; only that org's owners/admins add/remove members). The READ requires only MEMBERSHIP — any role may view
// it, and a NON-member is 404 (not-yours == not-found, mirroring api_keys' load), so an enumerable id leaks nothing.
//
// IDENTITY: every route is deny-by-default authenticated (401); the authz SUBJECT is the token, the SCOPE is the
// team's org. teams imports NOTHING from orgs — it reads membership through core.OrgRole (boundary: domains -> core).
// authn -> not-found -> authz -> validation, identical ×3 (the rbac order): the path routes run auth, then load,
// then the OrgRole check BEFORE the body is decoded (a mutation non-member is 403, a read non-member is 404); create
// takes its org from the body, so its OrgRole check is after field validation (401 -> 422 -> 403). The read-scoping
// was the documented follow-on to the create + member wave; it is now closed. Matches python/node; durable.
package teams

import (
	"net/http"
	"sort"
	"strconv"

	"app/internal/core"
	"app/internal/parts/well_formed"
)

type teamsMember struct {
	Handle string `json:"handle"`
	Role   string `json:"role"`
}

type teamsRecord struct {
	Id      int           `json:"id"`
	Org     string        `json:"org"`
	Name    string        `json:"name"`
	Members []teamsMember `json:"members"`
}

var teamsRecords = core.NewKV[string, teamsRecord]("teams_records")

// an org owner|admin may manage that org's teams.
func teamsOrgManager(org, caller string) bool {
	role, _ := core.OrgRole(org, caller)
	return role == "owner" || role == "admin"
}

// ANY member of the org (any role) may read its teams. A non-member is not a member.
func teamsOrgMember(org, caller string) bool {
	_, ok := core.OrgRole(org, caller)
	return ok
}

func teamsSort(members []teamsMember) []teamsMember {
	sort.Slice(members, func(i, j int) bool { return members[i].Handle < members[j].Handle })
	return members
}

// teamsManageLoad: the shared chokepoint for the path-scoped member routes. authn (401) -> id validation (422) ->
// load (404) -> OrgRole owner|admin (403), all BEFORE the body is decoded — identical ×3 with python's
// Depends(_team_manager_dep). Returns the loaded team + caller, or ok=false after writing the right status.
func teamsManageLoad(w http.ResponseWriter, r *http.Request) (teamsRecord, string, bool) {
	caller, ok := core.RequireIdentity(w, r)
	if !ok {
		return teamsRecord{}, "", false
	}
	tid, err := strconv.Atoi(r.PathValue("team_id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid team id")
		return teamsRecord{}, "", false
	}
	team, exists := teamsRecords.Get(strconv.Itoa(tid))
	if !exists {
		core.WriteProblem(w, 404, "team not found")
		return teamsRecord{}, "", false
	}
	if !teamsOrgManager(team.Org, caller) {
		core.WriteProblem(w, 403, "managing this team requires being an owner or admin of its org")
		return teamsRecord{}, "", false
	}
	return team, caller, true
}

// teamsMemberLoad: the chokepoint for the READ route. authn (401) -> id validation (422) -> load (404) -> org
// MEMBERSHIP (any role; a non-member is 404, not-yours == not-found, mirroring api_keys' load), all identical ×3
// with python's Depends(_team_member_dep). Returns the loaded team, or ok=false after writing the right status.
func teamsMemberLoad(w http.ResponseWriter, r *http.Request) (teamsRecord, bool) {
	caller, ok := core.RequireIdentity(w, r)
	if !ok {
		return teamsRecord{}, false
	}
	tid, err := strconv.Atoi(r.PathValue("team_id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid team id")
		return teamsRecord{}, false
	}
	team, exists := teamsRecords.Get(strconv.Itoa(tid))
	if !exists {
		core.WriteProblem(w, 404, "team not found")
		return teamsRecord{}, false
	}
	if !teamsOrgMember(team.Org, caller) { // not a member of the team's org -> not-yours == not-found
		core.WriteProblem(w, 404, "team not found")
		return teamsRecord{}, false
	}
	return team, true
}

func TeamsCreate(w http.ResponseWriter, r *http.Request) {
	// body-only POST: DecodeJSON FIRST (413 + drains the stream), THEN RequireIdentity, THEN field validation, THEN
	// the org_role authz on the BODY's org (so the order is 401 -> 422 -> 403, matching python's in-handler check).
	in, ok := core.DecodeJSON[struct {
		Org  *string `json:"org"`
		Name *string `json:"name"`
	}](w, r)
	if !ok {
		return
	}
	caller, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if in.Org == nil || !well_formed.IsWellFormed(*in.Org) || in.Name == nil || *in.Name == "" {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	if !teamsOrgManager(*in.Org, caller) { // only an owner|admin of that org may create a team under it
		core.WriteProblem(w, 403, "managing this team requires being an owner or admin of its org")
		return
	}
	tid := core.NextID("teams_team")
	team := teamsRecord{Id: tid, Org: *in.Org, Name: *in.Name, Members: []teamsMember{}} // org bound once
	teamsRecords.Set(strconv.Itoa(tid), team)
	core.WriteJSON(w, 201, team)
}

func TeamsGet(w http.ResponseWriter, r *http.Request) {
	// read-scoping: auth (401) -> load (404) -> org membership (a non-member is 404,
	// not-yours == not-found); only a member of the team's org sees it. Now closed (was a documented follow-on).
	if team, ok := teamsMemberLoad(w, r); ok {
		core.WriteJSON(w, 200, team)
	}
}

func TeamsAddMember(w http.ResponseWriter, r *http.Request) {
	team, _, ok := teamsManageLoad(w, r) // auth + org owner|admin (403) BEFORE the body is decoded
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
	if in.Handle == nil || !well_formed.IsWellFormed(*in.Handle) || in.Role == nil || *in.Role == "" {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	// SET semantics: drop any existing entry for this handle, then add — an upsert, never a duplicate
	members := []teamsMember{}
	for _, m := range team.Members {
		if m.Handle != *in.Handle {
			members = append(members, m)
		}
	}
	members = append(members, teamsMember{Handle: *in.Handle, Role: *in.Role})
	team.Members = teamsSort(members)
	teamsRecords.Set(strconv.Itoa(team.Id), team) // whole team in ONE atomic put
	core.WriteJSON(w, 200, team)
}

func TeamsRemoveMember(w http.ResponseWriter, r *http.Request) {
	team, _, ok := teamsManageLoad(w, r) // auth + org owner|admin (403) BEFORE the path is validated
	if !ok {
		return
	}
	handle := r.PathValue("handle")
	if !well_formed.IsWellFormed(handle) {
		core.WriteProblem(w, 422, "the member handle must be non-empty with no control characters")
		return
	}
	// idempotent: filtering a non-member changes nothing, still a 200
	members := []teamsMember{}
	for _, m := range team.Members {
		if m.Handle != handle {
			members = append(members, m)
		}
	}
	team.Members = teamsSort(members)
	teamsRecords.Set(strconv.Itoa(team.Id), team)
	core.WriteJSON(w, 200, team)
}
