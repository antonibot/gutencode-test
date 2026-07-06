// teams — teams within an org, with role-bearing membership, AUTHORIZED AGAINST ORG MEMBERSHIP.
// (1) SET MEMBERSHIP: the member list is a SET keyed by handle — adding an existing member UPDATES their role
// (idempotent upsert, never a duplicate), removing is idempotent (a non-member is a no-op), deterministic (sorted by
// handle). Whole team in ONE atomic put. (2) ORG BINDING set once at creation, never changed. (3) ORG-SCOPED AUTHZ
// — every route authorizes against the caller's role IN THE TEAM'S ORG (the core orgRole seam, which reads the
// orgs_members store orgs writes). MUTATIONS require an owner|admin (creating a team under an org you don't manage
// is 403; only that org's owners/admins add/remove members). The READ requires only MEMBERSHIP — any role may view
// it, and a NON-member is 404 (not-yours == not-found, mirroring api_keys' load), so an enumerable id leaks nothing.
//
// IDENTITY: every route is deny-by-default authenticated (401); the authz SUBJECT is the token, the SCOPE is the
// team's org. teams imports NOTHING from orgs — it reads membership through orgRole (boundary: domains -> core).
// authn -> not-found -> authz -> validation, identical ×3 (the rbac order): the path routes run requireIdentity,
// then load, then the orgRole check BEFORE the body fields are validated (a mutation non-member is 403, a read
// non-member is 404); create takes its org from the body, so its orgRole check is after field validation (401 -> 422
// -> 403). The read-scoping was the documented follow-on to the create + member wave; it is now closed. Matches
// python/go; durable.
import { intParam, nextId, orgRole, problem, requireIdentity, sendJSON, storeGet, storePut } from '../core/runtime.js';
import { isWellFormed } from '../parts/well_formed.js';

// state in store: seq 'teams_team' · ns 'teams_records' String(id) -> {id, org, name, members:[{handle, role}]}

const MANAGER_ROLES = ['owner', 'admin']; // an org owner|admin may manage that org's teams
const orgManager = async (org, caller) => MANAGER_ROLES.includes(await orgRole(org, caller));
const orgMember = async (org, caller) => (await orgRole(org, caller)) !== undefined; // ANY role of the org may read its teams

const sortMembers = (members) => members.slice().sort((a, b) => (a.handle < b.handle ? -1 : a.handle > b.handle ? 1 : 0));

// manageLoad: the shared chokepoint for the path-scoped member routes. authn (401) -> id validation (422) ->
// load (404) -> orgRole owner|admin (403), all BEFORE the body fields are validated — identical ×3 with python's
// Depends(team_manager_dep). Returns the loaded team + caller, or null after sending the right status.
async function manageLoad(req, res, params) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return null;
  const tid = intParam(params.team_id);
  if (tid === null) {
    problem(res, 422, 'invalid team id');
    return null;
  }
  const team = await storeGet('teams_records', String(tid));
  if (team === undefined) {
    problem(res, 404, 'team not found');
    return null;
  }
  if (!(await orgManager(team.org, caller))) {
    problem(res, 403, 'managing this team requires being an owner or admin of its org');
    return null;
  }
  return { team, caller };
}

// memberLoad: the chokepoint for the READ route. authn (401) -> id validation (422) -> load (404) -> org MEMBERSHIP
// (any role; a non-member is 404, not-yours == not-found, mirroring api_keys' load), all identical ×3 with python's
// Depends(team_member_dep). Returns the loaded team, or null after sending the right status.
async function memberLoad(req, res, params) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return null;
  const tid = intParam(params.team_id);
  if (tid === null) {
    problem(res, 422, 'invalid team id');
    return null;
  }
  const team = await storeGet('teams_records', String(tid));
  if (team === undefined) {
    problem(res, 404, 'team not found');
    return null;
  }
  if (!(await orgMember(team.org, caller))) { // not a member of the team's org -> not-yours == not-found
    problem(res, 404, 'team not found');
    return null;
  }
  return team;
}

export async function teamsCreate(req, res, params, body) {
  // requireIdentity (401) -> field validation (422) -> orgRole authz on the BODY's org (403), matching python.
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  if (!body || !isWellFormed(body.org) || typeof body.name !== 'string' || body.name === '') {
    return problem(res, 422, 'invalid body');
  }
  if (!(await orgManager(body.org, caller))) { // only an owner|admin of that org may create a team under it
    return problem(res, 403, 'managing this team requires being an owner or admin of its org');
  }
  const tid = await nextId('teams_team');
  const team = { id: tid, org: body.org, name: body.name, members: [] }; // org bound once, never changed
  await storePut('teams_records', String(tid), team);
  sendJSON(res, 201, team);
}

export async function teamsGet(req, res, params) {
  // read-scoping: auth (401) -> load (404) -> org membership (a non-member is 404,
  // not-yours == not-found); only a member of the team's org sees it. Now closed (was a documented follow-on).
  const team = await memberLoad(req, res, params);
  if (team !== null) sendJSON(res, 200, team);
}

export async function teamsAddMember(req, res, params, body) {
  const ctx = await manageLoad(req, res, params); // auth + org owner|admin (403) BEFORE field validation
  if (ctx === null) return;
  if (!body || !isWellFormed(body.handle) || typeof body.role !== 'string' || body.role === '') {
    return problem(res, 422, 'invalid body');
  }
  // SET semantics: drop any existing entry for this handle, then add — an upsert, never a duplicate
  const members = ctx.team.members.filter((m) => m.handle !== body.handle);
  members.push({ handle: body.handle, role: body.role });
  const updated = { ...ctx.team, members: sortMembers(members) };
  await storePut('teams_records', String(ctx.team.id), updated); // whole team in ONE atomic put
  sendJSON(res, 200, updated);
}

export async function teamsRemoveMember(req, res, params) {
  const ctx = await manageLoad(req, res, params); // auth + org owner|admin (403) BEFORE path validation
  if (ctx === null) return;
  if (!isWellFormed(params.handle)) {
    return problem(res, 422, 'the member handle must be non-empty with no control characters');
  }
  // idempotent: filtering a non-member changes nothing, still a 200
  const updated = { ...ctx.team, members: sortMembers(ctx.team.members.filter((m) => m.handle !== params.handle)) };
  await storePut('teams_records', String(ctx.team.id), updated);
  sendJSON(res, 200, updated);
}
