"""teams — teams within an org, with role-bearing membership, AUTHORIZED AGAINST ORG MEMBERSHIP. Dangerous
properties:
(1) SET MEMBERSHIP: the member list is a SET keyed by handle — adding an existing member UPDATES their role
    (idempotent upsert, never a duplicate row), removing is idempotent (a non-member is a no-op), and the list is
    deterministic (sorted by handle). The whole team (with its members) is ONE row, so a change is one atomic put.
(2) ORG BINDING: a team is bound to exactly one org at creation and that binding is never changed.
(3) ORG-SCOPED AUTHORIZATION: a team is an ORG resource — every route authorizes against the caller's role IN
    THE TEAM'S ORG (the core org_role seam, which reads the orgs_members store orgs writes). MUTATIONS require an
    owner|admin (creating a team under an org you don't manage is 403; only that org's owners/admins add/remove
    members). The READ requires only MEMBERSHIP — any role of the team's org may view it, and a NON-member is 404
    (not-yours == not-found, mirroring api_keys `_load`), so an enumerable team id leaks no existence across orgs.

IDENTITY: every route is deny-by-default authenticated (no token -> 401); the authz SUBJECT is the bearer
token (never a body/path field) and the authz SCOPE is the team's org. teams imports NOTHING from orgs — it reads
org membership through the core org_role seam (the boundary rule: domains -> core only). authn -> not-found ->
authz -> validation, identical ×3 (the rbac order): the path routes run auth, then load, then the org_role
check BEFORE the body is validated (a mutation non-member gets 403 not the body's 422; a read non-member gets 404);
team CREATE takes its org from the body, so its in-handler org_role check is after body validation (401 -> 422 ->
403). The read-scoping was the documented follow-on to the create + member-management wave; it is now closed.
Durable across restart."""
from typing import List

from fastapi import APIRouter, Depends
from pydantic import BaseModel, StrictStr, field_validator

from ..core import store
from ..core.errors import IntPath, forbidden, not_found, org_role, require_identity
from ..parts.well_formed import WellFormedStr, require_well_formed

router = APIRouter(prefix="/teams", tags=["teams"])
# state in `store`: seq "teams_team" · ns "teams_records" str(id) -> {id, org, name, members:[{handle, role}]} (×3)

_MANAGER_ROLES = ("owner", "admin")   # an org owner|admin may manage that org's teams


class TeamIn(BaseModel):
    org: WellFormedStr
    name: StrictStr

    @field_validator("name")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("must be non-empty")
        return value


class MemberIn(BaseModel):
    handle: WellFormedStr
    role: StrictStr

    @field_validator("role")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("must be non-empty")
        return value


def _load(team_id: int) -> dict:
    team = store.get("teams_records", str(team_id))
    if team is None:
        raise not_found("team")
    return team


def _require_org_manager(org: str, caller: str) -> None:
    # authz: the caller's role IN THE TEAM'S ORG (the core org_role seam) must be owner|admin, else 403.
    if org_role(org, caller) not in _MANAGER_ROLES:
        raise forbidden("managing this team requires being an owner or admin of its org")


def _team_manager_dep(team_id: IntPath, caller: str = Depends(require_identity)) -> dict:
    # A dependency for the path-scoped member routes: resolve the caller, LOAD the team (404), require the caller to
    # be an owner|admin of the team's ORG (403) — all BEFORE the body is validated, so authn -> not-found -> authz
    # -> validation, identical ×3 (the rbac order). Returns the loaded team for the handler to reuse.
    team = _load(team_id)
    _require_org_manager(team["org"], caller)
    return team


def _team_member_dep(team_id: IntPath, caller: str = Depends(require_identity)) -> dict:
    # A dependency for the READ route: resolve the caller (401), LOAD the team (404), then require the caller to be a
    # MEMBER of the team's ORG — ANY role (the read is visible to any member; only mutations require owner|admin). A
    # non-member is 404, NOT 403: a team is not-yours == not-found, so an enumerable id leaks no existence across orgs
    # (mirrors api_keys `_load`). authn -> not-found, identical ×3.
    team = _load(team_id)
    if org_role(team["org"], caller) is None:   # not a member of the team's org -> not-yours == not-found
        raise not_found("team")
    return team


def _sorted(members: List[dict]) -> List[dict]:
    return sorted(members, key=lambda m: m["handle"])   # deterministic membership order ×3


@router.post("", status_code=201)
def create(data: TeamIn, caller: str = Depends(require_identity)) -> dict:
    # the authz scope is the BODY's org (validated above by pydantic); the subject is the token. Only an owner|admin
    # of that org may create a team under it (org_role of a non-existent org is None -> 403). [401 -> 422 -> 403]
    _require_org_manager(data.org, caller)
    tid = store.next_id("teams_team")
    team = {"id": tid, "org": data.org, "name": data.name, "members": []}   # org bound once, never changed
    store.put("teams_records", str(tid), team)
    return team


@router.get("/{team_id}")
def get_team(team: dict = Depends(_team_member_dep)) -> dict:
    # read-scoping: the dependency resolved identity (401), loaded the team (404), and required the
    # caller to be a member of the team's ORG — a non-member is a 404 (not-yours == not-found), only a member sees it.
    return team


@router.post("/{team_id}/members")
def add_member(data: MemberIn, team: dict = Depends(_team_manager_dep)) -> dict:
    # the dependency enforced auth + org owner|admin (403) before this body validated (422).
    members = [m for m in team["members"] if m["handle"] != data.handle]   # SET upsert, never a duplicate
    members.append({"handle": data.handle, "role": data.role})
    team = {**team, "members": _sorted(members)}
    store.put("teams_records", str(team["id"]), team)         # whole team in ONE atomic put
    return team


@router.delete("/{team_id}/members/{handle}")
def remove_member(handle: str, team: dict = Depends(_team_manager_dep)) -> dict:
    # the dependency enforced auth + org owner|admin (403) before this path validated (422).
    require_well_formed(handle, "the member handle")
    # idempotent: filtering a non-member changes nothing, still a 200 (removal is a state assertion, not an event)
    team = {**team, "members": _sorted([m for m in team["members"] if m["handle"] != handle])}
    store.put("teams_records", str(team["id"]), team)
    return team
