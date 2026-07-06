"""users — profiles + lifecycle, separate from auth credentials. Two dangerous properties, both proven:
(1) HANDLE UNIQUENESS: a handle is claimed exactly once via the idempotent_claim part — two processes racing
    the same handle create ONE user (the loser sees the winner); a duplicate create is 409, never a silent
    overwrite. (2) MONOTONIC LIFECYCLE: deactivation is a terminal-value write (the billing-cancel class) —
    idempotent, race-convergent, and a deactivated user never returns to active. Durable across restart.
(3) IDENTITY: both mutations require the core require_identity seam (no/invalid token -> 401). CREATE is
    AUTHENTICATED-SELF — a logged-in caller may only mint THEIR OWN handle (handle == caller, else 403): this
    closes handle-squatting/spam (a stranger can no longer claim any name). DEACTIVATE is SELF-OR-ADMIN — the
    account owner OR a core admin (is_admin) may deactivate; anyone else is 403 (closing "anyone permanently
    kills any account"). (4) AUTHENTICATED READ: GET /{handle} requires a valid session (no/invalid token ->
    401) — the profile directory is visible to logged-in callers, not the anonymous public; any authenticated caller
    may look up any handle."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, StrictStr, field_validator

from ..core import store
from ..core.errors import conflict, forbidden, is_admin, not_found, require_identity
from ..parts.idempotent_claim import claim_once
from ..parts.well_formed import WellFormedStr, require_well_formed

router = APIRouter(prefix="/users", tags=["users"])
# state in `store`: seq "users_user" · ns "users_profiles" handle -> {id, handle, display_name, status} (×3)


class UserIn(BaseModel):
    handle: WellFormedStr
    display_name: StrictStr

    @field_validator("display_name")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("must be non-empty")
        return value


@router.post("", status_code=201)
def create(data: UserIn, caller: str = Depends(require_identity)) -> dict:
    # AUTHENTICATED-SELF: a caller may only create their OWN handle (closes handle-squatting). authn (401) is
    # resolved by the dependency; this 403 fires before the conflict/claim, mirrored ×3 by go/node.
    if data.handle != caller:
        raise forbidden("you may only create your own handle")
    if store.get("users_profiles", data.handle) is not None:
        raise conflict("handle taken")   # fast path: a settled handle never mints (ids stay contiguous)
    # mint BEFORE the claim (a race loser's id is a gap), then claim the handle atomically — exactly one winner
    rec = {"id": store.next_id("users_user"), "handle": data.handle,
           "display_name": data.display_name, "status": "active"}
    settled = claim_once("users_profiles", data.handle, rec)
    if settled["id"] != rec["id"]:
        raise conflict("handle taken")   # the handle has an owner — never silently overwrite a profile
    return settled


@router.get("/{handle}")
def get_user(handle: str, _caller: str = Depends(require_identity)) -> dict:
    # AUTHENTICATED READ: the profile directory is visible to any logged-in caller (no/invalid token -> 401),
    # not the anonymous public; any authenticated caller may look up any handle. authn (Depends) resolves BEFORE the
    # path well_formed/404, mirrored ×3. Returns only public fields (id, handle, display_name, status).
    user = store.get("users_profiles", require_well_formed(handle, "the handle"))
    if user is None:
        raise not_found("user")
    return user


@router.post("/{handle}/deactivate")
def deactivate(handle: str, caller: str = Depends(require_identity)) -> dict:
    # SELF-OR-ADMIN: resolve identity (401) first, then authorize — the account owner OR a core admin may
    # deactivate; anyone else is 403. The authz fires BEFORE the well-formed/404 path checks (authn -> authz
    # -> path/semantic), identical ×3, exactly as the rbac admin pattern orders it.
    if caller != handle and not is_admin(caller):
        raise forbidden("you may only deactivate your own account")
    user = store.get("users_profiles", require_well_formed(handle, "the handle"))
    if user is None:
        raise not_found("user")
    # monotonic + idempotent: "deactivated" is TERMINAL — concurrent calls converge, nothing reactivates
    deactivated = {**user, "status": "deactivated"}
    store.put("users_profiles", handle, deactivated)
    return deactivated
