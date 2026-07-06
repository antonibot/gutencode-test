"""crew — multi-agent orchestration: named roles that each process the running value and hand off to the next.
The load-bearing invariant is TERMINATION UNDER CYCLES: the handoff graph MAY cycle (A->B->A is a legal
definition), so MAX_HANDOFFS bounds every run — infinite ping-pong is impossible, and hitting the bound is
reported (terminated:false), never disguised as success. A handoff to an UNKNOWN role is CONTAINED (the run
stops gracefully with the trace so far). Handoffs THREAD: each role builds on the prior output. Roles are
tagged contributions here; real roles (an agent with a provider + tools) drop in behind the same contract."""
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from pydantic import BaseModel, StrictStr, field_validator

from ..core import store
from ..core.errors import IntPath, not_found, require_identity
from ..parts.well_formed import is_well_formed

router = APIRouter(prefix="/crews", tags=["crew"])

_MAX_HANDOFFS = 25   # the terminate guard: a run performs at most this many handoffs (bounds any cycle)
# state in `store`: seq "crew_def" · ns "crew_defs" str(id) -> {id, roles} (same names + shape ×3 languages)


class CrewIn(BaseModel):
    roles: List[Dict[str, Any]]   # [{name, next?}] — the first role is the entry point

    @field_validator("roles")
    @classmethod
    def well_formed_roles(cls, value: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not value:
            raise ValueError("a crew needs at least one role")
        seen = set()
        for role in value:
            if not isinstance(role, dict) or not is_well_formed(role.get("name")):
                raise ValueError("every role must be an object with a well-formed string 'name'")
            if "next" in role and not isinstance(role["next"], str):
                raise ValueError("'next' must be a string role name")
            if role["name"] in seen:
                raise ValueError("role names must be unique")
            seen.add(role["name"])
        return value


class RunIn(BaseModel):
    input: StrictStr


@router.post("", status_code=201)
def create(data: CrewIn, caller: str = Depends(require_identity)) -> dict:
    cid = store.next_id("crew_def")
    store.put("crew_defs", str(cid), {"id": cid, "roles": data.roles})
    return {"id": cid, "roles": len(data.roles)}


@router.post("/{crew_id}/run")
def run(crew_id: IntPath, data: RunIn, caller: str = Depends(require_identity)) -> dict:
    crew = store.get("crew_defs", str(crew_id))
    if crew is None:
        raise not_found("crew")
    by_name = {r["name"]: r for r in crew["roles"]}
    current, value, trace = crew["roles"][0], data.input, []
    terminated = False
    while len(trace) < _MAX_HANDOFFS:            # TERMINATION: the bound holds whatever the graph shape
        value = f"{value} [{current['name']}]"   # the role's tagged contribution — THREADING by construction
        trace.append({"role": current["name"], "output": value})
        nxt = current.get("next")
        if nxt is None:
            terminated = True                     # a clean finish: the chain ended by design
            break
        if nxt not in by_name:
            break                                 # CONTAINED: an unknown handoff stops gracefully, trace kept
        current = by_name[nxt]
    return {"output": value, "handoffs": len(trace), "terminated": terminated, "trace": trace}
