"""ai_workflow — multi-step pipelines over a running value: each step's output threads into the next. The
dangerous property is TERMINATION + CONTAINMENT: a run ALWAYS terminates (MAX_STEPS bounds every run — a
runaway pipeline is impossible) and a failing or unknown step is CONTAINED (the run stops gracefully with
ok:false and the trace so far — never a crash, never a 5xx). String ops slice and measure by CODEPOINTS — the
×3-identical semantic (go uses runes, node spreads to codepoints). Definitions are durable. The ops are simple
transforms here; real steps (a gateway completion, a tool invoke) drop in behind the same contract."""
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from pydantic import BaseModel, StrictStr, field_validator

from ..core import store
from ..core.errors import IntPath, not_found, require_identity

router = APIRouter(prefix="/workflows", tags=["ai_workflow"])

_MAX_STEPS = 50   # the terminate guard: a run executes at most this many steps, ever
# state in `store`: seq "ai_workflow_def" · ns "ai_workflow_defs" str(id) -> {id, steps} (same names ×3)


class WorkflowIn(BaseModel):
    steps: List[Dict[str, Any]]

    @field_validator("steps")
    @classmethod
    def well_formed_steps(cls, value: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not value:
            raise ValueError("a workflow needs at least one step")
        for step in value:
            if not isinstance(step, dict) or not isinstance(step.get("op"), str) or not step["op"]:
                raise ValueError("every step must be an object with a string 'op'")
        return value


class RunIn(BaseModel):
    input: StrictStr   # the seed value — empty is legal (the length op of "" is "0")


def _apply(op: str, value: str, step: Dict[str, Any]):
    """One step. Returns (new_value, ok) — unknown/invalid ops report ok=False, they never raise."""
    if op == "append":
        return value + str(step.get("text", "")), True
    if op == "prepend":
        return str(step.get("text", "")) + value, True
    if op == "truncate":
        n = step.get("n", 0)
        return value[: n if isinstance(n, int) and n >= 0 else 0], True   # python slices by codepoints natively
    if op == "length":
        return str(len(value)), True
    return value, False


@router.post("", status_code=201)
def create(data: WorkflowIn, caller: str = Depends(require_identity)) -> dict:   # authenticated mutation (no/invalid token -> 401)
    wid = store.next_id("ai_workflow_def")
    store.put("ai_workflow_defs", str(wid), {"id": wid, "steps": data.steps})
    return {"id": wid, "steps": len(data.steps)}


@router.post("/{workflow_id}/run")
def run(workflow_id: IntPath, data: RunIn, caller: str = Depends(require_identity)) -> dict:   # authenticated mutation (no/invalid token -> 401)
    wf = store.get("ai_workflow_defs", str(workflow_id))
    if wf is None:
        raise not_found("workflow")
    value, trace, ok = data.input, [], True
    for step in wf["steps"][:_MAX_STEPS]:        # TERMINATION: never more than MAX_STEPS, whatever was defined
        value, step_ok = _apply(step["op"], value, step)
        if not step_ok:
            ok = False                            # CONTAINMENT: stop gracefully, keep the trace so far
            break
        trace.append({"op": step["op"], "output": value})
    if ok and len(wf["steps"]) > _MAX_STEPS:
        ok = False                                # the budget itself was exceeded — report it, loudly
    return {"output": value, "steps_run": len(trace), "ok": ok, "trace": trace}
