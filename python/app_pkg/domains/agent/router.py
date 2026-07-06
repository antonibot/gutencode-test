"""The agent API — wires provider + tools + memory + the loop into endpoints. State (agents · sessions ·
conversations) lives in the durable store seam (namespaces agent_agents/agent_sessions/agent_memory + the
agent_* counters — the SAME names in all three languages)."""
from typing import List

from fastapi import APIRouter, Depends, Request

from ...core import clock, store
from ...core.errors import IntPath, not_found, require_identity, sse_stream, wants_stream
from .models import AgentIn, AgentOut, MessageOut, RunIn, RunOut, SessionOut
from .providers.factory import get_provider
from .runtime import Memory, chunk_output, run_loop
from .tools.builtin import register_builtins
from .tools.registry import ToolRegistry

router = APIRouter(prefix="/agents", tags=["agents"])

_memory = Memory(store)
_tools = ToolRegistry()
register_builtins(_tools)


# IDENTITY + USER-SCOPED: every route addressed by {agent_id} requires an authenticated
# caller AND the agent must be OWNED by that caller. The OWNER is stamped from the authenticated subject at create
# (never a body field) and kept OUT of the API response (internal, like api_keys' secret_hash). A management/read
# op on another caller's agent id is 404 — byte-identical to a missing id (the tenancy not-yours==not-found
# pattern), so the enumerable sequential id leaks no existence: ANY caller can no longer read ANY user's session
# history. FastAPI orders Depends(require_identity) before body/path validation, so PARSE->AUTH->SEMANTIC holds.
@router.post("/", response_model=AgentOut, status_code=201)
def create_agent(data: AgentIn, caller: str = Depends(require_identity)) -> AgentOut:
    aid = store.next_id("agent_agent")
    # owner derived from the token, never client-set; stored on the record but NOT in the AgentOut response.
    store.put("agent_agents", str(aid),
              {"id": aid, "name": data.name, "system_prompt": data.system_prompt, "owner": caller})
    return AgentOut(id=aid, name=data.name, system_prompt=data.system_prompt)


def _load_agent(agent_id: int, caller: str) -> dict:
    # owner-or-404 loader (mirrors api_keys `_load`): 404 if the agent is MISSING or owned by someone else, so a
    # cross-owner probe can't learn the id exists. Every {agent_id}-addressed route loads through this.
    agent = store.get("agent_agents", str(agent_id))
    if agent is None or agent.get("owner") != caller:
        raise not_found("agent")
    return agent


@router.post("/{agent_id}/sessions", response_model=SessionOut, status_code=201)
def create_session(agent_id: IntPath, caller: str = Depends(require_identity)) -> SessionOut:
    _load_agent(agent_id, caller)   # owner-or-404 before creating a session under the agent
    sid = store.next_id("agent_session")
    store.put("agent_sessions", str(sid), agent_id)
    return SessionOut(id=sid, agent_id=agent_id)


@router.post("/{agent_id}/sessions/{session_id}/run", response_model=RunOut)
def run(agent_id: IntPath, session_id: IntPath, data: RunIn, request: Request,
        caller: str = Depends(require_identity)):
    agent = _load_agent(agent_id, caller)   # owner-or-404 FIRST, then the session<->agent binding
    if store.get("agent_sessions", str(session_id)) != agent_id:
        raise not_found("session for this agent")
    # owner = the run's authenticated subject (the owner-self-metering trust model, executed server-side — the spend
    # lands in THIS user's llm_usage summary); now = the request clock (keeps the test-clock seam coherent).
    result = run_loop(get_provider(), _tools, _memory, session_id, str(agent["system_prompt"]), data.input,
                      caller, clock.current(request))
    if wants_stream(request):
        # SSE mode (?stream=1, or Accept: text/event-stream) — the SAME run result, chunked at the transport:
        # the delta frames concatenate to exactly `output`, and `event: done` carries this exact sync body.
        return sse_stream(chunk_output(result["output"]), {"session_id": session_id, **result})
    return RunOut(session_id=session_id, **result)


# READ is USER-SCOPED: require_identity + owner-or-404, THEN
# the session<->agent binding. A non-owner reading another's messages -> 404; no token -> 401.
@router.get("/{agent_id}/sessions/{session_id}/messages", response_model=List[MessageOut])
def messages(agent_id: IntPath, session_id: IntPath, caller: str = Depends(require_identity)) -> List[MessageOut]:
    _load_agent(agent_id, caller)   # owner-or-404: a stranger cannot read this agent's session history
    if store.get("agent_sessions", str(session_id)) != agent_id:
        raise not_found("session for this agent")
    return [MessageOut(role=m.role, content=m.content) for m in _memory.history(session_id)]
