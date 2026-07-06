"""The run loop: input -> provider -> (structured tool call? -> run -> observe -> loop) -> answer.
THE INVARIANT: the loop ALWAYS terminates — bounded by MAX_ITERATIONS, proven black-box by the 'use forever'
contract case and the shipped invariant test. Memory is the durable store seam (survives restarts)."""
import logging
from typing import Any, Dict, List, Optional

from . import config
from .ports import LLMProvider, Message, Usage
from .tools.registry import ToolRegistry
from ...core import store, usage as core_usage
from ...parts.well_formed import make_well_formed

_MSG_TRUNC = "…[truncated]…"   # the middle-truncation marker (advisory only — a tool may emit it; never key a decision on it)
_log = logging.getLogger("agent")
_warned_unmetered = False       # the lazy warn-once flag (a real provider running unmetered warns ONCE per process)


def _meter_call(owner: str, session_id: int, now: int, u: Optional[Usage]) -> None:
    """Meter ONE provider call's usage into the core usage sink (which forwards to llm_usage when present). NEVER
    raises — a meter failure must not break the run. Real providers always meter; the fake meters only when ARMED
    (AI_USAGE_METER_FAKE=1), so the default fake stays free + the bar stays inert."""
    global _warned_unmetered
    if u is None:
        return
    provider = config.provider_name()
    if provider == "fake" and not config.meter_fake():
        return                                     # fake is free + unmetered by default (arm to see the wire)
    # the identifier (exactly-once): the provider's response id when present; else agent's OWN atomic-minted fallback
    identifier = u.identifier or f"agent:{session_id}:{store.next_id('agent_usage_seq')}"
    call = {"identifier": identifier, "provider": provider, "model": u.model,
            "input_tokens": u.input_tokens, "output_tokens": u.output_tokens,
            "cache_read_input_tokens": u.cache_read_input_tokens,
            "cache_creation_input_tokens": u.cache_creation_input_tokens, "reasoning_tokens": u.reasoning_tokens}
    status = core_usage.usage_record(owner, call, now)   # never raises; the run's success is independent of the meter's
    if status == "no-meter" and provider != "fake" and not _warned_unmetered:
        _warned_unmetered = True                   # lazy, first-real-use only (no boot-time check — the import-order trap)
        _log.warning("AI_PROVIDER=%s but no usage meter is registered in this build — LLM spend is NOT being recorded "
                     "(add the llm_usage domain, or meter externally via POST /llm_usage/events)", provider)


def _truncate_middle(s: str, cap: int) -> str:
    """Bound s to cap CODE POINTS, keeping the HEAD and the TAIL (the tool's answer/error is often at the end) with a
    marker between — matches smolagents. Codepoint-based (python len/slice), so identical ×3 with go/node."""
    if len(s) <= cap:
        return s
    keep = cap - len(_MSG_TRUNC)
    if keep <= 0:
        return s[:cap]
    head = keep // 2
    return s[:head] + _MSG_TRUNC + s[len(s) - (keep - head):]


def chunk_output(s: str) -> List[str]:
    """Split the final output into fixed CODE-POINT windows (SSE_CHUNK_CODEPOINTS) for the streamed response —
    the same codepoint discipline as _truncate_middle (python len/slice · go []rune · node [...s]), so the delta
    frames are identical ×3 and always concatenate back to exactly the sync output."""
    k = config.SSE_CHUNK
    return [s[i:i + k] for i in range(0, len(s), k)]


class Memory:
    """Per-session conversation history over the durable store (ns agent_memory — same name in all 3 languages)."""

    def __init__(self, store: Any) -> None:
        self._store = store

    def append(self, session_id: int, role: str, content: str) -> None:
        # CONTAIN a lone surrogate (e.g. a decoded `\ud800` JSON escape) -> U+FFFD via the central well_formed part, so
        # the stored content is ALWAYS UTF-8-serializable — else GET /messages (and the run response) raise an
        # uncontained 5xx on encode (the lone-surrogate crash class). Go is identity (its strings are valid UTF-8).
        content = _truncate_middle(make_well_formed(content), config.MSG_MAX)   # well-formed THEN size-bounded
        # atomic append via the do seam: a get-then-put RACES — concurrent appends to one session's history lose a
        # message (the rbac F1 class). do() holds the write lock across read+write; the callback is pure.
        # RING-BUFFER: keep only the last HISTORY_MAX messages (drop-oldest) so the stored blob, the per-turn feed, and
        # GET /messages are all BOUNDED — closes the unbounded-history O(n^2)/OOM/cost soft-DoS.
        self._store.do("agent_memory", str(session_id),
                       lambda hist: (((hist or []) + [{"role": role, "content": content}])[-config.HISTORY_MAX:], None))

    def history(self, session_id: int) -> List[Message]:
        return [Message(**m) for m in (self._store.get("agent_memory", str(session_id)) or [])]


def run_loop(provider: LLMProvider, tools: ToolRegistry, memory: Memory,
             session_id: int, system: str, user_input: str, owner: str, now: int) -> Dict[str, Any]:
    memory.append(session_id, "user", user_input)

    def done(output: str, iterations: int, terminated: bool) -> Dict[str, Any]:
        output = _truncate_middle(make_well_formed(output), config.MSG_MAX)   # the RESPONSE matches the stored copy (bounded + contained)
        memory.append(session_id, "assistant", output)
        return {"output": output, "iterations": iterations, "terminated": terminated}

    for i in range(config.MAX_ITERATIONS):
        resp = provider.complete(system, memory.history(session_id))
        _meter_call(owner, session_id, now, resp.usage)  # meter this call's spend (never breaks the run)
        if resp.final is not None:                       # the agent answered -> done
            return done(resp.final, i + 1, False)
        result = tools.run(resp.tool or "", resp.args or {})
        observation = result.output if result.ok else f"error: {result.error}"   # graceful, never a crash
        memory.append(session_id, "tool", observation)
    return done("stopped: max iterations reached", config.MAX_ITERATIONS, True)   # the terminate guard
