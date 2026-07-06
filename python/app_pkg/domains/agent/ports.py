"""The agent's contracts — the provider PORT and the shapes that cross it. A provider returns EITHER a final
answer OR a structured tool call; the runtime never parses free text."""
from typing import Any, Dict, List, Optional, Protocol

from pydantic import BaseModel


class Message(BaseModel):
    role: str        # user | assistant | tool
    content: str


class Usage(BaseModel):
    # the provider call's reported spend, carried back so the run loop can METER it into llm_usage. `identifier` is the
    # provider's response id (the natural exactly-once key); None -> the run loop mints a fallback. `model` is the model
    # the adapter actually sent (so the meter's price table can price it). Absent on a provider that reports no usage.
    identifier: Optional[str] = None
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0
    reasoning_tokens: int = 0


class LLMResponse(BaseModel):
    final: Optional[str] = None                 # the answer (terminal), or
    tool: Optional[str] = None                  # a structured tool call
    args: Optional[Dict[str, Any]] = None
    usage: Optional[Usage] = None               # the provider call's token usage (metered into llm_usage when present)


class ToolResult(BaseModel):
    ok: bool
    output: str = ""
    error: str = ""


class LLMProvider(Protocol):
    def complete(self, system: str, messages: List[Message]) -> LLMResponse: ...
