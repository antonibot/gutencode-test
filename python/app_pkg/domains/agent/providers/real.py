"""The SHIPPED real-provider adapters (stdlib urllib only, no SDK): Anthropic Messages + OpenAI Chat
Completions behind the SAME port as the offline fake. Env is read per CALL (AI_MODEL · AI_TIMEOUT_SECONDS ·
AI_MAX_TOKENS · the base-URL overrides — the base URL is both a proxy/gateway feature and the offline test
seam), the conversation arrives already bounded (ring-buffered history, truncated messages), and the adapter
returns ONE final text — provider-native tool-use and token streaming are deliberately not mapped (the run
loop's tools stay local; the SSE mode chunks the final output at the transport). Failure map (identical in
go/node): upstream non-2xx -> 502 problem+json carrying the status + a <=200-char body snippet with the key
value REDACTED (credentials are never echoed, headers never dumped); timeout / network / bad endpoint -> 504;
a 2xx that isn't the documented shape -> 502. The adapter never fabricates a completion."""
import json
import os
import urllib.error
import urllib.request
from typing import List

from fastapi import HTTPException

from ....parts.env_int import env_int
from ..ports import LLMResponse, Message, Usage

_ANTHROPIC_VERSION = "2023-06-01"   # the Messages API version pin — a wire constant the API requires
_UPSTREAM_BODY_CAP = 1048576        # bytes read of a provider response (a text completion is KBs)


def _u(usage: dict, key: str) -> int:
    # a provider-reported token count, defensively coerced: a real non-negative int or 0 (a missing/odd field never
    # crashes the run — the usage is best-effort spend attribution, never the run's correctness).
    v = usage.get(key)
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


def _merged_turns(messages: List[Message]) -> list:
    """Map the port's roles onto provider wire roles: tool observations become user turns (the minimal-adapter
    doctrine — the model sees the observation as conversation), then consecutive same-role turns merge
    (newline-joined) so the wire alternates user/assistant cleanly. Identical mapping in go/node."""
    turns = []
    for m in messages:
        role = "assistant" if m.role == "assistant" else "user"
        if turns and turns[-1]["role"] == role:
            turns[-1]["content"] += "\n" + m.content
        else:
            turns.append({"role": role, "content": m.content})
    return turns


def _shape_error(which: str) -> HTTPException:
    return HTTPException(status_code=502, detail=f"provider '{which}' upstream error: unexpected response shape")


def _post_json(which: str, url: str, headers: dict, payload: dict, key: str) -> dict:
    """POST a JSON body, return the parsed JSON response — or raise the mapped 502/504 (see the module doc)."""
    timeout = env_int(os.environ.get("AI_TIMEOUT_SECONDS"), 60, 1, 600)
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                 headers={"content-type": "application/json", **headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(_UPSTREAM_BODY_CAP + 1)
    except urllib.error.HTTPError as e:                     # non-2xx: loud + sanitized, never invented text
        body = e.read(4096).decode("utf-8", "replace")
        snippet = (body.replace(key, "[redacted]") if key else body)[:200]
        raise HTTPException(status_code=502,
                            detail=f"provider '{which}' upstream error (HTTP {e.code}): {snippet}") from None
    except (OSError, ValueError):                           # timeout, refused, DNS, malformed base URL
        raise HTTPException(status_code=504,
                            detail=f"provider '{which}' upstream timeout or network failure") from None
    if len(raw) > _UPSTREAM_BODY_CAP:
        raise _shape_error(which)
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        raise _shape_error(which) from None


class AnthropicLLM:
    """POST {ANTHROPIC_BASE_URL}/v1/messages — x-api-key auth, the system prompt as the top-level `system`
    field, the merged conversation as `messages`; the concatenated text blocks come back as the final answer.
    A lone-surrogate escape in the answer is contained downstream (the run loop well-forms every output)."""

    def complete(self, system: str, messages: List[Message]) -> LLMResponse:
        key = os.environ["ANTHROPIC_API_KEY"]               # non-empty — the selection site checked
        base = (os.environ.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com").rstrip("/")
        model = os.environ.get("AI_MODEL") or "claude-sonnet-4-6"
        payload = {"model": model, "max_tokens": env_int(os.environ.get("AI_MAX_TOKENS"), 1024, 1),
                   "messages": _merged_turns(messages)}
        if system:
            payload["system"] = system
        data = _post_json("anthropic", base + "/v1/messages",
                          {"x-api-key": key, "anthropic-version": _ANTHROPIC_VERSION}, payload, key)
        try:
            text = ""                                       # concatenate the text blocks (usually exactly one)
            for block in data["content"]:
                if isinstance(block, dict) and block.get("type") == "text":
                    if not isinstance(block.get("text"), str):
                        raise TypeError("text block")
                    text += block["text"]
        except (KeyError, TypeError):
            raise _shape_error("anthropic") from None
        u = data.get("usage")                               # the provider's reported spend (metered into llm_usage)
        usage = None
        if isinstance(u, dict):
            usage = Usage(identifier=data.get("id") if isinstance(data.get("id"), str) else None, model=model,
                          input_tokens=_u(u, "input_tokens"), output_tokens=_u(u, "output_tokens"),
                          cache_read_input_tokens=_u(u, "cache_read_input_tokens"),
                          cache_creation_input_tokens=_u(u, "cache_creation_input_tokens"))
        return LLMResponse(final=text, usage=usage)


class OpenAILLM:
    """POST {OPENAI_BASE_URL}/v1/chat/completions — Bearer auth, the system prompt riding as the first
    message; `choices[0].message.content` comes back as the final answer."""

    def complete(self, system: str, messages: List[Message]) -> LLMResponse:
        key = os.environ["OPENAI_API_KEY"]                  # non-empty — the selection site checked
        base = (os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com").rstrip("/")
        model = os.environ.get("AI_MODEL") or "gpt-4o"
        turns = _merged_turns(messages)
        if system:
            turns = [{"role": "system", "content": system}] + turns
        payload = {"model": model, "messages": turns}
        data = _post_json("openai", base + "/v1/chat/completions",
                          {"Authorization": "Bearer " + key}, payload, key)
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise _shape_error("openai") from None
        if not isinstance(text, str):
            raise _shape_error("openai")
        u = data.get("usage")                               # openai reports prompt/completion tokens (metered into llm_usage)
        usage = None
        if isinstance(u, dict):
            usage = Usage(identifier=data.get("id") if isinstance(data.get("id"), str) else None, model=model,
                          input_tokens=_u(u, "prompt_tokens"), output_tokens=_u(u, "completion_tokens"))
        return LLMResponse(final=text, usage=usage)
