"""ai_provider — the unified LLM gateway: the ONE seam every caller uses for completions. The dangerous
property is BILLING HONESTY: the meter is CONSERVED (usage always equals the sum of every billed completion —
the update is one atomic read-modify-write through the `do` seam) and a cache replay is NEVER re-billed. Model
fallback degrades an unknown model to the default — never a 5xx. The offline fake is deterministic (output and
token counts are pure functions of model+prompt; tokens are utf-8 BYTE lengths, the ×3-identical semantic), so
it is the test oracle; SHIPPED stdlib adapters for Anthropic + OpenAI swap in behind the same response shape
(INTEROP.md): AI_PROVIDER=anthropic|openai with the matching key env set round-trips the REAL API per call —
stdlib HTTP only, env read at call time, one configured model per deployment (AI_MODEL or the provider
default), upstream non-2xx mapped to a LOUD 502 problem+json with a SANITIZED snippet (the key is never
echoed), timeout/network failure to 504, and a failed call is never billed and never cached.
HONESTY CONTRACT (identical ×3): AI_PROVIDER naming a real provider WITHOUT its key env — or any unknown
value — makes POST /ai/complete REFUSE per call with a 501 that says exactly what to set, NEVER silent fake
output under a real provider's name (GET /ai/usage —
the spend meter — keeps working: the failure stays local to completions, and a refusal is never billed or
cached). The cache key
comes from the digest part — never a hand-joined string (the rbac forgery lesson). Durable: the meter and the
cache survive a restart. AUTHN: POST /ai/complete requires identity — ANY authenticated caller (no/invalid
token -> 401); the meter stays a single global "total" key for now (the PER-SUBJECT meter + per-caller cache key
is a FOLLOW-ON data-model change, see INTEROP.md). GET /ai/usage (the aggregate meter) is ADMIN-ONLY
(the core require_admin seam): it is the GLOBAL spend metric across ALL callers — no token is 401, a non-admin is
403, resolved BEFORE the read, so the app's total AI spend can't leak to an anonymous or unprivileged caller."""
import json
import os
import urllib.error
import urllib.request
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, StrictStr, field_validator

from ..core import store
from ..core.errors import require_admin, require_identity
from ..parts.digest import digest_hex
from ..parts.env_int import env_int
from ..parts.well_formed import make_well_formed

router = APIRouter(prefix="/ai", tags=["ai_provider"])

_DEFAULT_MODEL = "fake"                      # the offline model-selection site
_MODELS = {"fake", "fast", "smart"}          # offline tiers; anything else FALLS BACK to the default
# the SHIPPED real providers (INTEROP.md): key env · default model · base-URL env + real endpoint. The base-URL
# override is both a proxy/gateway feature and the offline test seam (the invariant drives a loopback stub).
_KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}
_REAL_MODEL = {"anthropic": "claude-sonnet-4-6", "openai": "gpt-4o"}
_BASE_ENV = {"anthropic": "ANTHROPIC_BASE_URL", "openai": "OPENAI_BASE_URL"}
_BASE_DEFAULT = {"anthropic": "https://api.anthropic.com", "openai": "https://api.openai.com"}
_ANTHROPIC_VERSION = "2023-06-01"            # the Messages API version pin — a wire constant the API requires
_UPSTREAM_BODY_CAP = 1048576                 # bytes read of a provider response (a text completion is KBs)
_MAX_SAFE_TOKENS = 9007199254740991          # 2**53-1 — a reported token count past this bills 0, never overflows
# state in `store`: ns "ai_provider_meter" key "total" -> the running usage (atomic RMW) ·
# ns "ai_provider_cache" digest(model, prompt) -> the stored completion (same names + shape ×3 languages)


class CompleteIn(BaseModel):
    prompt: StrictStr
    model: Optional[StrictStr] = None

    @field_validator("prompt")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("must be non-empty")
        return value


def _select_provider() -> str:
    """HONESTY GATE (identical in go/node): returns which provider runs this call — 'fake' (the offline
    default) or a SHIPPED real adapter whose key env is set. A real name WITHOUT its key, or any unknown
    string, refuses LOUD with a 501 that names exactly what to set — never silent fake output. Checked per
    CALL (not at boot) and BEFORE the cache/meter, so the app stays usable (GET /ai/usage keeps working) and a
    refusal is never billed or cached. 501 Not Implemented — deliberate: not 503 (the missing key is not
    transient; retrying cannot succeed until an operator sets one) and not a 4xx (the request is valid; the
    DEPLOYMENT lacks the capability). Empty env counts as unset (parity: go EnvOr / node `||`)."""
    which = os.environ.get("AI_PROVIDER") or "fake"
    if which == "fake":
        return which
    if which in _KEY_ENV:
        if not os.environ.get(_KEY_ENV[which]):
            raise HTTPException(status_code=501,
                                detail=f"provider '{which}' needs {_KEY_ENV[which]} — see INTEROP.md")
        return which
    raise HTTPException(status_code=501, detail=f"unknown provider '{which}' — see INTEROP.md")


def _usage_int(value) -> int:
    """A provider-reported token count, contained: an integral number in [0, 2**53-1] bills as-is; anything
    else (absent, non-numeric, negative, fractional, absurd magnitude) bills 0 — the CONSERVED meter can never
    be poisoned or overflowed by an upstream payload. Identical decision in go/node."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    if isinstance(value, float) and not value.is_integer():
        return 0
    n = int(value)
    return n if 0 <= n <= _MAX_SAFE_TOKENS else 0


def _real_complete(which: str, model: str, prompt: str) -> dict:
    """The SHIPPED adapter (stdlib urllib only, no SDK): POST the provider's completion API, extract the text +
    real token usage into the gateway's response shape. Env is read per CALL (key, base URL, timeout, ceiling).
    Failure map (identical ×3): upstream non-2xx -> 502 problem+json carrying the status + a <=200-char body
    snippet with the key value REDACTED (never echo credentials, never dump headers); timeout / network /
    bad-endpoint -> 504; a 2xx whose body isn't the documented shape -> 502. A raised failure propagates BEFORE
    the cache write and the meter add, so it is never billed and never cached."""
    key = os.environ[_KEY_ENV[which]]                       # non-empty — _select_provider checked
    timeout = env_int(os.environ.get("AI_TIMEOUT_SECONDS"), 60, 1, 600)
    base = (os.environ.get(_BASE_ENV[which]) or _BASE_DEFAULT[which]).rstrip("/")
    if which == "anthropic":
        url = base + "/v1/messages"
        payload = {"model": model, "max_tokens": env_int(os.environ.get("AI_MAX_TOKENS"), 1024, 1),
                   "messages": [{"role": "user", "content": prompt}]}
        headers = {"content-type": "application/json", "x-api-key": key,
                   "anthropic-version": _ANTHROPIC_VERSION}
    else:
        url = base + "/v1/chat/completions"
        payload = {"model": model, "messages": [{"role": "user", "content": prompt}]}
        headers = {"content-type": "application/json", "Authorization": "Bearer " + key}
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
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
    shape = HTTPException(status_code=502, detail=f"provider '{which}' upstream error: unexpected response shape")
    if len(raw) > _UPSTREAM_BODY_CAP:
        raise shape
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
        if which == "anthropic":
            text = ""
            for block in data["content"]:                   # concatenate the text blocks (usually exactly one)
                if isinstance(block, dict) and block.get("type") == "text":
                    if not isinstance(block.get("text"), str):
                        raise TypeError("text block")
                    text += block["text"]
            usage = data.get("usage")
            usage = usage if isinstance(usage, dict) else {}
            p_tokens, c_tokens = _usage_int(usage.get("input_tokens")), _usage_int(usage.get("output_tokens"))
        else:
            text = data["choices"][0]["message"]["content"]
            usage = data.get("usage")
            usage = usage if isinstance(usage, dict) else {}
            p_tokens, c_tokens = _usage_int(usage.get("prompt_tokens")), _usage_int(usage.get("completion_tokens"))
        if not isinstance(text, str):
            raise TypeError("completion text")
    except (KeyError, IndexError, TypeError, ValueError):
        raise shape from None
    # contain the extracted text BEFORE it is cached/served: an upstream `\ud800` escape decodes to a lone
    # surrogate that would 5xx the response encode (go's decoder substitutes U+FFFD natively; node mirrors).
    # cost stays 0: token counts are the provider's real numbers, but no price table is baked in (prices move) —
    # wire your own pricing into the billed usage if you want money units in the meter.
    return {"model": model, "output": make_well_formed(text),
            "usage": {"prompt_tokens": p_tokens, "completion_tokens": c_tokens, "cost": 0}}


def _fake_complete(model: str, prompt: str) -> dict:
    # the deterministic offline completion: output + usage are pure functions of (model, prompt);
    # token counts are utf-8 BYTE lengths so all three languages agree on every payload
    p_tokens = len(prompt.encode("utf-8"))
    return {"model": model, "output": f"[{model}] " + prompt.upper(),
            "usage": {"prompt_tokens": p_tokens,
                      "completion_tokens": p_tokens + len(model.encode("utf-8")) + 3, "cost": 0}}


@router.post("/complete")
def complete(data: CompleteIn, caller: str = Depends(require_identity)) -> dict:
    # authenticated mutation — ANY authenticated caller (no/invalid token -> 401). The meter stays a single
    # global "total" key for now; the PER-SUBJECT meter + per-caller cache key (bill/quota the `caller`, scope
    # the cache by subject) is a documented FOLLOW-ON data-model change — see INTEROP.md.
    which = _select_provider()  # fail LOUD on a keyless/unknown AI_PROVIDER — never silent fake output
    if which == "fake":
        model = data.model if data.model in _MODELS else _DEFAULT_MODEL   # FALLBACK: unknown -> default, never a 5xx
    else:
        # a wired gateway serves ONE configured model per deployment (AI_MODEL, else the provider default), so
        # spend stays operator-controlled: the request `model` field is not a caller escalation channel — any
        # value falls back to the configured model (the same unknown->default doctrine as the offline tiers).
        model = os.environ.get("AI_MODEL") or _REAL_MODEL[which]
    key = digest_hex(model, data.prompt)
    prior = store.get("ai_provider_cache", key)
    if prior is not None:
        return {**prior, "cached": True}                  # a replay is served stored and NEVER re-billed
    result = _fake_complete(model, data.prompt) if which == "fake" else _real_complete(which, model, data.prompt)
    # rmw-safe: convergent-or-benign — the cache key is digest(model, prompt); the offline completion is
    # deterministic (identical concurrent writes), and a sampling real provider makes two concurrent misses a
    # benign last-write-wins cache fill (each real call WAS made and IS billed, so conservation still holds)
    store.put("ai_provider_cache", key, result)

    def bill(meter):
        meter = meter or {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0, "cost": 0}
        usage = result["usage"]
        return ({"requests": meter["requests"] + 1,
                 "prompt_tokens": meter["prompt_tokens"] + usage["prompt_tokens"],
                 "completion_tokens": meter["completion_tokens"] + usage["completion_tokens"],
                 "cost": meter["cost"] + usage["cost"]}, None)

    store.do("ai_provider_meter", "total", bill)          # CONSERVED: one atomic add per billed completion
    return {**result, "cached": False}


@router.get("/usage")
def usage(subject: str = Depends(require_admin)) -> dict:
    # ADMIN-ONLY: this is the GLOBAL usage meter (total requests/tokens/cost across ALL completions) — it exposes
    # the app's total AI spend, an operationally sensitive metric. The admin seam is authn -> authz BEFORE any read
    # (no token -> 401, a valid non-admin -> 403), identical ×3 with the secrets_vault admin-read idiom.
    meter = store.get("ai_provider_meter", "total")
    return meter or {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0, "cost": 0}
