"""The ONE provider-selection site — change AI_PROVIDER env, never a call site. HONESTY CONTRACT (identical
in go/node): the offline deterministic fake is the default, and the SHIPPED stdlib adapters (real.py) run a
recognized real provider — anthropic, openai — the moment its key env is set. A real name WITHOUT its key, or
any unknown value, is REFUSED per call with a 501 problem+json that names exactly what to set, NEVER a silent
fake completion under a real provider's name. Refused at CALL time (not boot), before the run loop touches
memory: every other route keeps working and a refused run leaves no trace."""
import os

from fastapi import HTTPException  # rendered by the core problem_handler -> the ONE problem+json envelope

from .. import config
from ..ports import LLMProvider
from .fake import FakeLLM
from .real import AnthropicLLM, OpenAILLM

# the SHIPPED real providers: name -> (key env, adapter). Adding a provider = one row + one adapter class.
_REAL_PROVIDERS = {"anthropic": ("ANTHROPIC_API_KEY", AnthropicLLM),
                   "openai": ("OPENAI_API_KEY", OpenAILLM)}


def get_provider() -> LLMProvider:
    which = config.provider_name()
    if which == "fake":
        return FakeLLM()
    # 501 Not Implemented — deliberate: not 503 (the missing key is not transient; retrying cannot succeed
    # until an operator sets one) and not a 4xx (the request is valid; the DEPLOYMENT lacks the capability).
    if which in _REAL_PROVIDERS:
        key_env, adapter = _REAL_PROVIDERS[which]
        if not os.environ.get(key_env):   # empty counts as unset (parity: go os.Getenv=="", node `!`)
            raise HTTPException(status_code=501,
                                detail=f"provider '{which}' needs {key_env} — see INTEROP.md")
        return adapter()
    raise HTTPException(status_code=501, detail=f"unknown provider '{which}' — see INTEROP.md")
