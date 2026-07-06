"""The deterministic provider — the default AND the test oracle (the whole stack runs offline, no keys).
Protocol: 'use <tool> <args>' -> a STRUCTURED tool call · a tool observation -> 'answer: <obs>' ·
'use forever …' -> NEVER finalizes (exists so the iteration guard is provable black-box) · else '[fake] <input>'."""
from typing import List

from ..ports import LLMResponse, Message, Usage


def _usage() -> Usage:
    # deterministic NONZERO counts so the metering wire is provable offline (armed via AI_USAGE_METER_FAKE); model
    # "fake" is priced at zero in the meter's table (an explicit priced-at-zero row, not a silent $0). Same counts ×3.
    return Usage(model="fake", input_tokens=3, output_tokens=5)


class FakeLLM:
    def complete(self, system: str, messages: List[Message]) -> LLMResponse:
        last = messages[-1]
        user_inputs = [m for m in messages if m.role == "user"]
        run_input = user_inputs[-1].content if user_inputs else ""
        if run_input.startswith("use forever"):              # the runaway simulator: always another tool call
            return LLMResponse(tool="echo", args={"text": "again"}, usage=_usage())
        if last.role == "tool":                              # we observed a tool result -> finalize
            return LLMResponse(final=f"answer: {last.content}", usage=_usage())
        if last.content.startswith("use "):                  # 'use calc 2+2' -> structured args for that tool
            rest = last.content[4:].split(" ", 1)
            tool = rest[0]
            value = rest[1] if len(rest) > 1 else ""
            args = {"expr": value} if tool == "calc" else {"text": value}
            return LLMResponse(tool=tool, args=args, usage=_usage())
        return LLMResponse(final=f"[fake] {last.content}", usage=_usage())
