"""Provider selection + the loop budget, from env (12-factor — every knob is in .env.example). Change env, not code."""
import os

from ...parts.env_int import env_int

def provider_name() -> str:
    """AI_PROVIDER, read at CALL time (go/node read env per run too — same read-time in all three languages), so
    provider selection — and the loud refusal of an unwired provider — always reflects the CURRENT environment.
    Empty counts as unset (parity: go EnvOr and node `||` treat '' as the default). fake = the offline default."""
    return os.environ.get("AI_PROVIDER") or "fake"


def meter_fake() -> bool:
    """AI_USAGE_METER_FAKE — arm usage metering for the offline fake provider. Default off, so the fake stays free and
    the bar stays INERT by default (real providers always meter). Read at CALL time (parity with provider_name)."""
    return os.environ.get("AI_USAGE_METER_FAKE") == "1"


_mi = env_int(os.environ.get("AGENT_MAX_ITERATIONS"), 6)
MAX_ITERATIONS = _mi if _mi >= 1 else 6                              # the run-loop terminate guard (sub-1 -> default)
# the per-session conversation buffer is RING-BUFFERED to the last HISTORY_MAX messages (drop-oldest on append) — an
# unbounded history is an O(n^2)-RMW / OOM / cost soft-DoS (every append re-serializes the whole blob, every turn feeds
# it all to the provider). The bounded buffer is the letta/Assistants model; long-term archival is a deploy concern.
# MUST be >= MAX_ITERATIONS + 2 (a single run's footprint) so a run never evicts its own user turn mid-loop.
HISTORY_MAX = max(MAX_ITERATIONS + 2, env_int(os.environ.get("AGENT_HISTORY_MAX"), 200))
# each stored message is MIDDLE-truncated to MSG_MAX CODE POINTS (head + marker + tail) — a giant tool observation or
# user input would otherwise flood the buffer + the next prompt unbounded (smolagents caps tool output the same way).
# Codepoints, not bytes/UTF-16, so the cap is IDENTICAL ×3 (python len / go RuneCountInString / node [...s].length).
MSG_MAX = max(64, env_int(os.environ.get("AGENT_MAX_MSG_CHARS"), 4000))
# the SSE delta window: a streamed run response chops the FINAL output into fixed CODE-POINT chunks at the
# transport (the run loop itself is untouched — sync and stream derive from the same result). Codepoints, like
# MSG_MAX, so the frame sequence is IDENTICAL ×3 (a byte window would split a multibyte character differently
# per language). Sub-1 -> the default, same guard shape as MAX_ITERATIONS.
_sc = env_int(os.environ.get("SSE_CHUNK_CODEPOINTS"), 12)
SSE_CHUNK = _sc if _sc >= 1 else 12
