"""CENTRAL env_int part — parse an integer from a RAW environment value the SAME way in python/go/node, with a
default and optional clamp bounds. A config knob (PBKDF2 iterations, a throttle window, a chunk size, a backoff cap)
must resolve IDENTICALLY in all three runtimes, but bare int()/strconv.Atoi()/parseInt() do NOT agree on the edges:
parseInt('5x')==5 in node but errors in py/go; Atoi(' 5 ') errors but int(' 5 ') strips; AND a value past 2**53-1
diverges (go's int64 vs node's float vs python's unbounded int). The caller passes the raw value (os.getenv /
os.Getenv / process.env[name]); this is the PURE parse+clamp. Rule: trim; an absent / empty /
non-integer value, OR one whose magnitude exceeds 2**53-1 (the cross-language-safe ceiling), -> the default; THEN
clamp by the optional bounds — env_int(raw, default) no clamp · env_int(raw, default, floor) clamp UP to floor ·
env_int(raw, default, lo, hi) clamp to [lo, hi]."""
import re

_INT = re.compile(r"[+-]?\d+")
_MAX_SAFE = 9007199254740991   # 2**53 - 1 (JS Number.MAX_SAFE_INTEGER) — the ×3-safe magnitude ceiling


def env_int(raw: str | None, default: int, *bounds: int) -> int:
    """raw is a raw env value (or None). Absent / empty / non-integer / |value| > 2**53-1 -> default; then clamp by
    0 bounds (none), 1 bound (floor), or 2 bounds (lo, hi)."""
    s = raw.strip() if raw is not None else ""
    v = default
    if _INT.fullmatch(s):
        n = int(s)
        if -_MAX_SAFE <= n <= _MAX_SAFE:
            v = n
    if len(bounds) >= 1:
        v = max(bounds[0], v)
    if len(bounds) >= 2:
        v = min(bounds[1], v)
    return v
