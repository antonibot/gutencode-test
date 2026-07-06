"""Runtime `clock` — the test-clock seam. A `now` query parameter is honored ONLY when APP_TEST_CLOCK=1
(deterministic test vectors and probes); in production the parameter is IGNORED and real time is used — a
client-controlled clock in prod is a replay/ratelimit-bypass hole, which is why this seam exists.
Mirrors go core.go:testNow and node runtime.js:testNow exactly."""
import os
import time

from fastapi import Request


def current(request: Request) -> int:
    if os.getenv("APP_TEST_CLOCK") == "1":
        raw = request.query_params.get("now", "0")
        try:
            v = int(raw)
        except ValueError:
            v = 0
        if v > 0:
            return v
    return int(time.time())
