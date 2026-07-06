"""ratelimit — fixed-window rate limiting. The dangerous property is that THE LIMIT HOLDS: at most LIMIT
requests per key per window, the (LIMIT+1)th is 429, and — the part naive limiters get wrong — the consume is
ONE atomic consume-or-deny read-modify-write through the store's `do` seam, so concurrent processes cannot race
past the limit (a get-then-put limiter is breachable under load; this one is not, proven by the invariant's
two-process attack). Windows are derived from the clock seam (deterministic under APP_TEST_CLOCK); the counter
is durable, so a restart never resets a window. LIMIT and WINDOW are env knobs."""
import os

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from ..core import clock, store
from ..core.errors import require_service, too_many
from ..parts.env_int import env_int
from ..parts.well_formed import WellFormedStr

router = APIRouter(prefix="/ratelimit", tags=["ratelimit"])

_LIMIT = env_int(os.getenv("RATELIMIT_LIMIT"), 5)      # requests allowed per key per window
_WINDOW = env_int(os.getenv("RATELIMIT_WINDOW"), 60)   # window length in seconds
# state in `store`: ns "ratelimit_windows" "<key>:<window_id>" -> count (one row per key per window; old windows
# simply stop being read — same names + model in all three languages)


class CheckIn(BaseModel):
    key: WellFormedStr   # the throttled identity (api key, ip, user) — the central well_formed rule


class Decision(BaseModel):
    allowed: bool
    remaining: int


@router.post("/check", response_model=Decision)
def check(data: CheckIn, request: Request, _service: str = Depends(require_service)) -> Decision:
    # mutation-auth: service — a server-side throttle PRIMITIVE, NOT a user action, so it is gated by the trusted
    # SERVICE seam (core.require_service), NOT require_identity: the throttle runs BEFORE the user is authenticated
    # (login brute-force protection throttles the username on the login attempt itself, pre-auth) and its subject
    # is the caller-supplied `data.key` (an ip/username/api-key) which the trusted service vouches for. Auth
    # resolves via Depends BEFORE the body's field validation, so an unauthenticated ill-typed body is 401 not 422,
    # The declaration and the require_service call sit in the same handler, so they cannot drift apart.
    window_id = clock.current(request) // _WINDOW
    # ATOMIC consume-or-deny: read the count and increment it in ONE exclusive transaction — two processes
    # racing the same key cannot both see count==LIMIT-1 and both pass. fn stays pure (no store calls inside).
    def consume(count):
        count = count or 0
        if count >= _LIMIT:
            return None, -1                      # deny: leave the row untouched
        return count + 1, _LIMIT - (count + 1)   # allow: one consumed, report what's left

    remaining = store.do("ratelimit_windows", f"{data.key}:{window_id}", consume)
    if remaining < 0:
        raise too_many("rate limit exceeded")
    return Decision(allowed=True, remaining=remaining)
