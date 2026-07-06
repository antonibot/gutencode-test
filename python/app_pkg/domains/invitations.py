"""invitations — invite + accept with single-use, expiring tokens. The dangerous property is ACCEPT-AT-MOST-
ONCE-AND-NEVER-EXPIRED: the token is server-minted and unguessable; accepting is an atomic single-use consume
through the `do` seam (two processes racing one token yield one acceptance + one 409), and expiry beats
availability — an expired token is 410 even if never used. The expiry is computed from the test-clock seam, so
it is deterministic under APP_TEST_CLOCK. Tokens are durable; a pending invite survives a restart.

TWO routes, TWO auth models: POST /invitations (create) requires identity (the core require_identity seam) and
STAMPS the inviter = the authenticated caller, derived from the bearer token and NEVER a client-supplied body field
(a smuggled `inviter` is ignored), so a no-token caller is 401 — identical ×3. POST /{token}/accept is intentionally
PUBLIC (see its `mutation-auth: public` declaration): the 192-bit single-use capability token IS the credential, so
requiring a session would break logged-out invitees."""
import os
import secrets
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, StrictInt

from ..core import clock, store
from ..core.errors import conflict, gone, not_found, require_identity
from ..parts.env_int import env_int
from ..parts.well_formed import WellFormedStr, require_well_formed

router = APIRouter(prefix="/invitations", tags=["invitations"])

_DEFAULT_TTL = env_int(os.getenv("INVITATIONS_TTL"), 604800)   # 7 days
# state in `store`: ns "invitations_tokens" token -> {token, email, inviter, status, expires_at} (×3 identical)


class InviteIn(BaseModel):
    email: WellFormedStr
    ttl: Optional[Annotated[StrictInt, Field(ge=1, le=31536000)]] = None


@router.post("", status_code=201)
def create(data: InviteIn, request: Request, inviter: str = Depends(require_identity)) -> dict:
    # authenticated mutation (no/invalid token -> 401). The inviter is the AUTHENTICATED subject, derived from
    # the token — never a client-supplied body field — so a smuggled `inviter` cannot override it.
    now = clock.current(request)
    ttl = data.ttl if data.ttl is not None else _DEFAULT_TTL
    token = secrets.token_urlsafe(24)                  # unguessable, server-side — never client-set
    rec = {"token": token, "email": data.email, "inviter": inviter, "status": "pending", "expires_at": now + ttl}
    store.put("invitations_tokens", token, rec)
    return rec


@router.post("/{token}/accept")
def accept(token: str, request: Request) -> dict:
    # mutation-auth: public — INTENTIONALLY unauthenticated. The 192-bit single-use capability token IS the
    # credential: accept consumes a token a recipient already holds (typically while logged OUT), so requiring a
    # session would break the invite flow. The token's secrecy + single-use/expiry are the authorization.
    require_well_formed(token, "the token")
    now = clock.current(request)
    outcome = {}

    def consume(rec):
        if rec is None:
            return None, "unknown"
        if now > rec["expires_at"]:
            return None, "expired"                     # expiry beats availability — even a pending token is gone
        if rec["status"] == "accepted":
            return None, "used"
        accepted = {**rec, "status": "accepted"}
        outcome["rec"] = accepted
        return accepted, "ok"                          # atomic single-use: the FIRST accept wins

    result = store.do("invitations_tokens", token, consume)
    if result == "unknown":
        raise not_found("invitation")
    if result == "expired":
        raise gone("invitation expired")
    if result == "used":
        raise conflict("invitation already accepted")
    return outcome["rec"]
