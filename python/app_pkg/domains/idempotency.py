"""idempotency — replay-safe writes per the IETF Idempotency-Key shape (the Stripe pattern). The dangerous
property is EXACTLY-ONCE: same key + same body returns the STORED response (the side effect never re-runs);
same key + a different body is a 409 (a reused key never silently bills a new amount); no key means no
deduplication (idempotency is opt-in, per the standard). The claim itself is ONE atomic read-modify-write
through the store's `do` seam — two processes racing the same key produce exactly one winner; the loser is
served the winner's stored response. The key table is durable: a replay still works after a restart."""
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, Field

from ..core import store
from ..core.errors import SafeInt, conflict, invalid, require_identity
from ..parts.digest import digest_hex, scoped_key
from ..parts.idempotent_claim import claim_once
from ..parts.well_formed import require_well_formed

router = APIRouter(prefix="/idempotency", tags=["idempotency"])
# state in `store`: seq "idempotency_payment" the side-effect counter · ns "idempotency_keys" SCOPED-key ->
# {id, amount, body_hash, caller} (the stored response · its body fingerprint · the OWNING caller; same names +
# shape ×3). The store key is SCOPED TO THE CALLER — _scoped_key(route, caller, idempotency_key) — so an
# Idempotency-Key is PRIVATE to its caller: caller B can never replay, nor be 409-blocked by, caller A's slot.

_ROUTE = "POST /idempotency/payments"   # the route discriminator — scope the slot to THIS operation, so a copier
# whose namespace serves >1 idempotent route can never collide a key across them (the per-route slot, GAP-6).


class PaymentIn(BaseModel):
    amount: Annotated[SafeInt, Field(ge=1)]   # a positive amount in minor units


class PaymentOut(BaseModel):
    id: int
    amount: int


def _digest(amount: int) -> str:
    # body_hash = the FULL request body fingerprint (here the one field `amount`) — the SAME-KEY-DIFFERENT-BODY guard,
    # kept SEPARATE from the lookup key. A copier whose body gains fields MUST add them here (else a changed field
    # silently replays the wrong response). The lookup key (below) is who-owns-the-slot; this is is-the-body-the-same.
    return digest_hex("amount", amount)   # the central canonical fingerprint (digest part)


@router.post("/payments", response_model=PaymentOut, status_code=201)
def pay(data: PaymentIn, request: Request, caller: str = Depends(require_identity),
        idempotency_key: Optional[str] = Header(default=None)) -> PaymentOut:
    # identity: the caller must be AUTHENTICATED (deny-by-default, no token -> 401), evaluated BEFORE any side
    # effect. The Idempotency-Key is a DEDUPE token, NOT identity — it is kept ON TOP of the authn requirement AND
    # the dedup slot is SCOPED TO THE CALLER (the key is private to its caller).
    if idempotency_key is None:                       # no key -> no dedupe; every request is a fresh side effect
        pid = store.next_id("idempotency_payment")
        return PaymentOut(id=pid, amount=data.amount)
    if len(request.headers.getlist("idempotency-key")) > 1:
        # an Idempotency-Key is a SINGLE opaque token; DUPLICATE headers are ambiguous (go takes the first, node would
        # comma-join) — REJECT them so the dedup behavior is deterministic + IDENTICAL ×3, never a silent slot divergence.
        raise invalid("Idempotency-Key must be a single value")
    require_well_formed(idempotency_key, "Idempotency-Key")   # a PRESENT key must be a well-formed identifier
    digest = _digest(data.amount)
    scoped = scoped_key(_ROUTE, caller, idempotency_key)     # the central caller-scoped, collision-safe slot (digest part)
    prior = store.get("idempotency_keys", scoped)            # fast path: a settled key never mints
    if prior is None:
        # mint BEFORE the claim (a race loser's id is a gap), then claim atomically via the central part
        rec = {"id": store.next_id("idempotency_payment"), "amount": data.amount, "body_hash": digest, "caller": caller}
        prior = claim_once("idempotency_keys", scoped, rec)
    if prior.get("caller") != caller:
        # DEFENSE-IN-DEPTH: the scoped key already isolates callers, so a stored-caller mismatch is structurally
        # impossible — but if it EVER happens (a hash collision / a scoping regression) we REFUSE, never cross-replay.
        raise conflict("idempotency key is not owned by this caller")
    if prior["body_hash"] != digest:
        raise conflict("idempotency key reused with a different body")
    return PaymentOut(id=prior["id"], amount=prior["amount"])   # first call and every replay: the SAME response
