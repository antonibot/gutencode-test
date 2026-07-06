"""stripe — Stripe-shape payments with two dangerous properties, both proven:
(1) NO DOUBLE-CHARGE: charge creation is idempotent on the Idempotency-Key; the claim is ONE atomic
    read-modify-write through the store's `do` seam, so two processes racing the same key produce one charge
    and the loser is served the winner's stored response. Key reuse with a DIFFERENT body is a 409 (real
    Stripe behavior; a naive replay would silently charge a different amount).
(2) ONLY STRIPE CAN SPEAK: the webhook verifies 'Stripe-Signature: t=<ts>,v1=<hex>' — HMAC-SHA256 over the RAW
    request bytes via the central signing part, inside a replay window from the clock seam. A tampered payload,
    a forged signature, or a stale timestamp is a 400, deny-by-default.
The endpoint secret is env-backed and rotatable. Charges are durable: a replay works after a restart.

TWO routes, TWO auth models: POST /charges is the server-side charge-creation API, so it requires the
AUTHENTICATED caller (the core require_identity seam) — anonymous today is charge fabrication + idempotency-key
griefing; no token 401, ×3. POST /webhook is authed by the Stripe HMAC, NOT a session (see its
`mutation-auth: signature` declaration)."""
import os
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, Field

from ..core import clock, store
from ..core.errors import SafeInt, bad_request, conflict, invalid, require_identity
from ..parts.currency import is_currency
from ..parts.digest import digest_hex, scoped_key
from ..parts.idempotent_claim import claim_once
from ..parts.signing import stripe_verify
from ..parts.well_formed import WellFormedStr, require_well_formed

router = APIRouter(prefix="/stripe", tags=["stripe"])

# one or more ACTIVE endpoint secrets (comma-separated) — verify against EACH so a secret can be rotated with ZERO
# downtime (Stripe sends one v1 per active secret during a roll). Empty entries are DROPPED — an empty secret would be
# a forgeable empty-key HMAC; no secret configured -> the list is empty -> every webhook is denied (deny-by-default).
# os.getenv returns the demo default only when UNSET; a present-but-BLANK value returns "" -> [] -> deny (never the
# public placeholder) — so blanking the env to disable the endpoint can't leave it open (×3-identical with go/node).
_SECRETS = [s.strip() for s in os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_demo_change_me").split(",") if s.strip()]
_TOLERANCE = 300                                                       # seconds; the signature replay window
_ROUTE = "POST /stripe/charges"   # the route discriminator — scope the dedup slot to THIS operation (per-route slot)
# state in `store`: seq "stripe_charge" the charge counter · ns "stripe_charges" SCOPED-key ->
# {id, amount, currency, status, body_hash, caller} (the stored response + body fingerprint + the OWNING caller;
# same names ×3 languages). The store key is SCOPED TO THE CALLER via scoped_key — an Idempotency-Key is PRIVATE to
# its caller: caller B can never replay, nor be 409-griefed by, caller A's slot.


class ChargeIn(BaseModel):
    amount: Annotated[SafeInt, Field(ge=1)]   # a positive amount in minor units
    currency: WellFormedStr                     # an IDENTIFIER-grade code — the central well_formed rule


class ChargeOut(BaseModel):
    id: str
    amount: int
    currency: str
    status: str


def _digest(amount: int, currency: str) -> str:
    return digest_hex("amount", amount, "currency", currency)   # the central canonical fingerprint (digest part)


@router.post("/charges", response_model=ChargeOut, status_code=201)
def charge(data: ChargeIn, request: Request, subject: str = Depends(require_identity),
           idempotency_key: Optional[str] = Header(default=None)) -> ChargeOut:
    # require_identity: the server-side charge API is for an AUTHENTICATED caller — anonymous is charge
    # fabrication + idempotency-key griefing. FastAPI orders the body parse (413/422) before the dependency, so a
    # malformed body is 422 and a no-token caller is 401, identical to go's decode-then-auth precedence ×3.
    if not is_currency(data.currency):                # SEMANTIC (post-auth): a CLOSED ISO-4217 set, not just well-formed
        raise invalid("currency must be a valid ISO-4217 code")
    if idempotency_key is None:                       # no key -> no dedupe (opt-in, per the standard)
        cid = store.next_id("stripe_charge")
        return ChargeOut(id=f"ch_{cid}", amount=data.amount, currency=data.currency, status="succeeded")
    if len(request.headers.getlist("idempotency-key")) > 1:
        # an Idempotency-Key is a SINGLE opaque token; DUPLICATE headers are ambiguous (go takes the first, node
        # comma-joins) — REJECT them so the dedup slot is deterministic + IDENTICAL ×3, never a silent divergence.
        raise invalid("Idempotency-Key must be a single value")
    require_well_formed(idempotency_key, "Idempotency-Key")
    digest = _digest(data.amount, data.currency)
    scoped = scoped_key(_ROUTE, subject, idempotency_key)   # caller-scoped, collision-safe slot
    prior = store.get("stripe_charges", scoped)             # fast path: a settled key never mints
    if prior is None:
        # mint BEFORE the claim (a race loser's id is a gap), then charge once per key via the central part
        cid = store.next_id("stripe_charge")
        rec = {"id": f"ch_{cid}", "amount": data.amount, "currency": data.currency,
               "status": "succeeded", "body_hash": digest, "caller": subject}
        prior = claim_once("stripe_charges", scoped, rec)
    if prior.get("caller") != subject:
        # DEFENSE-IN-DEPTH: the scoped slot already isolates callers, so a stored-caller mismatch is structurally
        # impossible — but if it EVER happens (a hash collision / a scoping regression) we REFUSE, never cross-replay.
        raise conflict("idempotency key is not owned by this caller")
    if prior["body_hash"] != digest:
        raise conflict("idempotency key reused with a different body")
    return ChargeOut(id=prior["id"], amount=prior["amount"], currency=prior["currency"], status=prior["status"])


@router.post("/webhook")
async def webhook(request: Request, stripe_signature: Optional[str] = Header(default=None)) -> dict:
    # mutation-auth: signature — INTENTIONALLY not require_identity. This route is authenticated by the Stripe HMAC
    # over the RAW request body (verified below via the central signing part), NOT by a session: Stripe sends no
    # bearer token, so require_identity would reject every real delivery with a 401. The signature IS the identity —
    # only the holder of the endpoint secret can produce a valid 'Stripe-Signature', deny-by-default.
    if stripe_signature is None:
        raise invalid("Stripe-Signature header is required")
    raw = (await request.body()).decode()             # the EXACT event bytes — Stripe signs the raw body
    now = clock.current(request)
    if not any(stripe_verify(s, stripe_signature, raw, now, _TOLERANCE) for s in _SECRETS):
        raise bad_request("invalid signature")        # tampered / forged / stale / no active secret -> reject
    return {"received": True}
