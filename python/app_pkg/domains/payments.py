"""payments — a provider-agnostic payment-INTENT lifecycle (authorize · retrieve · capture/void/refund), with two
dangerous properties proven:
(1) EXACTLY-ONCE AUTHORIZATION: the intent id is DERIVED — id = scoped_key('POST /payments', caller, Idempotency-Key)
    — a caller-private, deterministic slot; the claim is ONE atomic read-modify-write through the store's `do` seam
    (via idempotent_claim), so two processes racing the same key authorize ONE intent (the loser is served the
    winner's stored intent). The same key with a DIFFERENT body is a 409 (a naive replay would silently re-authorize a
    different amount). The amount is CAPPED at 2^53-1 so the per-intent balance sums this domain will run can never
    overflow Go's int64 / lose Node's float precision (the money-conservation ×3 floor).
(2) OWNER ISOLATION: an intent belongs to its authorizing caller (the core require_identity seam). The store slot is
    the composite '<caller>\\x1f<id>', so a by-id GET for another caller's intent lands in a DIFFERENT slot -> 404,
    byte-indistinguishable from missing (existence never leaks across callers); the list is owner-FIELD-filtered.
Every route requires the AUTHENTICATED caller — an anonymous authorize is money fabrication; no token -> 401, ×3."""
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, Field, StrictInt

from ..core import store
from ..core.errors import conflict, invalid, not_found, require_identity
from ..parts.currency import is_currency
from ..parts.digest import digest_hex, scoped_key
from ..parts.idempotent_claim import claim_once
from ..parts.paginate import paginate
from ..parts.well_formed import WellFormedStr, require_well_formed

router = APIRouter(prefix="/payments", tags=["payments"])

_NS = "payments_intents"
_ROUTE = "POST /payments"   # the route discriminator — scope the derived id/slot to THIS operation
# the cross-language-safe amount ceiling: within JS's exact-integer range (2^53-1) AND well below int64, so the
# per-intent capture/refund SUMS (added in later waves) cannot overflow differently across python/go/node.
MAX_AMOUNT = (1 << 53) - 1
# state in `store`: ns "payments_intents" composite key "<caller>\x1f<id>" -> the intent record (field names ×3):
# {id, caller, status, amount, currency, amount_captured, amount_voided, amount_refunded, refunds, body_hash}.


class AuthorizeIn(BaseModel):
    amount: Annotated[StrictInt, Field(ge=1, le=MAX_AMOUNT)]   # positive minor units, capped (the overflow floor)
    currency: WellFormedStr                                    # an IDENTIFIER-grade code — the central well_formed rule


class CaptureIn(BaseModel):
    # the amount to capture, 1..authorized (full capture = the authorized amount). REQUIRED (not optional-default-full)
    # so the body parses + validates IDENTICALLY ×3 with no empty-body ambiguity; the remainder is auto-voided.
    amount: Annotated[StrictInt, Field(ge=1, le=MAX_AMOUNT)]


class RefundIn(BaseModel):
    amount: Annotated[StrictInt, Field(ge=1, le=MAX_AMOUNT)]   # the amount to refund (cumulative Σrefunds <= captured)


class PaymentOut(BaseModel):
    id: str
    status: str
    amount: int
    currency: str
    amount_captured: int
    amount_voided: int
    amount_refunded: int


def _out(rec) -> PaymentOut:
    # the PUBLIC projection — the internal caller/body_hash/refunds bookkeeping never leaves the store
    return PaymentOut(id=rec["id"], status=rec["status"], amount=rec["amount"], currency=rec["currency"],
                      amount_captured=rec["amount_captured"], amount_voided=rec["amount_voided"],
                      amount_refunded=rec["amount_refunded"])


def _digest(amount: int, currency: str) -> str:
    return digest_hex("amount", amount, "currency", currency)   # the central canonical body fingerprint (digest part)


def _id(value: str) -> str:
    return require_well_formed(value, "the payment id")          # the central handler-side identifier rule


@router.post("", response_model=PaymentOut, status_code=201)
def authorize(data: AuthorizeIn, request: Request, subject: str = Depends(require_identity),
              idempotency_key: Optional[str] = Header(default=None)) -> PaymentOut:
    # PRECEDENCE (×3): the body PARSE (pydantic 422) precedes the dependency; require_identity (401) precedes the
    # SEMANTIC checks below — so a malformed body is 422, a no-token caller is 401, and a no-token + bad-semantic
    # caller is 401 (auth before semantic), identical to go's decode->auth->validate order.
    if not is_currency(data.currency):                # SEMANTIC: a CLOSED ISO-4217 set, not just well-formed
        raise invalid("currency must be a valid ISO-4217 code")
    if idempotency_key is None:                       # REQUIRED: the intent id is DERIVED from the key (no key, no id)
        raise invalid("Idempotency-Key header is required")
    if len(request.headers.getlist("idempotency-key")) > 1:
        # a SINGLE opaque token; duplicate headers are ambiguous (go takes the first, node comma-joins) -> reject ×3
        raise invalid("Idempotency-Key must be a single value")
    require_well_formed(idempotency_key, "Idempotency-Key")
    body_hash = _digest(data.amount, data.currency)
    pi_id = scoped_key(_ROUTE, subject, idempotency_key)   # the deterministic, caller-private intent id
    slot = f"{subject}\x1f{pi_id}"                          # the owner-composite store slot (cross-caller -> 404)
    prior = store.get(_NS, slot)                           # fast path: a settled key never re-authorizes
    if prior is None:
        rec = {"id": pi_id, "caller": subject, "status": "authorized", "amount": data.amount,
               "currency": data.currency, "amount_captured": 0, "amount_voided": 0, "amount_refunded": 0,
               "refunds": [], "body_hash": body_hash}
        prior = claim_once(_NS, slot, rec)                 # ONE atomic claim per slot (no double-authorize under a race)
    if prior.get("caller") != subject:
        # DEFENSE-IN-DEPTH: the composite slot already isolates callers, so this is structurally impossible — but if it
        # EVER happens (a hash collision / a scoping regression) we REFUSE, never serve another caller's intent.
        raise conflict("idempotency key is not owned by this caller")
    if prior["body_hash"] != body_hash:
        raise conflict("idempotency key reused with a different body")
    return _out(prior)


@router.get("")
def list_payments(limit: str = "", cursor: str = "", subject: str = Depends(require_identity)) -> dict:
    # SCOPED read: only the caller's OWN intents (owner-FIELD-filtered — the comparison runs on the STORED owner
    # field, never a client value), then a BOUNDED page over that stable-ordered set via the shared paginate part.
    mine = [r for r in store.values(_NS) if r.get("caller") == subject]
    page, nxt, ok = paginate(mine, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": [_out(r).model_dump() for r in page], "next_cursor": nxt}


@router.get("/{payment_id}", response_model=PaymentOut)
def get_payment(payment_id: str, subject: str = Depends(require_identity)) -> PaymentOut:
    rec = store.get(_NS, f"{subject}\x1f{_id(payment_id)}")
    if rec is None:
        raise not_found("payment")   # not-yours == not-found: another caller's intent is under a different slot
    return _out(rec)


# ── the lifecycle TRANSITIONS — each is ONE atomic read-modify-write through the `do` seam. The state read,
# the conservation check, and the write ALL happen INSIDE the callback against `cur` (NEVER a value read before the
# do() — the latent-RMW class no gate catches), so two processes racing a transition serialize on the slot's write
# lock and the loser sees the already-transitioned intent (no double-capture / void-after-capture race). ───────────


@router.post("/{payment_id}/capture", response_model=PaymentOut)
def capture(payment_id: str, data: CaptureIn, subject: str = Depends(require_identity)) -> PaymentOut:
    outcome: dict = {"code": 0, "rec": None}

    def fn(cur):
        if cur is None:
            outcome["code"] = 404
            return None, None
        if cur["status"] != "authorized":                     # capture-after-capture / after-void -> 409
            outcome["code"] = 409
            return None, None
        if data.amount > cur["amount"]:                       # over-capture (>= 1 enforced by the model) -> 422
            outcome["code"] = 422
            return None, None
        nxt = dict(cur)
        nxt["status"] = "captured"
        nxt["amount_captured"] = data.amount
        nxt["amount_voided"] = cur["amount"] - data.amount    # CONSERVATION: the uncaptured remainder is released
        outcome["rec"] = nxt
        return nxt, None

    store.do(_NS, f"{subject}\x1f{_id(payment_id)}", fn)
    if outcome["code"] == 404:
        raise not_found("payment")
    if outcome["code"] == 409:
        raise conflict("payment is not in the authorized state")
    if outcome["code"] == 422:
        raise invalid("capture amount must not exceed the authorized amount")
    return _out(outcome["rec"])


@router.post("/{payment_id}/void", response_model=PaymentOut)
def void_payment(payment_id: str, subject: str = Depends(require_identity)) -> PaymentOut:
    outcome: dict = {"code": 0, "rec": None}

    def fn(cur):
        if cur is None:
            outcome["code"] = 404
            return None, None
        if cur["status"] != "authorized":                     # void-after-capture / double-void -> 409
            outcome["code"] = 409
            return None, None
        nxt = dict(cur)
        nxt["status"] = "voided"
        nxt["amount_voided"] = cur["amount"]                  # CONSERVATION: the full authorization is released
        outcome["rec"] = nxt
        return nxt, None

    store.do(_NS, f"{subject}\x1f{_id(payment_id)}", fn)
    if outcome["code"] == 404:
        raise not_found("payment")
    if outcome["code"] == 409:
        raise conflict("payment is not in the authorized state")
    return _out(outcome["rec"])


@router.post("/{payment_id}/refund", response_model=PaymentOut)
def refund(payment_id: str, data: RefundIn, request: Request, subject: str = Depends(require_identity),
           idempotency_key: Optional[str] = Header(default=None)) -> PaymentOut:
    # a refund is idempotent on its Idempotency-Key (a retried refund must NOT double-refund), so it carries one — UNLIKE
    # capture/void, which are one-time transitions idempotent by the status check. The dedup scan + the conservation
    # check + the append ALL happen inside the ONE do() callback (never a pre-read), so a racing retry sees the
    # already-recorded refund and a racing over-refund is refused (the cross-process I-RACE-REFUND wall). The
    # Idempotency-Key is scoped BY CONSTRUCTION to the owner-composite intent slot — a cross-caller refund 404s before
    # the key is ever consulted, so the raw key is private to (caller, intent) without a separate scoped slot.
    if idempotency_key is None:
        raise invalid("Idempotency-Key header is required")
    if len(request.headers.getlist("idempotency-key")) > 1:
        raise invalid("Idempotency-Key must be a single value")
    require_well_formed(idempotency_key, "Idempotency-Key")
    outcome: dict = {"code": 0, "detail": "", "rec": None}

    def fn(cur):
        if cur is None:
            outcome["code"] = 404
            return None, None
        if cur["status"] != "captured":                       # refund-before-capture / after-void -> 409
            outcome["code"] = 409
            outcome["detail"] = "payment must be captured before it can be refunded"
            return None, None
        for r in cur["refunds"]:                              # idempotent: a settled refund key returns the stored intent
            if r["key"] == idempotency_key:
                if r["amount"] != data.amount:
                    outcome["code"] = 409
                    outcome["detail"] = "idempotency key reused with a different refund amount"
                    return None, None
                outcome["rec"] = cur                          # same key + amount -> the unchanged intent (no double-refund)
                return None, None
        if sum(r["amount"] for r in cur["refunds"]) + data.amount > cur["amount_captured"]:   # over-refund -> 422
            outcome["code"] = 422
            return None, None
        nxt = dict(cur)
        nxt["refunds"] = cur["refunds"] + [{"key": idempotency_key, "amount": data.amount}]
        nxt["amount_refunded"] = cur["amount_refunded"] + data.amount   # CONSERVATION: Σrefunds <= captured
        outcome["rec"] = nxt
        return nxt, None

    store.do(_NS, f"{subject}\x1f{_id(payment_id)}", fn)
    if outcome["code"] == 404:
        raise not_found("payment")
    if outcome["code"] == 409:
        raise conflict(outcome["detail"])
    if outcome["code"] == 422:
        raise invalid("refund amount would exceed the captured amount")
    return _out(outcome["rec"])
