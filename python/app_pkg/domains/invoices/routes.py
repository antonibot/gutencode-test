"""invoices — a CONSERVED multi-line bill (create-draft · retrieve · edit-draft · finalize · pay/void/uncollectible).
Two dangerous properties are proven here:
(1) CONSERVATION: the server RECOMPUTES every total — line amount = unit_amount × quantity, subtotal = Σ line
    amounts, total = subtotal + tax — and DISCARDS any client-supplied total, so a stored bill ALWAYS reconciles to
    its lines + tax (a client can never post a $0 total over $1000 of lines). Every amount is capped at 2^53-1 and the
    per-line PRODUCT is bounded BEFORE the multiply (Go's int64 would WRAP silently past 2^63), as is the running
    subtotal/total, so the sums this domain runs cannot diverge across python/go/node — the money-conservation ×3 floor.
(2) OWNER ISOLATION: a bill belongs to its creating caller (the core require_identity seam). The store slot is the
    composite '<caller>\\x1f<id>', so a by-id GET for another caller's bill lands in a DIFFERENT slot -> 404,
    byte-indistinguishable from missing; the list is owner-FIELD-filtered.
Every route requires the AUTHENTICATED caller — an anonymous create is bill fabrication; no token -> 401, ×3.
The id is DERIVED — id = scoped_key('POST /invoices', caller, Idempotency-Key) — a caller-private deterministic slot
claimed via ONE atomic read-modify-write (idempotent_claim), so two processes racing the same key create ONE draft
(the loser is served the winner's). The same key with a DIFFERENT body is a 409. Echoed text (the customer handle, line
descriptions) is run through make_well_formed so a lone surrogate can never crash response/store serialization. The line list is COUNT-bounded."""
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, Field, StrictInt

from ...core import clock, store
from ...core.errors import conflict, invalid, not_found, require_identity
from ...parts.currency import is_currency
from ...parts.digest import digest_hex, scoped_key
from ...parts.idempotent_claim import claim_once
from ...parts.paginate import paginate
from ...parts.well_formed import WellFormedStr, make_well_formed, require_well_formed

router = APIRouter(prefix="/invoices", tags=["invoices"])

_NS = "invoices_records"
_ROUTE = "POST /invoices"          # the route discriminator — scope the derived id/slot to THIS operation
MAX_AMOUNT = (1 << 53) - 1         # the cross-language-safe ceiling: sums below it can't wrap int64 / lose float precision
MAX_LINES = 1000                   # a single bill's line list is COUNT-bounded (no unbounded record growth)
# state in `store`: ns "invoices_records" composite key "<caller>\x1f<id>" -> the bill record (field names ×3):
# {id, caller, customer, status, currency, line_items:[{description,quantity,unit_amount,amount}], subtotal, tax,
#  total, amount_paid, number, finalized_at, body_hash}.


class LineIn(BaseModel):
    description: WellFormedStr                                       # human text, no control chars, <=1024 cp (well_formed)
    quantity: Annotated[StrictInt, Field(ge=1, le=MAX_AMOUNT)]      # positive count, capped (the per-line product floor)
    unit_amount: Annotated[StrictInt, Field(ge=1, le=MAX_AMOUNT)]   # positive minor units, capped


class CreateInvoiceIn(BaseModel):
    customer: WellFormedStr                                         # the bill's customer handle (well-formed, echoed back)
    currency: WellFormedStr                                         # an IDENTIFIER-grade code — validated to ISO-4217 below
    tax: Annotated[StrictInt, Field(ge=0, le=MAX_AMOUNT)]          # the tax amount in minor units (0 allowed)
    line_items: Annotated[list[LineIn], Field(min_length=1, max_length=MAX_LINES)]   # >=1 line, COUNT-bounded


class LineOut(BaseModel):
    description: str
    quantity: int
    unit_amount: int
    amount: int


class InvoiceOut(BaseModel):
    id: str
    number: Optional[str]
    customer: str
    status: str
    currency: str
    line_items: list[LineOut]
    subtotal: int
    tax: int
    total: int
    amount_paid: int


def _out(rec) -> InvoiceOut:
    # the PUBLIC projection — the internal caller/body_hash/finalized_at bookkeeping never leaves the store
    return InvoiceOut(id=rec["id"], number=rec["number"], customer=rec["customer"], status=rec["status"],
                      currency=rec["currency"], line_items=[LineOut(**li) for li in rec["line_items"]],
                      subtotal=rec["subtotal"], tax=rec["tax"], total=rec["total"], amount_paid=rec["amount_paid"])


def _id(value: str) -> str:
    return require_well_formed(value, "the invoice id")            # the central handler-side identifier rule


def _recompute(customer: str, line_items, tax: int):
    # the CONSERVATION core — derive every money field server-side; the per-line PRODUCT and the running subtotal/total
    # are each bounded so the sums can't wrap int64 / lose float precision (×3). Echoed text is U+FFFD-sanitized so a
    # lone surrogate can never crash response/store serialization. Returns (customer, lines, subtotal, total).
    safe_customer = make_well_formed(customer)
    lines, subtotal = [], 0
    for li in line_items:
        # quantity >= 1 (model-enforced), so the product comparison is EXACT ×3: python's arbitrary precision and node's
        # exact-below-2^53 compare the product directly; go pre-checks by division (its int64 product would WRAP first).
        if li.unit_amount * li.quantity > MAX_AMOUNT:
            raise invalid("a line amount exceeds the maximum")
        amount = li.unit_amount * li.quantity
        lines.append({"description": make_well_formed(li.description), "quantity": li.quantity,
                      "unit_amount": li.unit_amount, "amount": amount})
        subtotal += amount
        if subtotal > MAX_AMOUNT:                                  # the running SUM is bounded before it can overflow
            raise invalid("the subtotal exceeds the maximum")
    total = subtotal + tax
    if total > MAX_AMOUNT:
        raise invalid("the total exceeds the maximum")
    return safe_customer, lines, subtotal, total


def _digest(customer: str, currency: str, tax: int, lines) -> str:
    # the canonical body fingerprint for idempotency (over the recomputed, U+FFFD-safe shape): a same-key replay with
    # the same body returns the same draft; a different body is a 409. Lines are serialized field-by-field, in order.
    parts = ["customer", customer, "currency", currency, "tax", tax, "lines", len(lines)]
    for i, li in enumerate(lines):
        parts += [f"d{i}", li["description"], f"q{i}", li["quantity"], f"u{i}", li["unit_amount"]]
    return digest_hex(*parts)


@router.post("", response_model=InvoiceOut, status_code=201)
def create(data: CreateInvoiceIn, request: Request, subject: str = Depends(require_identity),
           idempotency_key: Optional[str] = Header(default=None)) -> InvoiceOut:
    # PRECEDENCE (identical ×3): the JSON FRAME is parsed FIRST — a malformed body -> 422 before auth (pydantic here,
    # DecodeJSON in go, the runtime parse in node all frame-check first); then require_identity (no token + a valid
    # body -> 401); then the field validation + is_currency + the idem-key + the conservation recompute (-> 422).
    if not is_currency(data.currency):                # SEMANTIC: a CLOSED ISO-4217 set, not just well-formed
        raise invalid("currency must be a valid ISO-4217 code")
    if idempotency_key is None:                       # REQUIRED: the bill id is DERIVED from the key (no key, no id)
        raise invalid("Idempotency-Key header is required")
    if len(request.headers.getlist("idempotency-key")) > 1:
        raise invalid("Idempotency-Key must be a single value")
    require_well_formed(idempotency_key, "Idempotency-Key")
    safe_customer, lines, subtotal, total = _recompute(data.customer, data.line_items, data.tax)
    body_hash = _digest(safe_customer, data.currency, data.tax, lines)
    inv_id = scoped_key(_ROUTE, subject, idempotency_key)   # the deterministic, caller-private bill id
    slot = f"{subject}\x1f{inv_id}"                         # the owner-composite store slot (cross-caller -> 404)
    prior = store.get(_NS, slot)                           # fast path: a settled key never re-creates
    if prior is None:
        rec = {"id": inv_id, "caller": subject, "customer": safe_customer, "status": "draft",
               "currency": data.currency, "line_items": lines, "subtotal": subtotal, "tax": data.tax,
               "total": total, "amount_paid": 0, "number": None, "finalized_at": None, "body_hash": body_hash}
        prior = claim_once(_NS, slot, rec)                 # ONE atomic claim per slot (no double-create under a race)
    if prior.get("caller") != subject:
        # DEFENSE-IN-DEPTH: the composite slot already isolates callers, so this is structurally impossible — but if it
        # EVER happens (a hash collision / a scoping regression) we REFUSE, never serve another caller's bill.
        raise conflict("idempotency key is not owned by this caller")
    if prior["body_hash"] != body_hash:
        raise conflict("idempotency key reused with a different body")
    return _out(prior)


@router.get("")
def list_invoices(limit: str = "", cursor: str = "", subject: str = Depends(require_identity)) -> dict:
    # SCOPED read: only the caller's OWN bills (owner-FIELD-filtered — the comparison runs on the STORED owner
    # field, never a client value), then a BOUNDED page over that stable-ordered set via the shared paginate part.
    mine = [r for r in store.values(_NS) if r.get("caller") == subject]
    page, nxt, ok = paginate(mine, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": [_out(r).model_dump() for r in page], "next_cursor": nxt}


@router.get("/{invoice_id}", response_model=InvoiceOut)
def get_invoice(invoice_id: str, subject: str = Depends(require_identity)) -> InvoiceOut:
    rec = store.get(_NS, f"{subject}\x1f{_id(invoice_id)}")
    if rec is None:
        raise not_found("invoice")   # not-yours == not-found: another caller's bill is under a different slot
    return _out(rec)


# ── the lifecycle TRANSITIONS — each is ONE atomic read-modify-write through the `do` seam. The state read,
# the conservation/recompute, and the write ALL happen INSIDE the callback against `cur` (NEVER a value read before the
# do() — the latent-RMW class no gate catches), so two processes racing a transition serialize on the slot's write lock
# and the loser sees the already-transitioned bill. ──────────────────────────────────────────────────────────────────


@router.patch("/{invoice_id}", response_model=InvoiceOut)
def update_invoice(invoice_id: str, data: CreateInvoiceIn, subject: str = Depends(require_identity)) -> InvoiceOut:
    # DRAFT-ONLY edit (the IMMUTABILITY trap door: a finalized bill is FROZEN, 409). Re-validate + RECOMPUTE the new
    # content (pure, BEFORE the do()), then atomically check status=="draft" and replace the editable fields. No
    # Idempotency-Key: the bill is addressed by its path id, and a PATCH is idempotent by nature (same body -> same bill).
    if not is_currency(data.currency):
        raise invalid("currency must be a valid ISO-4217 code")
    safe_customer, lines, subtotal, total = _recompute(data.customer, data.line_items, data.tax)
    body_hash = _digest(safe_customer, data.currency, data.tax, lines)
    outcome: dict = {"code": 0, "rec": None}

    def fn(cur):
        if cur is None:
            outcome["code"] = 404
            return None, None
        if cur["status"] != "draft":                  # IMMUTABILITY: only a draft is editable
            outcome["code"] = 409
            return None, None
        nxt = dict(cur)
        nxt.update(customer=safe_customer, currency=data.currency, line_items=lines,
                   subtotal=subtotal, tax=data.tax, total=total, body_hash=body_hash)
        outcome["rec"] = nxt
        return nxt, None

    store.do(_NS, f"{subject}\x1f{_id(invoice_id)}", fn)
    if outcome["code"] == 404:
        raise not_found("invoice")
    if outcome["code"] == 409:
        raise conflict("only a draft invoice can be edited")
    return _out(outcome["rec"])


@router.post("/{invoice_id}/finalize", response_model=InvoiceOut)
def finalize(invoice_id: str, request: Request, subject: str = Depends(require_identity)) -> InvoiceOut:
    # FINALIZE = the one-way trap door draft -> open + assign the legal NUMBER. The number is monotonic + no-dup but NOT
    # gapless: minting it INSIDE the transition do() would RE-ENTER the store (the reentrancy guard throws ×3), and
    # minting BEFORE a possible 409 would burn a number -> a gap. So it is a TWO-STEP: (1) an atomic do() flips
    # draft->open WITHOUT minting; (2) only after that commits, mint next_id OUTSIDE the callback and attach it via a 2nd
    # do(). A crash between the steps leaves an open bill with number=null, which a re-finalize COMPLETES (idempotent).
    # Two processes racing -> exactly ONE number attached (the other's mint is a rare, owned gap), never a duplicate.
    slot = f"{subject}\x1f{_id(invoice_id)}"
    now = clock.current(request)
    outcome: dict = {"code": 0, "rec": None}

    def step1(cur):
        if cur is None:
            outcome["code"] = 404
            return None, None
        if cur["status"] == "draft":                  # the transition: freeze the content, stamp finalized_at, NO mint
            nxt = dict(cur)
            nxt["status"] = "open"
            nxt["finalized_at"] = now
            outcome["rec"] = nxt
            return nxt, None
        if cur["status"] == "open":                   # already finalized (number set) OR half-finalized (number null)
            outcome["rec"] = cur
            return None, None
        outcome["code"] = 409                          # paid / void / uncollectible -> past finalize, not re-finalizable
        return None, None

    store.do(_NS, slot, step1)
    if outcome["code"] == 404:
        raise not_found("invoice")
    if outcome["code"] == 409:
        raise conflict("only a draft invoice can be finalized")
    rec = outcome["rec"]
    if rec["number"] is None:                          # mint OUTSIDE the do() (reentrancy-safe), then attach atomically
        minted = f"INV-{store.next_id('invoices_number_' + subject):06d}"

        def step2(cur):
            if cur is None or cur["status"] != "open" or cur["number"] is not None:
                outcome["rec"] = cur if cur is not None else rec   # another process attached first -> use the stored one
                return None, None
            nxt = dict(cur)
            nxt["number"] = minted
            outcome["rec"] = nxt
            return nxt, None

        store.do(_NS, slot, step2)
    return _out(outcome["rec"])


# ── the TERMINAL transitions — a finalized (open) bill moves ONCE to a terminal state: paid / void /
# uncollectible. Each is ONE atomic do() that reads + checks + writes against `cur`; idempotent on its own target
# state, 409 from any other. amount_paid == total IFF paid (conservation: a bill is fully paid or written off, never
# partial — mark-paid). The three share ONE helper (the transition is identical bar the target state). ──────


def _terminal(invoice_id: str, subject: str, target: str, pay: bool):
    outcome: dict = {"code": 0, "rec": None}

    def fn(cur):
        if cur is None:
            outcome["code"] = 404
            return None, None
        if cur["status"] == target:            # idempotent re-application of the SAME transition (no double-pay)
            outcome["rec"] = cur
            return None, None
        if cur["status"] != "open" or cur["number"] is None:   # only a FULLY-finalized (NUMBERED) bill transitions — a
            outcome["code"] = 409                               # torn finalize (open, number=null, the crash/race window)
            return None, None                                   # 409s until a re-finalize completes its number (no number-less terminal)
        nxt = dict(cur)
        nxt["status"] = target
        if pay:
            nxt["amount_paid"] = nxt["total"]  # CONSERVATION: a paid bill records its FULL total (never partial)
        outcome["rec"] = nxt
        return nxt, None

    store.do(_NS, f"{subject}\x1f{_id(invoice_id)}", fn)
    if outcome["code"] == 404:
        raise not_found("invoice")
    if outcome["code"] == 409:
        raise conflict(f"invoice cannot transition to {target} from its current state")
    return _out(outcome["rec"])


@router.post("/{invoice_id}/pay", response_model=InvoiceOut)
def pay(invoice_id: str, subject: str = Depends(require_identity)) -> InvoiceOut:
    # mark-paid: record the bill as fully paid (amount_paid = total) WITHOUT importing the payments domain.
    # open -> paid; idempotent on paid; a draft/void/uncollectible bill -> 409 (only a finalized open bill can be paid).
    return _terminal(invoice_id, subject, "paid", True)


@router.post("/{invoice_id}/void", response_model=InvoiceOut)
def void_invoice(invoice_id: str, subject: str = Depends(require_identity)) -> InvoiceOut:
    # void a finalized bill that will NOT be collected. open -> void (amount_paid stays 0); idempotent; else 409.
    return _terminal(invoice_id, subject, "void", False)


@router.post("/{invoice_id}/mark_uncollectible", response_model=InvoiceOut)
def mark_uncollectible(invoice_id: str, subject: str = Depends(require_identity)) -> InvoiceOut:
    # mark a finalized bill as bad debt. open -> uncollectible (amount_paid stays 0); idempotent; else 409.
    return _terminal(invoice_id, subject, "uncollectible", False)
