"""audit_log — an append-only, tamper-evident evidence log (the hash-chain shape). Every event's hash is
sha256 over the COMPLETE record (prev · id · at · actor · action — the two well_formed fields pre-hashed so the
join stays injective), rooted at GENESIS, so editing ANY past field — a backdate, an actor swap, an action edit —
breaks every later link.
The dangerous property is CHAIN INTEGRITY: the append is ONE atomic read-modify-write on the chain head through
the store's `do` seam — two processes appending concurrently get sequential ids on one chain, never a fork.
Immutability is by construction (no update or delete route exists). /verify re-derives the whole chain and
reports ANY damage loudly: a tampered action, a broken link, a missing event — including self-damage (a crash
between the head advance and the event write leaves a visible hole; an evidence log must show its own wounds,
never paper over them). Events are durable; the chain survives a restart.

WRITES ARE SERVICE-ONLY, THE DISCLOSING READ ADMIN-ONLY: an anonymous append is log-poisoning (the chain
stays "valid" over forged rows, so the integrity proof can't catch it) and the event LIST discloses every
subject's events. POST /events (append) is gated by the trusted SERVICE seam (core.require_service) — audit events
are ingested by app services on a user's behalf, never posted by end users directly; GET /events (list) requires
the 'admin' role (core require_admin). A missing/wrong service token on the append is 401; a non-admin on the list
is 403. For the body-only append, auth resolves via FastAPI's Depends — a cleanly-decoding but ill-typed body with
no token is 401 (auth before body validation), identical ×3. GET /verify stays OPEN on purpose: it is the
integrity probe and returns only {valid, count, detail} — no event contents — so anyone may ask "is the chain
intact?" without seeing what is in it."""
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from ..core import clock, store
from ..core.errors import invalid, require_admin, require_service
from ..parts.digest import digest_hex
from ..parts.paginate import paginate
from ..parts.well_formed import WellFormedStr

router = APIRouter(prefix="/audit_log", tags=["audit_log"])
# state in `store`: ns "audit_log_chain" key "head" -> {id, hash} (the RMW target — the ONLY mutable row) ·
# ns "audit_log_events" str(id) -> {id, at, actor, action, prev, hash} (append-only; same names + shape ×3). The
# record is the WHO (actor) · WHAT (action) · WHEN (at, from the core clock seam) — the mandated audit fields
# (NIST AU-3 / PCI-10) — and ALL of them are covered by `hash`, so a backdate or an actor-forge is tamper-evident.


class EventIn(BaseModel):
    actor: WellFormedStr    # WHO — the subject the trusted service is logging on behalf of (service-supplied)
    action: WellFormedStr   # WHAT — an IDENTIFIER-grade string — the central well_formed rule


class EventOut(BaseModel):
    id: int
    at: int                 # WHEN — seconds since epoch (UTC), from the core clock seam; covered by the hash
    actor: str
    action: str
    prev: str
    hash: str


class VerifyOut(BaseModel):
    valid: bool
    count: int
    detail: str


def _link(prev: str, event_id: int, at: int, actor: str, action: str) -> str:
    # the chain link over the COMPLETE record, INJECTIVE for the multi-field hash: prev (64-hex/GENESIS), id and at
    # (digits) are colon-free, and the two ADVERSARIAL well_formed fields (actor, action — well_formed ALLOWS ':',
    # 0x3A >= 0x20) are PRE-HASHED to colon-free 64-hex FIRST, so digest_hex's ':'-join stays unambiguous (the
    # delimiter lesson — a bare digest_hex(prev,id,at,actor,action) would be collision-prone).
    return digest_hex(prev, event_id, at, digest_hex(actor), digest_hex(action))


@router.post("/events", response_model=EventOut, status_code=201)
def append(data: EventIn, request: Request, _service: str = Depends(require_service)) -> EventOut:
    # mutation-auth: service — audit events are ingested by the trusted backend (a SERVICE) on a user's behalf, never
    # posted by end users, so the append is gated by core.require_service (the SERVICE_TOKEN seam), NOT require_admin
    # (an admin is still a user session). Auth resolves via Depends BEFORE the body's field validation, so an
    # unauthenticated ill-typed body is 401 not 422, ×3. The `mutation-auth: service` declaration + the
    # require_service call sit in the same handler, so the declaration cannot drift from the enforcement.
    # WHEN: the timestamp comes from the core CLOCK seam — deterministic under APP_TEST_CLOCK (a `?now=` test vector),
    # the real wall clock in production (a client can't forge prod time — the seam exists for exactly that). It is
    # COVERED BY THE HASH below, so a backdated/forward-dated event is tamper-evident (the /verify re-derive catches it).
    now = clock.current(request)
    # THE APPEND: one atomic claim on the head — the id is chain-derived (head.id + 1, never a separate counter)
    # and computed INSIDE the exclusive transaction, so two processes can never build on the same predecessor.
    # The fn stays PURE (no store calls inside `do`); the event row is written right after the head advances.
    def advance(head):
        prev_id, prev_hash = (head["id"], head["hash"]) if head else (0, "GENESIS")
        event = {"id": prev_id + 1, "at": now, "actor": data.actor, "action": data.action, "prev": prev_hash,
                 "hash": _link(prev_hash, prev_id + 1, now, data.actor, data.action)}
        return {"id": event["id"], "hash": event["hash"]}, event

    event = store.do("audit_log_chain", "head", advance)
    store.put("audit_log_events", str(event["id"]), event)
    return EventOut(**event)


@router.get("/events")
def list_events(limit: str = "", cursor: str = "", subject: str = Depends(require_admin)) -> dict:
    # ADMIN-ONLY read: the full event list discloses every subject's events — a read the mutation gate won't
    # catch, so it is hand-gated here (require_admin runs FIRST, before pagination — no token 401, non-admin 403,
    # auth precedence PRESERVED). /verify (below) stays OPEN: it leaks only {valid, count, detail}.
    # BOUNDED via the shared paginate part — never an unbounded full dump. Events are the hash-chain rows in
    # stable id order (store.values is rowid-stable == monotonic id order), so the offset cursor is well-defined.
    # unscoped-read: admin — the event log is GLOBAL by design (every subject's events); require_admin (the Depends
    # above) is the explicit privileged gate. There is no per-caller owner field — the whole chain IS the trail.
    events = store.values("audit_log_events")
    page, nxt, ok = paginate(events, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/verify", response_model=VerifyOut)
def verify() -> VerifyOut:
    # read-scope: public — integrity probe, returns only {valid, count, detail}, never event contents (already documented as intentionally open).
    # re-derive the WHOLE chain from GENESIS: every id 1..head present, every link correct. Any deviation —
    # a tampered action, a missing event (crash damage), a forged head — is reported loudly, never smoothed.
    head = store.get("audit_log_chain", "head")
    count = head["id"] if head else 0
    prev = "GENESIS"
    for event_id in range(1, count + 1):
        event = store.get("audit_log_events", str(event_id))
        if event is None:
            return VerifyOut(valid=False, count=count, detail=f"event {event_id} missing (hole in the chain)")
        if event["prev"] != prev or event["hash"] != _link(prev, event_id, event["at"], event["actor"], event["action"]):
            return VerifyOut(valid=False, count=count, detail=f"chain broken at event {event_id}")
        prev = event["hash"]
    if head and head["hash"] != prev:
        return VerifyOut(valid=False, count=count, detail="head does not match the derived chain")
    return VerifyOut(valid=True, count=count, detail="chain intact")
