"""notifications — in-app notifications with three dangerous properties, all proven:
(1) SENDER IS THE AUTHENTICATED CALLER: sending requires a valid bearer token (no token -> 401), and the
    notification's `from` is STAMPED from the authenticated subject (the core require_identity seam) — NEVER a
    caller-supplied body field, so a caller cannot forge the sender (an anonymous caller cannot spam a trusted
    inbox, and a logged-in caller always sends AS themselves).
(2) RECIPIENT SCOPING: a notification belongs to its recipient; listing or acting as anyone else returns 404,
    byte-indistinguishable from missing (existence never leaks across recipients), keyed by the AUTHENTICATED
    identity from the core require_identity seam — NOT a caller-supplied param — so a client cannot read another's
    notifications by setting a header. Deny-by-default.
(3) MONOTONIC READ-STATE: unread -> read only; marking read is idempotent (a TERMINAL-value write — concurrent
    marks converge, the billing-cancel class, no atomic seam needed) and a read notification never returns to
    unread. Durable: the read-state survives a restart."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, StrictStr, field_validator

from ..core import store
from ..core.errors import IntPath, invalid, not_found, require_identity
from ..parts.paginate import paginate
from ..parts.well_formed import WellFormedStr

router = APIRouter(prefix="/notifications", tags=["notifications"])
# state in `store`: seq "notifications_item" the id counter · ns "notifications_items" str(id) ->
# {id, from, to, message, status: unread|read} (the WHOLE record per write; same names + shape ×3 languages).
# `from` is the AUTHENTICATED sender (require_identity), never a body field — the sender can't be forged.


class NotifyIn(BaseModel):
    to: WellFormedStr      # the recipient is an IDENTIFIER — the central well_formed rule
    message: StrictStr     # content — may carry anything printable, but an empty message is a mistake
    # NOTE: there is intentionally NO `from` field — the sender is the authenticated subject, never client input.

    @field_validator("message")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("must be non-empty")
        return value


@router.post("", status_code=201)
def send(data: NotifyIn, sender: str = Depends(require_identity)) -> dict:
    # the sender is the AUTHENTICATED subject (require_identity), stamped into `from` — never a body field, so
    # the sender cannot be forged. A request without a valid bearer token is 401 before any write. (`from` is a
    # Python keyword, so the record is a plain dict — same wire shape {id, from, to, message, status} ×3.)
    nid = store.next_id("notifications_item")   # atomic, durable; a crash before the put loses the id (a gap)
    notif = {"id": nid, "from": sender, "to": data.to, "message": data.message, "status": "unread"}  # created UNREAD
    store.put("notifications_items", str(nid), notif)
    return notif


@router.get("")
def list_for(limit: str = "", cursor: str = "", subject: str = Depends(require_identity)) -> dict:
    # SCOPED read: the recipient is the AUTHENTICATED subject (require_identity), NOT a caller-supplied query
    # param — you can only ever list YOUR OWN notifications, in id order (deterministic ×3).
    # BOUNDED: the owner-scoped list rides the shared paginate seam (clamps to PAGE_MAX) so a busy inbox can never
    # become a soft-DoS/OOM ceiling — the owner-scope is applied FIRST, then the page is sliced.
    rows = sorted((n for n in store.values("notifications_items") if n["to"] == subject), key=lambda n: n["id"])
    page, nxt, ok = paginate(rows, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.post("/{note_id}/read")
def mark_read(note_id: IntPath, subject: str = Depends(require_identity)) -> dict:
    notif = store.get("notifications_items", str(note_id))
    if notif is None or notif["to"] != subject:
        raise not_found("notification")   # not-yours == not-found: existence never leaks across recipients
    # rmw-safe: monotonic + idempotent — "read" is TERMINAL, so concurrent marks converge to the same value
    # (nothing ever writes "unread" back)
    read = {**notif, "status": "read"}
    store.put("notifications_items", str(note_id), read)
    return read
