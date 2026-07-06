"""admin — the guarded admin surface. Dangerous properties, all proven:
(1) DENY-BY-DEFAULT GUARD: every route requires a valid admin bearer token, compared CONSTANT-TIME against the
    env-backed secret (no timing oracle); a missing or wrong token is 401 and an unauthorized mutation records
    NOTHING (a failed attempt leaves no trace). (2) APPEND-ONLY: authorized actions get a monotonic id and there
    is no update or delete route — the admin trail is immutable by construction. Self-contained: admin records
    an action intent over a target reference; it never imports a sibling domain (the boundaries law). Durable."""
import hashlib
import hmac
import os

from fastapi import APIRouter, Header
from pydantic import BaseModel
from typing import Optional

from ..core import store
from ..core.errors import IntPath, invalid, not_found, unauthorized
from ..parts.paginate import paginate
from ..parts.well_formed import WellFormedStr

router = APIRouter(prefix="/admin", tags=["admin"])

_ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin_dev_token_change_me")   # env-backed, rotatable
# state in `store`: seq "admin_action" · ns "admin_actions" str(id) -> {id, action, target} (append-only). ×3.


class ActionIn(BaseModel):
    action: WellFormedStr
    target: WellFormedStr


def _require_admin(authorization: Optional[str]) -> None:
    # identity-exempt: a break-glass ADMIN token (constant-time vs the env ADMIN_TOKEN), NOT a user session — the
    # header parse here IS the admin-secret check, by design. Wave B migrates this to require_identity + an admin role.
    # deny-by-default: a Bearer token that does not constant-time-match the admin secret is rejected; the same
    # 401 for "no header", "wrong scheme", and "wrong token" (non-enumerable — no hint which part was wrong).
    # Compare FIXED-LENGTH sha256 digests of both sides so the compare is length-independent too (no length leak —
    # the length-safe CT compare, identical ×3 with go/node).
    token = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
    a = hashlib.sha256(token.encode()).digest()
    b = hashlib.sha256(_ADMIN_TOKEN.encode()).digest()
    if not hmac.compare_digest(a, b):
        raise unauthorized("admin authorization required")


@router.post("/actions", status_code=201)
def record(data: ActionIn, authorization: Optional[str] = Header(default=None)) -> dict:
    _require_admin(authorization)              # GUARD FIRST: an unauthorized call never reaches the store
    aid = store.next_id("admin_action")
    rec = {"id": aid, "action": data.action, "target": data.target}
    store.put("admin_actions", str(aid), rec)   # append-only: only put/get, never update/delete
    return rec


@router.get("/actions")
def list_actions(authorization: Optional[str] = Header(default=None), limit: str = "", cursor: str = "") -> dict:
    _require_admin(authorization)              # the read is guarded too — the trail is admin-only (gate PRESERVED)
    # unscoped-read: admin — the action trail is GLOBAL by design (every action, not per-caller); _require_admin
    # (above) is the explicit, privileged gate (the ABP IDataFilter.Disable / FORCE-RLS-bypass analog, never silent).
    actions = sorted(store.values("admin_actions"), key=lambda a: a["id"])   # stable id order, identical ×3
    page, nxt, ok = paginate(actions, cursor, limit)   # bound the full admin-only list through the shared part
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/actions/{action_id}")
def get_action(action_id: IntPath, authorization: Optional[str] = Header(default=None)) -> dict:
    _require_admin(authorization)
    rec = store.get("admin_actions", str(action_id))
    if rec is None:
        raise not_found("action")
    return rec
