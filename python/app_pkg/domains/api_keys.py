"""api_keys — issue/list/verify/rotate/revoke API keys with scopes. Every key records created_at (seconds, from the
core clock seam), preserved across rotate. Dangerous properties, all proven:
(1) NO PLAINTEXT AT REST: the secret is shown ONCE at issue; the stored record holds only sha256(secret) (the
    digest part), never the secret. (2) CONSTANT-TIME, NON-ENUMERABLE VERIFY: every verify hashes and runs ONE
    constant-time compare against a record (a dummy when the id is unknown), so an unknown key id and a wrong
    secret are the same {valid:false} after the same work — no timing oracle, no existence leak; scopes return
    only when valid. (3) ROTATION invalidates the old secret. (4) REVOCATION is monotonic (revoked verifies
    false forever). The key is `ak_<id>_<secret>`; the prefix `ak_<id>` is public, the secret never is.

OWNERSHIP — a key is USER-SCOPED: it belongs to the caller who created it. create/get/list/rotate/revoke require_identity
(the core seam); the OWNER is stamped from the authenticated subject at create (never a body field), and a management
op on another caller's key id is 404 — byte-identical to a missing id, so the enumerable sequential id leaks no
existence (the tenancy not-yours==not-found pattern). The LIST (GET /api_keys) is the SAME owner-scoping over a
COLLECTION: only the caller's keys leave the store (paginated, secret/owner-blind), a stranger gets an empty page —
never 403 (proven by I8). Without this, ids are public ints with no owner check: any caller could
rotate/revoke/read/list another caller's key (cross-caller theft / DoS). /verify stays PUBLIC — the
`ak_<id>_<secret>` key IS the credential (callers verify before they have a session); see its declaration."""
import hmac
import secrets
from typing import List

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, StrictStr, field_validator

from ..core import clock, store
from ..core.errors import IntPath, invalid, not_found, require_identity
from ..parts.digest import digest_hex
from ..parts.paginate import paginate
from ..parts.well_formed import WellFormedStr

router = APIRouter(prefix="/api_keys", tags=["api_keys"])
# state in `store`: seq "api_keys_key" · ns "api_keys_records" str(id) ->
# {id, name, owner, scopes, prefix, secret_hash, status} (owner + secret_hash are private; never returned). ×3 identical.
_DUMMY_HASH = digest_hex("api_keys_absent_record_filler")   # compared when an id is unknown


class KeyIn(BaseModel):
    name: WellFormedStr
    scopes: List[WellFormedStr]

    @field_validator("scopes")
    @classmethod
    def at_least_one(cls, value: List[str]) -> List[str]:
        if not value:
            raise ValueError("at least one scope is required")
        return value


class VerifyIn(BaseModel):
    key: StrictStr

    @field_validator("key")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("must be non-empty")
        return value


def _public(rec: dict) -> dict:
    # the public view NEVER includes secret_hash OR owner (owner is private, like the hash); created_at IS public
    return {"id": rec["id"], "name": rec["name"], "scopes": rec["scopes"], "prefix": rec["prefix"],
            "status": rec["status"], "created_at": rec["created_at"]}


def _issue(rec: dict) -> dict:
    # mint a fresh secret, store its hash, return the public view PLUS the one-time plaintext key (to the OWNER)
    secret = secrets.token_urlsafe(24)
    rec["secret_hash"] = digest_hex(secret)
    store.put("api_keys_records", str(rec["id"]), rec)
    return {**_public(rec), "key": f"ak_{rec['id']}_{secret}"}


@router.post("", status_code=201)
def create(data: KeyIn, request: Request, owner: str = Depends(require_identity)) -> dict:
    kid = store.next_id("api_keys_key")
    # created_at: the key's birth time via the core CLOCK seam (deterministic under APP_TEST_CLOCK, the real wall
    # clock in prod). Stamped ONCE here and PRESERVED across rotate (rotation re-mints the secret, not the birth).
    rec = {"id": kid, "name": data.name, "owner": owner, "scopes": list(data.scopes), "prefix": f"ak_{kid}",
           "status": "active", "created_at": clock.current(request)}   # owner derived from the token, never client-set
    return _issue(rec)


@router.get("")
def list_keys(owner: str = Depends(require_identity), limit: str = "", cursor: str = "") -> dict:
    # OWNER-SCOPED LIST: only the caller's keys ever leave the store — filtered INLINE on the authenticated `owner`
    # (the require_identity subject), mapped to the secret/owner-blind _public view, then a BOUNDED page. A second
    # caller's list never returns this owner's keys (the cross-owner-404 posture, proven by I8); a stranger with no
    # keys gets an empty page, never a 403 (non-enumerable).
    # sorted by id (the stable, monotonic order) — store.values is rowid-order, but rotate/revoke re-write a row and
    # bump its rowid, so an explicit id-sort is required for a stable paged walk (the notifications/admin precedent;
    # tenancy/audit_log skip it only because they never UPDATE a row). `.get("owner")` (not [...]) so a corrupt
    # owner-less row is skipped, not a 500 — matching Go/Node + the defensive _load.
    items = [_public(r) for r in sorted(store.values("api_keys_records"), key=lambda r: r["id"]) if r.get("owner") == owner]
    page, nxt, ok = paginate(items, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


def _load(key_id: int, owner: str) -> dict:
    rec = store.get("api_keys_records", str(key_id))
    if rec is None or rec.get("owner") != owner:
        raise not_found("api key")   # not-yours == not-found: a cross-owner probe can't learn the id exists
    return rec


@router.get("/{key_id}")
def get_key(key_id: IntPath, owner: str = Depends(require_identity)) -> dict:
    return _public(_load(key_id, owner))


@router.post("/verify")
def verify(data: VerifyIn) -> dict:
    # mutation-auth: public — INTENTIONALLY unauthenticated. The `ak_<id>_<secret>` key IS the credential (like a
    # login): a caller verifies it BEFORE it has a session, so require_identity would break the route's purpose. It
    # mutates no stored state on behalf of any user — it only recomputes the hash over the caller-supplied key and
    # runs one constant-time compare. The owner-scoping above guards the MANAGEMENT ops, not this credential check.
    # scopes are ADVISORY: returned to the caller (only when valid) for IT to enforce — verify does not check them; the
    # key's scopes are a label, not an authz boundary in this domain (an optional required-scope check is a v2 propose).
    key_id, secret = "", ""
    parts = data.key.split("_", 2)
    if len(parts) == 3 and parts[0] == "ak":
        key_id, secret = parts[1], parts[2]
    rec = store.get("api_keys_records", key_id) if key_id else None
    stored = rec["secret_hash"] if rec else _DUMMY_HASH
    match = hmac.compare_digest(digest_hex(secret), stored)   # ALWAYS one constant-time compare
    valid = bool(rec) and rec["status"] == "active" and match
    return {"valid": valid, "scopes": rec["scopes"] if valid else []}


@router.post("/{key_id}/rotate")
def rotate(key_id: IntPath, owner: str = Depends(require_identity)) -> dict:
    rec = _load(key_id, owner)
    return _issue(rec)   # a new secret + hash replaces the old; the old secret can never verify again


@router.post("/{key_id}/revoke")
def revoke(key_id: IntPath, owner: str = Depends(require_identity)) -> dict:
    rec = _load(key_id, owner)
    rec = {**rec, "status": "revoked"}   # monotonic + idempotent: revoked is TERMINAL
    store.put("api_keys_records", str(key_id), rec)
    return _public(rec)
