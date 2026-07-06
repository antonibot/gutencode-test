"""records — the App-Layer DATA SUBSTRATE: declare a typed record schema, then owner-scoped CRUD
(create/list/get/update/delete) over a durable store. The dangerous properties, all proven:
(1) OWNER-SCOPED: every record belongs to the caller who created it (the core require_identity seam); the owner is
    stamped from the authenticated subject, NEVER a client field. A by-id get/patch/delete of another caller's record
    is 404 — byte-indistinguishable from missing (existence never leaks cross-owner; the tenancy not-yours==not-found
    pattern), and the LIST returns ONLY the caller's own rows. This BEATS the common build (Payload returns 403 on a
    filtered by-id update/delete, leaking existence).
(2) NO MASS-ASSIGNMENT: a write reads ONLY the DECLARED field names out of the body's `fields` map (allowlist-READ);
    an undeclared key — a smuggled `owner`/`id`/`type`, a case-variant `Owner`, a nested object — is never consulted,
    so it is structurally impossible for a client to set an authority field (stronger than denylist-stripping).
(3) EXACTLY-ONCE CREATE: the id is DERIVED — `scoped_key("/records", owner, key)` — so it is deterministic,
    owner-partitioned (caller B's same `key` is a DIFFERENT id), and idempotent; the record is written through
    `claim_once`, so a repeat `key` returns the SAME record, never a duplicate.
(4) TYPED VALIDATION: each declared field is validated per its type (text/number/boolean/date/datetime/select/json)
    with cross-language-identical accept/reject; PATCH is a partial merge of validated declared fields through the
    atomic do() RMW seam (never get-then-put), and owner/id/created_at are never client-writable.

The record TYPE is declared HERE (the ×3 source of truth); the manifest's `x-record_schema` is a human-readable
mirror. Other App-Layer domains derive their own type the same way. State lives in the durable store seam; the by-id
slot key is the composite `<owner>\x1f<id>` so a cross-owner id lands in a different slot."""
import re

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, StrictStr

from ..core import clock, store
from ..core.errors import invalid, not_found, org_role, require_identity
from ..parts.digest import scoped_key
from ..parts.idempotent_claim import claim_once
from ..parts.paginate import paginate
from ..parts.well_formed import make_well_formed, require_well_formed, safe_number, sanitize_json

router = APIRouter(prefix="/records", tags=["records"])
# state in `store`: ns "records_rows" "<owner>\x1f<id>" -> {id, owner, created_at, updated_at, fields}. ×3 identical.

_ROUTE = "/records"
# `\Z` not `$` AND `[0-9]` not `\d` — both for ×3 parity: python's `$` also matches BEFORE a trailing newline (so a
# value with a trailing `\n` would pass on python but 422 on go/node, whose RE2/JS `$` anchor end-of-text), and
# python's `\d` matches Unicode digits while go/node's does not. `\Z` anchors the very end identically ×3.
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_DATETIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})?\Z")

# The record TYPE — authored here in all three languages (the source of truth; manifest x-record_schema mirrors it).
_SCHEMA = [
    {"name": "title", "type": "text", "required": True},
    {"name": "count", "type": "number", "required": False},
    {"name": "done", "type": "boolean", "required": False},
    {"name": "due", "type": "datetime", "required": False},
    {"name": "day", "type": "date", "required": False},
    {"name": "status", "type": "select", "required": False, "options": ["open", "closed"]},
    {"name": "meta", "type": "json", "required": False},
]


class CreateIn(BaseModel):
    key: StrictStr
    fields: dict = {}


class PatchIn(BaseModel):
    fields: dict = {}


def _public(rec: dict) -> dict:
    # the full record (no secret fields); owner IS returned — it is the caller's own id (proves the smuggled-owner no-op)
    return {"id": rec["id"], "owner": rec["owner"], "created_at": rec["created_at"],
            "updated_at": rec["updated_at"], "fields": rec["fields"]}


def _org_public(rec: dict) -> dict:
    # an ORG record's public view = the user view PLUS scope:"org" (the org partition marker). USER records stay
    # byte-identical (no scope key) — only org rows carry it.
    return {**_public(rec), "scope": "org"}


def _org_ctx(org: str, caller: str) -> str:
    # the org-scope AUTHZ ladder (identical ×3), applied BEFORE any body validation: the ?org= slug must be well-formed
    # (a forged/control-char slug -> 422), then the caller must be an ACTIVE member of that org (the core org_role seam,
    # never a client field) — a non-member / pending invitee / missing org is None -> 404, byte-identical to a missing
    # record so existence never leaks. Returns the validated org slug (the org record's server-set owner).
    slug = require_well_formed(org, "the org slug")
    if org_role(slug, caller) is None:
        raise not_found("record")
    return slug


def _date_ok(s: str) -> bool:
    # strict ISO format + field ranges, NOT calendar validity (an impossible day-of-month still passes) — calendar
    # validity is NOT ×3-identical (go time.Date NORMALIZES, node Date ROLLS OVER, python RAISES), an owned v2 hardening.
    if not _DATE_RE.match(s):
        return False
    mo, da = int(s[5:7]), int(s[8:10])
    return 1 <= mo <= 12 and 1 <= da <= 31


def _datetime_ok(s: str) -> bool:
    if not _DATETIME_RE.match(s):
        return False
    mo, da, hh, mi, se = int(s[5:7]), int(s[8:10]), int(s[11:13]), int(s[14:16]), int(s[17:19])
    return 1 <= mo <= 12 and 1 <= da <= 31 and hh <= 23 and mi <= 59 and se <= 59


def _validate_one(name: str, ftype: str, options, value):
    # returns the validated value or raises invalid(<message>); the message is byte-identical ×3 (go/node mirror it)
    if ftype == "text":
        if not isinstance(value, str):
            raise invalid(f"field '{name}' must be text")
        return make_well_formed(value)   # surrogate-safe so the response never 5xxs on serialize
    if ftype == "number":
        return safe_number(name, value)
    if ftype == "boolean":
        if not isinstance(value, bool):
            raise invalid(f"field '{name}' must be a boolean")
        return value
    if ftype == "date":
        if not isinstance(value, str) or not _date_ok(value):
            raise invalid(f"field '{name}' must be a date (YYYY-MM-DD)")
        return value
    if ftype == "datetime":
        if not isinstance(value, str) or not _datetime_ok(value):
            raise invalid(f"field '{name}' must be an ISO-8601 datetime")
        return value
    if ftype == "select":
        if value not in options:
            raise invalid(f"field '{name}' is not an allowed option")
        return value
    return sanitize_json(name, value)   # json: recursed — surrogate-safe strings + the ×3-safe number ceiling


def _validate(fields_in, *, creating: bool) -> dict:
    if not isinstance(fields_in, dict):
        raise invalid("fields must be an object")
    out = {}
    for f in _SCHEMA:
        name = f["name"]
        if name in fields_in:                                  # allowlist-READ: ONLY declared names are ever read
            out[name] = _validate_one(name, f["type"], f.get("options", []), fields_in[name])
        elif creating and f.get("required"):
            raise invalid(f"field '{name}' is required")
    return out


@router.post("", status_code=201)
def create(data: CreateIn, request: Request, owner: str = Depends(require_identity), org: str = "") -> dict:
    if org:
        slug = _org_ctx(org, owner)                             # membership FIRST: 422 (bad slug) then 404 (non-member) BEFORE body validation
        key = require_well_formed(data.key, "the record key")
        validated = _validate(data.fields, creating=True)
        now = clock.current(request)
        rid = scoped_key("/records@org", slug, key)             # a DISTINCT route literal -> a disjoint id space from user records
        rec = {"id": rid, "owner": slug, "created_at": now, "updated_at": now, "fields": validated}  # owner = the verified org slug, never client-set
        winner = claim_once("records_org_rows", f"{slug}\x1f{rid}", rec)   # exactly-once per (org, key); a distinct partition
        return _org_public(winner)
    key = require_well_formed(data.key, "the record key")        # the \x1f separator can't be forged (control char -> 422)
    validated = _validate(data.fields, creating=True)
    now = clock.current(request)
    rid = scoped_key(_ROUTE, owner, key)                        # deterministic + owner-partitioned + idempotent
    rec = {"id": rid, "owner": owner, "created_at": now, "updated_at": now, "fields": validated}  # owner from the token, never client-set
    winner = claim_once("records_rows", f"{owner}\x1f{rid}", rec)          # exactly-once: a repeat key returns the SAME record
    return _public(winner)


@router.get("")
def list_records(owner: str = Depends(require_identity), limit: str = "", cursor: str = "", org: str = "") -> dict:
    if org:
        slug = _org_ctx(org, owner)                            # non-member (incl. missing org) -> 404, never a leaked empty page
        items = [_org_public(r) for r in sorted(store.values("records_org_rows"), key=lambda r: r["id"]) if r.get("owner") == slug]
        page, nxt, ok = paginate(items, cursor, limit)
        if not ok:
            raise invalid("invalid cursor or limit")
        return {"results": page, "next_cursor": nxt}
    # SCOPED read: only the caller's own rows ever leave the store (filtered on the authenticated owner FIELD as
    # stored, never a client-supplied value), id-sorted for a stable paged walk, then a BOUNDED page. A stranger
    # gets an empty page, never 403 (non-enumerable).
    items = [_public(r) for r in sorted(store.values("records_rows"), key=lambda r: r["id"]) if r.get("owner") == owner]
    page, nxt, ok = paginate(items, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/{record_id}")
def get_record(record_id: str, owner: str = Depends(require_identity), org: str = "") -> dict:
    if org:
        slug = _org_ctx(org, owner)                                       # non-member -> 404 (same 404 as a missing org record)
        rec = store.get("records_org_rows", f"{slug}\x1f{record_id}")
        if rec is None:
            raise not_found("record")
        return _org_public(rec)
    rec = store.get("records_rows", f"{owner}\x1f{record_id}")             # cross-owner id -> different slot -> 404 (existence never leaks)
    if rec is None:
        raise not_found("record")
    return _public(rec)


@router.patch("/{record_id}")
def update_record(record_id: str, data: PatchIn, request: Request, owner: str = Depends(require_identity), org: str = "") -> dict:
    if org:
        slug = _org_ctx(org, owner)                             # membership FIRST (404) before body validation (422)
        validated = _validate(data.fields, creating=False)
        now = clock.current(request)

        def fn(cur):
            if cur is None:
                return None, None
            merged = dict(cur)
            merged["fields"] = {**cur["fields"], **validated}
            merged["updated_at"] = now                          # owner/id/created_at come from cur, never the client
            return merged, merged

        rec = store.do("records_org_rows", f"{slug}\x1f{record_id}", fn)
        if rec is None:
            raise not_found("record")
        return _org_public(rec)
    validated = _validate(data.fields, creating=False)          # validate BEFORE the transaction (do()'s fn must be pure)
    now = clock.current(request)

    def fn(cur):
        if cur is None:
            return None, None                                  # 404 (no resurrection of a deleted/absent record)
        merged = dict(cur)
        merged["fields"] = {**cur["fields"], **validated}      # partial merge of DECLARED fields only
        merged["updated_at"] = now                             # owner/id/created_at come from cur, never the client (I-PATCH-IMMUT)
        return merged, merged

    rec = store.do("records_rows", f"{owner}\x1f{record_id}", fn)         # atomic RMW, never get-then-put
    if rec is None:
        raise not_found("record")
    return _public(rec)


@router.delete("/{record_id}", status_code=204)
def delete_record(record_id: str, owner: str = Depends(require_identity), org: str = "") -> Response:
    if org:
        slug = _org_ctx(org, owner)                            # non-member -> 404 (existence never leaks)
        composite = f"{slug}\x1f{record_id}"
        if store.get("records_org_rows", composite) is None:
            raise not_found("record")
        store.delete_("records_org_rows", composite)
        return Response(status_code=204)
    composite = f"{owner}\x1f{record_id}"
    if store.get("records_rows", composite) is None:
        raise not_found("record")                              # idempotent re-delete -> 404; cross-owner -> 404
    store.delete_("records_rows", composite)
    return Response(status_code=204)
