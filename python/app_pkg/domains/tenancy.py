"""tenancy — tenant isolation, the application-level row-scoping shape (models Postgres row-level security).
Every row carries its tenant; EVERY read is scoped to the caller's tenant; a cross-tenant read is 404,
byte-indistinguishable from a missing row (existence is never revealed across tenants). The tenant is the
AUTHENTICATED identity (the core require_identity seam) — derived from the bearer token, NEVER a client-supplied
header — so a caller cannot read another tenant's rows by setting X-Tenant-Id. Deny-by-default (no token -> 401).
The demo resource is a note; the isolation pattern is the product. State lives in the durable store seam.
(Minimal scope: the tenant IS the authenticated principal; multi-user tenants via org membership are a
documented follow-on.)"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, StrictStr, field_validator

from ..core import store
from ..core.errors import IntPath, invalid, not_found, require_identity
from ..parts.paginate import paginate

router = APIRouter(prefix="/tenancy", tags=["tenancy"])
# state in `store`: seq "tenancy_note" the monotonic note counter · ns "tenancy_notes" str(id) ->
# {id, tenant, body} (the WHOLE row in one write; same names + shape in all three languages)


class NoteIn(BaseModel):
    body: StrictStr

    @field_validator("body")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("must be non-empty")
        return value


class NoteOut(BaseModel):
    id: int
    tenant: str
    body: str


@router.post("/notes", response_model=NoteOut, status_code=201)
def create(data: NoteIn, tenant: str = Depends(require_identity)) -> NoteOut:
    nid = store.next_id("tenancy_note")   # atomic, durable; a crash before the put loses the id (a harmless gap)
    row = {"id": nid, "tenant": tenant, "body": data.body}   # tenant derived from the token, never client-set
    store.put("tenancy_notes", str(nid), row)
    return NoteOut(**row)


@router.get("/notes")
def list_notes(tenant: str = Depends(require_identity), limit: str = "", cursor: str = "") -> dict:
    # SCOPED read: only the caller's tenant's rows ever leave the store (filtered on the authenticated tenant),
    # then a bounded page over that owner-scoped list (store insertion order is stable + identical ×3).
    items = [r for r in store.values("tenancy_notes") if r["tenant"] == tenant]
    page, nxt, ok = paginate(items, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/notes/{note_id}", response_model=NoteOut)
def get_note(note_id: IntPath, tenant: str = Depends(require_identity)) -> NoteOut:
    row = store.get("tenancy_notes", str(note_id))
    if row is None or row["tenant"] != tenant:
        raise not_found("note")   # not-yours == not-found: a cross-tenant probe can't learn the row exists
    return NoteOut(**row)
