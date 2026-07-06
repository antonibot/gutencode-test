"""storage routes — put/get/delete/list objects via the configured provider. USER-SCOPED: a stored object
belongs to its uploader (the core require_identity seam), so every route is deny-by-default authenticated (no
token -> 401) and an object is addressed by (owner, key) — caller A's `a.txt` and caller B's `a.txt` are DISTINCT
objects (no cross-owner overwrite), the list returns ONLY the caller's own keys, and a cross-owner get/delete is
404 (byte-indistinguishable from missing — existence never leaks across owners). The router never names a backend;
it asks the factory for whatever STORAGE_PROVIDER selected. The dangerous property is INTEGRITY: round-trips are
byte-for-byte and the etag is content-addressed, so corruption or substitution is always visible.
"""
from fastapi import APIRouter, Depends, Response

from ...core.errors import invalid, not_found, require_identity
from ...parts.paginate import paginate
from ...parts.well_formed import require_well_formed
from .ports import PutRequest, PutResult, StoredObject
from .providers.factory import get_provider

router = APIRouter(prefix="/storage", tags=["storage"])


def _key(value: str) -> str:
    return require_well_formed(value, "the object key")   # the central handler-side rule


@router.post("", response_model=PutResult, status_code=201)
def put_object(req: PutRequest, owner: str = Depends(require_identity)) -> PutResult:
    # the object is owned by the caller; the provider composes (owner, key) so it cannot overwrite another owner's
    return get_provider().put(owner, req)


@router.get("")
def list_keys(limit: str = "", cursor: str = "", owner: str = Depends(require_identity)) -> dict:
    # SCOPED read: only the caller's own bare keys ever leave the store (owner-filtered, prefix stripped), then a
    # BOUNDED page over that stable-ordered owner key set via the shared paginate part (the provider returns the
    # full owner list; bounding happens here, one layer up — so the provider signature stays stable across adapters).
    keys = get_provider().keys(owner)
    page, nxt, ok = paginate(keys, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/{object_key}", response_model=StoredObject)
def get_object(object_key: str, owner: str = Depends(require_identity)) -> StoredObject:
    obj = get_provider().get(owner, _key(object_key))
    if obj is None:
        raise not_found("object")   # not-yours == not-found: another owner's object is under a different key
    return obj


@router.delete("/{object_key}", status_code=204)
def delete_object(object_key: str, owner: str = Depends(require_identity)) -> Response:
    if not get_provider().delete(owner, _key(object_key)):
        raise not_found("object")   # not-yours == not-found: a cross-owner delete can't destroy another's object
    return Response(status_code=204)
