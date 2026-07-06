"""file_store routes — REAL byte objects behind a swappable provider port. Upload is base64-in-JSON (decoded with
the canonical-round-trip rule); download returns the exact raw bytes with the stored Content-Type reflected, a
content-addressed ETag, and the stored-XSS defense headers (nosniff + attachment). Every object is owned by its
uploader (the core require_identity seam), addressed by the composite <owner>\x1f<key>; a cross-owner surface is 404.
Usage is bounded BOTH ways — a per-owner file COUNT cap AND a per-owner total-BYTES quota — enforced atomically at
every write admission in ONE index do() (the old size read from the entry INSIDE the fn, so a replace is a TOCTOU-free
delta). The row (never the index) is the content authority for GET/meta; the index is the delete-existence authority.
Same names + DECISIONS in all three languages."""
from fastapi import APIRouter, Depends, Request, Response

from ...core import clock, store
from ...core.errors import invalid, not_found, require_identity
from ...parts.digest import digest_hex
from ...parts.paginate import paginate
from . import config
from .ports import PutIn
from .providers import get_provider
from .validate import clean_content_type, decode_b64, norm_key

router = APIRouter(prefix="/file_store", tags=["file_store"])

_INDEX = "file_store_index"   # "<owner>" -> [{key, size} ...] codepoint-sorted (the quota + COUNT authority; a RESERVATION ledger, not the content truth)


def _admit(owner: str, key: str, size: int) -> str:
    # ATOMIC quota/count admission in ONE index do(): the new-vs-existing decision AND the old size are read from
    # `entries` INSIDE the fn (never a pre-do row read — a row-sourced `old` is a TOCTOU under concurrent replace
    # AND double-counts over a create-tear). fn is PURE (the object row is written OUTSIDE the do). "ok"|"count"|"quota".
    mx_keys, mx_total = config.max_keys(), config.max_total_bytes()

    def fn(cur):
        entries = list(cur) if cur else []
        total = sum(e["size"] for e in entries)                     # derived total < MAX_KEYS*MAX_BYTES < 2^33 << 2^53 (safe x3)
        old = next((i for i, e in enumerate(entries) if e["key"] == key), -1)
        if old >= 0:                                                # REPLACE: a delta on the existing reservation
            if total - entries[old]["size"] + size > mx_total:
                return None, "quota"
            entries[old] = {"key": key, "size": size}
            return entries, "ok"
        if len(entries) >= mx_keys:                                 # the file-COUNT cap (the partition-COUNT bound)
            return None, "count"
        if total + size > mx_total:                                 # the total-BYTES quota
            return None, "quota"
        # unbounded-safe: the per-owner entries list is bounded at FILE_STORE_MAX_KEYS by the reject-past-cap guard
        # above (a create past the cap is a loud 422, never an eviction — dropping a user's file is data loss);
        # bounding the COUNT bounds the per-owner key-space, and each entry's bytes are bounded by the 1024-byte key
        # cap, so the index row is bounded by construction. Insert in CODEPOINT order (bisect on the key).
        lo, hi = 0, len(entries)
        while lo < hi:
            mid = (lo + hi) // 2
            if entries[mid]["key"] < key:
                lo = mid + 1
            else:
                hi = mid
        entries.insert(lo, {"key": key, "size": size})
        return entries, "ok"

    return store.do(_INDEX, owner, fn)


def _release(owner: str, key: str) -> bool:
    # remove the key's entry from the owner index; True iff it was present. The INDEX is the DELETE existence
    # authority (so a phantom entry — present with no row — is user-clearable), read-modified atomically through do.
    def fn(cur):
        entries = list(cur) if cur else []
        kept = [e for e in entries if e["key"] != key]
        return (kept, True) if len(kept) != len(entries) else (None, False)
    return store.do(_INDEX, owner, fn)


@router.post("", status_code=201)
def put_object(req: PutIn, request: Request, owner: str = Depends(require_identity)) -> dict:
    # mutation-auth: identity — the object is owned by the caller (the token subject, never a body field
    # [guarded_fields: owner]). Validate EVERYTHING before the admission so a bad request never touches the index.
    key = norm_key(req.key)
    content_type = clean_content_type(req.content_type)
    raw = decode_b64(req.content_b64)                       # canonical base64 -> the bytes; "" is a valid 0-byte object
    size = len(raw)                                         # derived: size — recomputed server-side, a smuggled value is ignored
    if size > config.max_bytes():
        raise invalid("file too large")
    etag = digest_hex(req.content_b64)                     # content-addressed over the CANONICAL b64 (via the digest part)
    created_at = clock.current(request)
    admit = _admit(owner, key, size)                       # RMW through the atomic index seam — never get-then-put
    if admit == "count":
        raise invalid(f"file count limit reached (max {config.max_keys()})")
    if admit == "quota":
        raise invalid("storage quota exceeded")
    provider = get_provider()
    row = {"owner": owner, "key": key, "content_b64": req.content_b64, "content_type": content_type,
           "size": size, "etag": etag, "created_at": created_at}
    provider.put(owner, key, row)                          # THEN the object row (outside the do — a tear lands on the SAFE side)
    return {"key": key, "provider": provider.name, "size": size, "etag": etag,
            "content_type": content_type, "created_at": created_at}


@router.get("/{file_key}/meta")
def get_meta(file_key: str, owner: str = Depends(require_identity)) -> dict:
    # read-scope: owner — the manifest-assertable JSON mirror; `size` here is the ACTUAL (row) size. Row authority:
    # a cross-owner key is a different composite -> 404 (existence never leaks).
    row = get_provider().get(owner, norm_key(file_key))
    if row is None:
        raise not_found("object")
    return {"key": row["key"], "size": row["size"], "etag": row["etag"],
            "content_type": row["content_type"], "created_at": row["created_at"]}


@router.get("/{file_key}")
def get_object(file_key: str, owner: str = Depends(require_identity)) -> Response:
    # read-scope: owner — the REAL-bytes download. The row (never the index) is the content authority; not-yours ==
    # 404. The stored content_type is reflected, PLUS the stored-XSS defense (nosniff + bare attachment): a VALID
    # text/html served from the app origin is an attack the write grammar cannot and should not block.
    row = get_provider().get(owner, norm_key(file_key))
    if row is None:
        raise not_found("object")
    body = decode_b64(row["content_b64"])                  # the stored b64 is canonical by construction -> always decodes
    return Response(content=body, headers={                # headers= NEVER media_type= (starlette appends ; charset to text/*)
        "Content-Type": row["content_type"], "ETag": f'"{row["etag"]}"',
        "X-Content-Type-Options": "nosniff", "Content-Disposition": "attachment"})


@router.get("")
def list_objects(limit: str = "", cursor: str = "", owner: str = Depends(require_identity)) -> dict:
    # read-scope: owner — the caller's own {key, size} served from the per-owner INDEX (ONE point-read, codepoint
    # order by construction — no namespace scan), BOUNDED through paginate. `size` here is the quota RESERVATION
    # (== actual outside a documented tear window); per-item etag/content_type live in /meta.
    entries = store.get(_INDEX, owner) or []
    page, nxt, ok = paginate(entries, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": [{"key": e["key"], "size": e["size"]} for e in page], "next_cursor": nxt}


@router.delete("/{file_key}", status_code=204)
def delete_object(file_key: str, owner: str = Depends(require_identity)) -> Response:
    # mutation-auth: identity — free the quota slot. Row delete FIRST (idempotent), index-release LAST: the INDEX is
    # the delete-existence authority, so a phantom (entry, no row) is clearable (204) while a truly-missing key is 404.
    key = norm_key(file_key)
    get_provider().delete(owner, key)                      # row first (idempotent)
    if not _release(owner, key):                           # index release is the existence authority
        raise not_found("object")
    return Response(status_code=204)
