"""The 'store' provider — objects in the DURABLE runtime store seam (the default AND the deterministic test
oracle: no network, no keys, and — unlike an in-memory dict — objects survive a process restart). USER-SCOPED:
the store key is the composite `<owner>\x1f<user-key>` (owner FIRST; the user key is well_formed — no control
chars — so it can never contain the \x1f unit separator, and the composite key CANNOT be forged to reach another
owner's object), and the row STAMPS its `owner` so the list filters on the authenticated owner (tenancy's
field-scoped pattern) and returns the BARE keys. The public object shape ({key,content,size,etag}) is unchanged —
`owner` is internal."""
from typing import List, Optional

from ....core import store
from ..ports import PutRequest, PutResult, StoredObject, etag_of

_SEP = "\x1f"   # the unit separator — forbidden in user keys by well_formed, so the composite key can't be forged

_PUBLIC = ("key", "content", "size", "etag")   # the StoredObject fields; `owner` is internal scoping metadata


def _okey(owner: str, key: str) -> str:
    return owner + _SEP + key   # owner FIRST: the row is addressed by (owner, key), never by the user key alone


class DurableStorage:
    name = "store"

    def put(self, owner: str, req: PutRequest) -> PutResult:
        # size is BYTE length (utf-8) — go's len(string) counts bytes, so this is the ×3-identical semantic
        obj = {"owner": owner, "key": req.key, "content": req.content,
               "size": len(req.content.encode("utf-8")), "etag": etag_of(req.content)}
        store.put("storage_objects", _okey(owner, req.key), obj)   # the WHOLE object under the owner-composed key
        return PutResult(provider=self.name, **{k: obj[k] for k in ("key", "size", "etag")})

    def get(self, owner: str, key: str) -> Optional[StoredObject]:
        obj = store.get("storage_objects", _okey(owner, key))
        return StoredObject(**{k: obj[k] for k in _PUBLIC}) if obj else None   # owner stays internal

    def delete(self, owner: str, key: str) -> bool:
        okey = _okey(owner, key)
        if store.get("storage_objects", okey) is None:
            return False
        store.delete_("storage_objects", okey)
        return True

    def keys(self, owner: str) -> List[str]:
        # owner-filtered (on the stamped owner field, tenancy-style), returned as BARE keys in a stable sorted order
        # unbounded-safe: the storageList route paginates this owner key set via the paginate part — keys() does the
        # raw .values() scan but bounding happens one layer up at the route (the provider signature stays stable ×adapters)
        return sorted(o["key"] for o in store.values("storage_objects") if o["owner"] == owner)
