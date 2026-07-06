"""file_store providers — the swappable seam (ports-and-adapters). Selection happens ONCE here
(FILE_STORE_PROVIDER), never at call sites. USER-SCOPED: the store key is the composite `<owner>\x1f<key>`
(owner FIRST; the user key is grammar-checked — no control chars — so it can never contain the \x1f unit separator,
and the composite key CANNOT be forged to reach another owner's object). The 'store' provider keeps whole object
rows in the durable runtime store seam; the 's3' provider is the FAIL-LOUD customization stub: selecting it
unconfigured raises -> a loud 500, never a silent black-hole store."""
from typing import Optional

from ...core import store
from . import config

_OBJECTS = "file_store_objects"   # "<owner>\x1f<key>" -> {owner, key, content_b64, content_type, size, etag, created_at}
_SEP = "\x1f"                     # the unit separator — forbidden in user keys by the grammar, so the composite key can't be forged


def okey(owner: str, key: str) -> str:
    return owner + _SEP + key     # owner FIRST: the row is addressed by (owner, key), never the user key alone


class DurableFileStore:
    name = "store"

    def put(self, owner: str, key: str, row: dict) -> None:
        store.put(_OBJECTS, okey(owner, key), row)     # the WHOLE object in ONE write -> the row is born consistent

    def get(self, owner: str, key: str) -> Optional[dict]:
        return store.get(_OBJECTS, okey(owner, key))

    def delete(self, owner: str, key: str) -> None:
        store.delete_(_OBJECTS, okey(owner, key))      # idempotent — deleting an absent row is a no-op


class S3FileStore:
    name = "s3"

    def _fail(self):
        # USER-SCOPED: a real adapter receives the AUTHENTICATED owner — namespace your bucket/prefix by it (an
        # `<owner>/` key prefix), exactly as the durable provider composes `<owner>\x1f<key>`.
        raise RuntimeError("the s3 provider is a customization stub - wire a real client here (or set FILE_STORE_PROVIDER=store)")

    def put(self, owner: str, key: str, row: dict) -> None:
        self._fail()

    def get(self, owner: str, key: str):
        self._fail()

    def delete(self, owner: str, key: str) -> None:
        self._fail()


_instance = None


def get_provider():
    global _instance
    if _instance is None:
        if config.FILE_STORE_PROVIDER == "s3":
            if not config.FILE_STORE_S3_BUCKET or not config.FILE_STORE_S3_ENDPOINT:
                raise RuntimeError("FILE_STORE_PROVIDER=s3 requires FILE_STORE_S3_BUCKET and FILE_STORE_S3_ENDPOINT")
            _instance = S3FileStore()
        else:
            _instance = DurableFileStore()
    return _instance
