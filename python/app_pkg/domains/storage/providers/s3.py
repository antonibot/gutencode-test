"""The 's3' provider — the customization stub, FAIL-LOUD by design: selecting it without configuration (or
without wiring a real client) raises immediately, so a misconfigured deployment can never silently store
nothing. Wire your S3/R2/GCS client into the four methods; the contract is ports.StorageProvider. USER-SCOPED:
each method receives the AUTHENTICATED `owner` first — namespace your bucket/prefix by it (e.g. an `<owner>/`
key prefix), exactly as the durable provider composes `<owner>\x1f<key>`, so one caller can never reach another's
objects and `keys(owner)` lists only that owner's."""
from typing import List, Optional

from .. import config
from ..ports import PutRequest, PutResult, StoredObject


class S3Storage:
    name = "s3"

    def __init__(self) -> None:
        if not config.S3_BUCKET or not config.S3_ENDPOINT:
            raise RuntimeError("STORAGE_PROVIDER=s3 requires S3_BUCKET and S3_ENDPOINT")

    def _todo(self):
        raise RuntimeError("the s3 provider is a customization stub — wire a real client here "
                           "(or set STORAGE_PROVIDER=store)")

    def put(self, owner: str, req: PutRequest) -> PutResult:
        self._todo()

    def get(self, owner: str, key: str) -> Optional[StoredObject]:
        self._todo()

    def delete(self, owner: str, key: str) -> bool:
        self._todo()

    def keys(self, owner: str) -> List[str]:
        self._todo()
