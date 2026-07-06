"""file_store ports — the provider contract + the upload model (the swappable seam, the storage idiom). A backend
stores/retrieves/deletes a whole object ROW by (owner, key); the quota + the per-owner index live one layer up in
the router (so the provider signature stays stable across adapters — a real S3 adapter inherits the same caps).
The backend is selected ONCE in providers.py."""
from typing import Optional, Protocol

from pydantic import BaseModel, StrictStr


class PutIn(BaseModel):
    # allowlist input model: a smuggled owner/size/etag is simply never read (guarded_fields: owner · derived: size).
    key: StrictStr                              # normalized + grammar-checked in the handler (make_well_formed at ingress)
    content_b64: StrictStr                      # canonical base64 of the object bytes; "" is a valid zero-byte object
    content_type: Optional[StrictStr] = None    # reflected on download -> allowlist-validated at write; default application/octet-stream


class FileStoreProvider(Protocol):
    """A backend stores + retrieves a whole object row by (owner, key). USER-SCOPED: the owner is the AUTHENTICATED
    caller (never client input), so a backend can never address another owner's object."""
    name: str

    def put(self, owner: str, key: str, row: dict) -> None: ...

    def get(self, owner: str, key: str) -> Optional[dict]: ...

    def delete(self, owner: str, key: str) -> None: ...
