"""storage ports — the provider contract + the object models (the swappable seam). A backend is anything that
can put/get/delete an object by key and list keys; it is selected ONCE in providers/factory.py. The etag is
CONTENT-ADDRESSED: sha256 over the payload via the central digest part — what you read is provably what was
stored."""
from typing import List, Optional, Protocol

from pydantic import BaseModel, StrictStr

from ...parts.digest import digest_hex
from ...parts.well_formed import WellFormedStr


def etag_of(content: str) -> str:
    return digest_hex(content)   # sha256 hex of the payload — the content-addressed integrity tag


class PutRequest(BaseModel):
    key: WellFormedStr     # an object key is an IDENTIFIER — the central well_formed rule
    content: StrictStr     # the payload, opaque; a zero-byte object is valid


class PutResult(BaseModel):
    key: str
    provider: str
    size: int
    etag: str


class StoredObject(BaseModel):
    key: str
    content: str
    size: int
    etag: str


class StorageProvider(Protocol):
    """A backend is anything that can store + retrieve by (owner, key) and list an owner's keys. Selected once in
    providers/factory.py. USER-SCOPED: the owner is the AUTHENTICATED caller (never client input), so a backend can
    never address another owner's object."""
    name: str

    def put(self, owner: str, req: PutRequest) -> PutResult: ...

    def get(self, owner: str, key: str) -> Optional[StoredObject]: ...

    def delete(self, owner: str, key: str) -> bool: ...

    def keys(self, owner: str) -> List[str]: ...
