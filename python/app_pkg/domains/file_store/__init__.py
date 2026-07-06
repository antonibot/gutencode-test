"""The file_store domain (package shape) — a durable, owner-scoped store of REAL BYTE objects behind a swappable
provider port: base64-in-JSON upload, raw-bytes download (with the stored Content-Type + the stored-XSS defense
headers), JSON metadata/list/delete, and per-owner file-count AND total-byte quotas. Public surface: `router`
(the wiring imports the PACKAGE, so this re-export is the entry)."""
from .router import router  # noqa: F401

__all__ = ["router"]
