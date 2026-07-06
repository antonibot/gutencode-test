"""Provider selection — the ONE site that picks a backend. Swap via STORAGE_PROVIDER env, never at call sites."""
from typing import Optional

from .. import config
from ..ports import StorageProvider
from .durable import DurableStorage
from .s3 import S3Storage

_instance: Optional[StorageProvider] = None


def get_provider() -> StorageProvider:
    global _instance
    if _instance is None:
        _instance = S3Storage() if config.STORAGE_PROVIDER == "s3" else DurableStorage()
    return _instance
