"""The secrets_vault domain (package shape) — a versioned secret store with a managed version LIFECYCLE, a
domain-local ACCESS AUDIT, and an opt-in at-rest AES-256-GCM SEAL. Public surface: `router` (the wiring imports the
PACKAGE, so this re-export is the entry). The routes, lifecycle, audit, and at-rest seal live in router.py."""
from .router import router  # noqa: F401

__all__ = ["router"]
