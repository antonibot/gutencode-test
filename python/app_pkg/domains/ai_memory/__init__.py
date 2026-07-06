"""The ai_memory domain (package shape) — a long-term, owner-scoped, retention-ENFORCED agent-memory store. Public
surface: `router` (the wiring imports the PACKAGE, so this re-export is the entry)."""
from .router import router  # noqa: F401

__all__ = ["router"]
