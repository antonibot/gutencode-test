"""The chat_threads domain (package shape) — a durable, owner-scoped AI-chat history store: threads plus an
append-only, seq-ordered, immutable message log per thread. Public surface: `router` (the wiring imports the
PACKAGE, so this re-export is the entry)."""
from .router import router  # noqa: F401

__all__ = ["router"]
