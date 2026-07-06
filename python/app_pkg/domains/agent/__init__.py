"""The agent domain — a multi-file AI agent runtime (bounded run loop · tool registry · swappable provider ·
durable memory). Public surface: `router` (the wiring imports the PACKAGE, so this re-export is the entry)."""
from .router import router  # noqa: F401

__all__ = ["router"]
