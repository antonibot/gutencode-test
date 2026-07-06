"""invoices domain package (package shape) — the CONSERVED bill lifecycle: create-draft + recompute, edit,
finalize (the monotonic legal number + the immutability trap door), and the terminal pay/void/uncollectible
transitions. Public surface: `router` (the wiring imports the PACKAGE, so this re-export is the entry)."""
from .routes import router  # noqa: F401

__all__ = ["router"]
