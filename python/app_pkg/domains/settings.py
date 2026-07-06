"""settings — settings over a fixed, typed schema, scoped to the AUTHENTICATED identity. The dangerous property is
TYPE SAFETY + COMPLETENESS: only known keys are writable (an unknown key is 422 — deny-by-default), each value is
STRICTLY type-checked against its key's declared type before any write (a string '20', a float 1.5, or a boolean
true is NOT an int — the ledger StrictInt discipline), and a read always returns EVERY known key with the declared
default filling any gap. The owner is the bearer token's subject (the core require_identity seam) — NOT a path
param — so a caller only ever reads/writes THEIR OWN settings. Deny-by-default (no token -> 401). Durable.
"""
from typing import Any, Dict

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..core import store
from ..core.errors import _MAX_SAFE_INT, invalid, not_found, require_identity

router = APIRouter(prefix="/settings", tags=["settings"])

# the schema is POLICY (fixed, code-reviewed): key -> (type, default). The ONLY writable keys + their types.
_SCHEMA: Dict[str, tuple] = {
    "notifications_enabled": ("bool", True),
    "items_per_page": ("int", 20),
    "theme": ("string", "light"),
}
# state in `store`: ns "settings_overrides" "<owner>\x1f<key>" -> value (owner = the authenticated subject; ×3 identical)


class ValueIn(BaseModel):
    value: Any


def _typed(kind: str, value: Any) -> bool:
    # STRICT: bool is checked BEFORE int (in python bool is a subclass of int — true must not pass as int)
    if isinstance(value, bool):
        return kind == "bool"
    if isinstance(value, int):
        return kind == "int" and abs(value) <= _MAX_SAFE_INT   # bound to the ×3-safe range (parity with go/node)
    if isinstance(value, str):
        return kind == "string"
    return False


def _key_id(owner: str, key: str) -> str:
    return f"{owner}\x1f{key}"   # owner (the subject) + key composite; both well-formed so the separator can't be forged


@router.get("")
def list_settings(owner: str = Depends(require_identity)) -> dict:
    # COMPLETENESS: start from defaults, overlay the owner's stored overrides — every known key is present
    out = {k: default for k, (_, default) in _SCHEMA.items()}
    for k in _SCHEMA:
        stored = store.get("settings_overrides", _key_id(owner, k))
        if stored is not None:
            out[k] = stored
    return out


@router.get("/{key}")
def get_setting(key: str, owner: str = Depends(require_identity)) -> dict:
    if key not in _SCHEMA:
        raise not_found("setting")
    stored = store.get("settings_overrides", _key_id(owner, key))
    return {"key": key, "value": stored if stored is not None else _SCHEMA[key][1]}


@router.put("/{key}")
def put_setting(key: str, data: ValueIn, owner: str = Depends(require_identity)) -> dict:
    if key not in _SCHEMA:
        raise invalid("unknown setting key")        # deny-by-default: no arbitrary keys
    kind, _ = _SCHEMA[key]
    if not _typed(kind, data.value):
        raise invalid(f"setting '{key}' must be of type {kind}")   # strict type check BEFORE any write
    store.put("settings_overrides", _key_id(owner, key), data.value)
    return {"key": key, "value": data.value}
