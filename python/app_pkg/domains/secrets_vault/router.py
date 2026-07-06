"""secrets_vault — a versioned secret store with a managed version LIFECYCLE, a domain-local ACCESS AUDIT, and an
at-rest SEAL seam. Dangerous properties, all proven:
(1) VERSION IMMUTABILITY: each write creates a NEW version; rotation only ever ADDS one, so reveal(N) resolves to
    exactly the bytes written at N — UNLESS that version was PRUNED (max_versions), DESTROYED, or DISABLED, each a
    404 that is BYTE-INDISTINGUISHABLE from "never existed" (a probe can't tell which). The per-name counter bumps
    atomically through the `do` seam (concurrent writes get distinct sequential versions).
(2) NO LEAK: the value is returned ONLY by the explicit reveal path — never by the metadata read, the name list, or
    the access audit.
(3) LIFECYCLE: max_versions prunes the OLDEST (bytes deleted via the secure-delete store); DESTROY irreversibly
    removes a version's bytes (tombstoned 'destroyed' -> 404, but visible in metadata); DISABLE/ENABLE reversibly
    hide/show a version (bytes KEPT). The state model mirrors GCP-SM / OpenBao: a version is ENABLED, DISABLED, or
    DESTROYED (plus PRUNED for the max_versions eviction).
(4) ADMIN-ONLY: EVERY route requires the 'admin' role — no token is 401, a non-admin is 403, resolved BEFORE
    any body/path validation (identical x3). Existence itself is sensitive, so even the metadata read and the name
    list are admin-only.
(5) ACCESS AUDIT (domain-local — the rbac/orgs convention; Cerbos/GCP-SM/Vault keep the component's own log): every
    reveal/put/destroy/disable/enable, success AND failure (403 denial / 404 probe), appends {actor, action, name,
    version, outcome, at, source} to secrets_vault_access — NEVER the value. APP_SECRETS_VAULT_AUDIT: off | deny
    (default — log denials + failures, the ASVS failed-access MUST) | all (also the successes). GET /access (admin).

AT-REST (now AVAILABLE, opt-in): every value routes through _seal/_unseal before storage / on reveal. The DEFAULT
(SECRETS_VAULT_KEK unset) is PASSTHROUGH — the stored bytes are PLAINTEXT (the honest, zero-dependency default;
secure_delete=ON still scrubs on delete). Set SECRETS_VAULT_KEK (base64 of 32 bytes) and every value is AES-256-GCM
SEALED before storage: a fresh per-record 96-bit nonce, AAD = name\x1fversion (so a blob can NOT be replayed under
another name/version slot), stored as a self-describing blob "svgcm:<keyver>:<b64(nonce+ciphertext+tag)>". python
lazy-imports the OPTIONAL `cryptography` dep ONLY when the KEK is set (the psycopg precedent — the default install
stays zero-dep; a missing lib fails LOUD, never a silent plaintext fallback); go/node use stdlib AES-GCM. CRYPTO-SHRED:
destroying a version (secure_delete) OR destroying/rotating the KEK makes the ciphertext unrecoverable even where the
DB can not scrub the bytes (a Postgres dead tuple, a backup/replica). A cloud KMS/HSM is the documented INTEROP
upgrade (env-KEK is the offline-deterministic default)."""
import base64
import hashlib
import os
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, StrictStr, field_validator

from ...core import clock, store
from ...core.errors import SafeInt, forbidden, invalid, is_admin, not_found, require_identity
from ...parts.env_int import env_int
from ...parts.paginate import paginate
from ...parts.well_formed import require_well_formed

router = APIRouter(prefix="/secrets_vault", tags=["secrets_vault"])
_META = "secrets_vault_meta"          # name -> {name, current_version, min_version, states:{"<v>":"disabled"|"destroyed"}}
_VERSIONS = "secrets_vault_versions"  # "<name>\x1f<version>" -> SEALED value (passthrough default = plaintext). x3.
_ACCESS = "secrets_vault_access"      # "<id>" -> {id, actor, action, name, version, outcome, at, source} (the audit)
_RESERVED_NAMES = {"access"}          # GET /secrets_vault/access is a static route -> a secret can't shadow that word


def _max_versions() -> int:
    # SECRETS_VAULT_MAX_VERSIONS bounds a name's retained versions (the oldest is PRUNED past the cap) — a soft-DoS
    # floor. Read per-write so a deployer (and the invariant test) can set it; a non-numeric/<1 value -> the default.
    return env_int(os.getenv("SECRETS_VAULT_MAX_VERSIONS"), 100, 1)


_SEAL_SCHEME = "svgcm"                 # AES-256-GCM, KEK-direct, per-record 96-bit nonce, name\x1fversion AAD
_SEAL_PREFIX = _SEAL_SCHEME + ":"      # self-describing blob "svgcm:<keyver>:<b64(nonce+ct+tag)>" (the Vault vault:v1: shape)


class _SealError(Exception):
    """A seal/unseal-layer failure — the KEK is missing/malformed, the optional `cryptography` dep is absent, or a
    ciphertext will NOT authenticate (wrong/rotated key, tampered, or relocated to another slot). Surfaced as a 500 at
    the call site: NEVER plaintext, NEVER garbage — the request fails LOUD (the 'no silent failure' law)."""


def _kek() -> Optional[bytes]:
    # The at-rest KEK: base64 of 32 bytes in SECRETS_VAULT_KEK. Unset/empty -> None (sealing OFF — the zero-dep,
    # byte-unchanged default; NO crypto import on this path). Read per-call so a deployer (and the invariant test) can
    # set it; a malformed key fails LOUD rather than silently degrading to plaintext.
    raw = (os.getenv("SECRETS_VAULT_KEK") or "").strip()
    if not raw:
        return None
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception:
        raise _SealError("SECRETS_VAULT_KEK is not valid base64") from None
    if len(key) != 32:
        raise _SealError("SECRETS_VAULT_KEK must decode to 32 bytes (a base64 256-bit key)")
    return key


def _keyver(key: bytes) -> str:
    # A NON-secret key identifier: the first 8 hex of sha256(key). Makes the blob self-describing (which key era sealed
    # it) and lets _unseal fail LOUD on a wrong/rotated key BEFORE decrypting. 32 bits of a 256-bit key's hash is not a leak.
    return hashlib.sha256(key).hexdigest()[:8]


def _aesgcm(key: bytes):
    # Lazy-import the OPTIONAL `cryptography` dep ONLY when a KEK is set (the psycopg precedent: the default install
    # stays zero-dep). FAIL LOUD + actionable if the KEK is set but the lib is missing — never a silent plaintext store.
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise _SealError("SECRETS_VAULT_KEK is set but the optional 'cryptography' package is not installed — "
                         "`pip install cryptography` to seal at rest, or unset SECRETS_VAULT_KEK") from None
    return AESGCM(key)


def _seal(value: str, name: str, version: int) -> str:
    # AT-REST SEAM. KEK unset -> PASSTHROUGH (identity — the stored bytes are PLAINTEXT, the honest zero-dep default).
    # KEK set -> AES-256-GCM seal: a fresh random 96-bit nonce; AAD = the storage slot (name\x1fversion) so a sealed
    # blob can NOT be replayed under another name/version; blob = "svgcm:<keyver>:<b64(nonce+ciphertext+tag)>".
    key = _kek()
    if key is None:
        return value
    nonce = os.urandom(12)
    ct = _aesgcm(key).encrypt(nonce, value.encode(), _vkey(name, version).encode())
    return f"{_SEAL_PREFIX}{_keyver(key)}:{base64.b64encode(nonce + ct).decode()}"


def _unseal(stored: str, name: str, version: int) -> str:
    # The inverse. KEK unset -> PASSTHROUGH (identity — today's behavior byte-for-byte). KEK set -> if the stored value
    # is a seal blob, AES-256-GCM open it (a wrong/rotated key or a relocated/tampered blob FAILS LOUD, never plaintext);
    # a value with NO seal prefix is legacy plaintext (written before the KEK was set) -> returned as-is (migration).
    key = _kek()
    if key is None:
        return stored
    if not stored.startswith(_SEAL_PREFIX):
        return stored                     # legacy plaintext (pre-KEK) — read-through so enabling a KEK is non-breaking
    try:
        _scheme, keyver, b64 = stored.split(":", 2)
    except ValueError:
        raise _SealError("malformed seal blob") from None
    if keyver != _keyver(key):
        raise _SealError("secret sealed under a different key (wrong or rotated SECRETS_VAULT_KEK)")
    try:
        blob = base64.b64decode(b64, validate=True)
        plaintext = _aesgcm(key).decrypt(blob[:12], blob[12:], _vkey(name, version).encode())
    except Exception:
        raise _SealError("secret failed to unseal (wrong key, tampered, or relocated ciphertext)") from None
    return plaintext.decode()


class SecretIn(BaseModel):
    value: StrictStr

    @field_validator("value")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("must be non-empty")
        return value


class RevealIn(BaseModel):
    version: Optional[Annotated[SafeInt, Field(ge=1)]] = None


class VersionIn(BaseModel):
    version: Annotated[SafeInt, Field(ge=1)]   # REQUIRED — you must name the version to destroy/disable/enable


def _vkey(name: str, version: int) -> str:
    return f"{name}\x1f{version}"      # name is well-formed (no separator) -> the version key can't be forged


def _state_of(meta: dict, version: int) -> str:
    # the lifecycle state of (name, version): active | pruned | destroyed | disabled | unknown. ONLY `active` reveals;
    # the other four are all a byte-indistinguishable 404 (a reveal probe can't tell evicted from never-written).
    if version < 1 or version > meta["current_version"]:
        return "unknown"
    if version < meta.get("min_version", 1):
        return "pruned"               # max_versions evicted it — bytes gone
    s = (meta.get("states") or {}).get(str(version))
    return s if s in ("destroyed", "disabled") else "active"


def _audit(request: Request, actor, action: str, name, version, outcome: str) -> None:
    # Domain-local AU-3 access audit. WHO (actor) did WHAT (action) to WHICH (name, version), WHEN (at), the OUTCOME,
    # and the SOURCE (the per-request id) — NEVER the value. APP_SECRETS_VAULT_AUDIT: off | deny (default) | all.
    mode = (os.getenv("APP_SECRETS_VAULT_AUDIT") or "").strip().lower()
    if mode not in ("off", "all"):
        mode = "deny"                 # unknown/empty/typo -> fail SAFE to the documented "deny" default
    if mode == "off" or (mode == "deny" and outcome == "allowed"):
        return
    rid = store.next_id("secrets_vault_access")
    store.put(_ACCESS, str(rid), {"id": rid, "actor": actor, "action": action, "name": name, "version": version,
                                  "outcome": outcome, "at": clock.current(request),
                                  "source": getattr(request.state, "request_id", "-")})


def _admin(action: str):
    # Admin-gate EVERY route AND audit a denial — resolved by FastAPI BEFORE the body, so a no-token caller is 401 and
    # a non-admin is 403 before validation (authn -> authz -> validation, identical x3). The denied audit captures the
    # subject (a 403 resolved the identity) + the path name; the version is unknown pre-body. A 401 (no identity) is
    # raised by require_identity before this body runs -> it is in the core access-log, not the domain audit (matches
    # rbac's _admin_dep). The function is named per-route so the audit records which action was attempted.
    def dep(request: Request, actor: str = Depends(require_identity)) -> str:
        if not is_admin(actor):
            _audit(request, actor, action, request.path_params.get("name"), None, "denied")
            raise forbidden("this operation requires the admin role")
        return actor
    return dep


@router.get("")
def list_names(request: Request, limit: str = "", cursor: str = "", actor: str = Depends(_admin("list"))) -> dict:
    # unscoped-read: admin — the vault is a GLOBAL admin resource. Lists names only (NEVER values), no per-caller owner.
    names = sorted(m["name"] for m in store.values(_META))   # names only — NEVER values; stable sort
    page, nxt, ok = paginate(names, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/access")
def access_log(request: Request, limit: str = "", cursor: str = "", actor: str = Depends(_admin("audit-read"))) -> dict:
    # unscoped-read: admin — the access audit is a GLOBAL admin resource (the _admin dep is the privileged gate); it has
    # no per-caller owner field. NEWEST-first; NEVER a value. Declared BEFORE /{name} so the static word wins the match
    # x3; "access" is a reserved name (_RESERVED_NAMES) so no secret can shadow it.
    rows = sorted(store.values(_ACCESS), key=lambda r: r["id"], reverse=True)
    page, nxt, ok = paginate(rows, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.put("/{name}", status_code=201)
def put_secret(name: str, data: SecretIn, request: Request, actor: str = Depends(_admin("put"))) -> dict:
    require_well_formed(name, "the secret name")
    if name in _RESERVED_NAMES:
        raise invalid(f"'{name}' is a reserved name")
    mx = _max_versions()
    pruned: list = []

    def bump(meta):
        nonlocal pruned
        version = (meta["current_version"] if meta else 0) + 1   # atomic, per-name, sequential
        min_v = meta.get("min_version", 1) if meta else 1
        states = dict(meta.get("states") or {}) if meta else {}
        new_min = max(min_v, version - mx + 1)                    # keep only the newest mx versions
        pruned = list(range(min_v, new_min))                     # reassign (idempotent if the callback re-runs)
        for v in pruned:
            states.pop(str(v), None)                             # drop the evicted version's lifecycle state
        return {"name": name, "current_version": version, "min_version": new_min, "states": states}, version

    version = store.do(_META, name, bump)
    try:
        sealed = _seal(data.value, name, version)               # AES-256-GCM under SECRETS_VAULT_KEK, else passthrough
    except _SealError:
        raise HTTPException(status_code=500, detail="secret could not be sealed")   # loud — never store the plaintext when a seal was requested
    store.put(_VERSIONS, _vkey(name, version), sealed)          # the immutable, SEALED version row
    for v in pruned:                                             # AFTER do() (the callback is pure — no nested store calls)
        store.delete_(_VERSIONS, _vkey(name, v))                # secure_delete=ON scrubs the evicted bytes
    _audit(request, actor, "put", name, version, "allowed")
    return {"name": name, "version": version}                   # the value is NEVER echoed back


@router.get("/{name}")
def get_meta(name: str, request: Request, actor: str = Depends(_admin("get"))) -> dict:
    meta = store.get(_META, require_well_formed(name, "the secret name"))
    if meta is None:
        _audit(request, actor, "get", name, None, "not_found")
        raise not_found("secret")
    # metadata only — NO value. Expose the non-active version states (disabled/destroyed) so an operator sees the
    # lifecycle; active versions are implied, pruned versions (< min_version) are gone and not listed.
    min_v = meta.get("min_version", 1)
    states = {v: s for v, s in (meta.get("states") or {}).items() if int(v) >= min_v}
    out = {"name": meta["name"], "current_version": meta["current_version"]}
    if states:
        out["states"] = states
    _audit(request, actor, "get", name, None, "allowed")
    return out


@router.post("/{name}/reveal")
def reveal(name: str, data: RevealIn, request: Request, actor: str = Depends(_admin("reveal"))) -> dict:
    require_well_formed(name, "the secret name")
    meta = store.get(_META, name)
    if meta is None:
        _audit(request, actor, "reveal", name, data.version, "not_found")
        raise not_found("secret")
    version = data.version if data.version is not None else meta["current_version"]
    if _state_of(meta, version) != "active":
        # pruned / destroyed / disabled / unknown all -> 404 (byte-indistinguishable: a probe can't tell which)
        _audit(request, actor, "reveal", name, version, "not_found")
        raise not_found("secret version")
    stored = store.get(_VERSIONS, _vkey(name, version))
    if stored is None:                            # defensive: state says active but the row is gone
        _audit(request, actor, "reveal", name, version, "not_found")
        raise not_found("secret version")
    try:
        value = _unseal(stored, name, version)    # AES-256-GCM open under SECRETS_VAULT_KEK, else passthrough
    except _SealError:
        raise HTTPException(status_code=500, detail="secret could not be unsealed")   # loud — never return plaintext/garbage
    _audit(request, actor, "reveal", name, version, "allowed")
    return {"name": name, "version": version, "value": value}   # the ONE path that returns the value


@router.post("/{name}/destroy")
def destroy(name: str, data: VersionIn, request: Request, actor: str = Depends(_admin("destroy"))) -> dict:
    require_well_formed(name, "the secret name")
    version = data.version

    def mark(meta):
        if meta is None:
            return None, "no-secret"        # None -> the do() leaves the row unwritten (no redundant write)
        if _state_of(meta, version) in ("unknown", "pruned"):
            return None, "no-version"       # None -> no write (the meta is untouched, not deleted)             # nothing to destroy (never existed / already evicted)
        states = dict(meta.get("states") or {})
        states[str(version)] = "destroyed"        # tombstone (idempotent; overrides 'disabled')
        return {**meta, "states": states}, "ok"

    outcome = store.do(_META, name, mark)
    if outcome != "ok":
        _audit(request, actor, "destroy", name, version, "not_found")
        raise not_found("secret" if outcome == "no-secret" else "secret version")
    store.delete_(_VERSIONS, _vkey(name, version))   # AFTER do(); secure_delete=ON scrubs the plaintext (real revocation)
    _audit(request, actor, "destroy", name, version, "allowed")
    return {"name": name, "version": version, "state": "destroyed"}


@router.post("/{name}/disable")
def disable(name: str, data: VersionIn, request: Request, actor: str = Depends(_admin("disable"))) -> dict:
    require_well_formed(name, "the secret name")
    version = data.version

    def mark(meta):
        if meta is None:
            return None, "no-secret"        # None -> the do() leaves the row unwritten (no redundant write)
        if _state_of(meta, version) in ("unknown", "pruned", "destroyed"):
            return None, "no-version"       # None -> no write (the meta is untouched, not deleted)             # can't disable a gone/destroyed version
        states = dict(meta.get("states") or {})
        states[str(version)] = "disabled"
        return {**meta, "states": states}, "ok"

    outcome = store.do(_META, name, mark)
    if outcome != "ok":
        _audit(request, actor, "disable", name, version, "not_found")
        raise not_found("secret" if outcome == "no-secret" else "secret version")
    _audit(request, actor, "disable", name, version, "allowed")
    return {"name": name, "version": version, "state": "disabled"}


@router.post("/{name}/enable")
def enable(name: str, data: VersionIn, request: Request, actor: str = Depends(_admin("enable"))) -> dict:
    require_well_formed(name, "the secret name")
    version = data.version

    def mark(meta):
        if meta is None:
            return None, "no-secret"        # None -> the do() leaves the row unwritten (no redundant write)
        st = _state_of(meta, version)
        if st == "active":
            return None, "ok"                     # already enabled -> idempotent (no write)
        if st != "disabled":
            return None, "no-version"       # None -> no write (the meta is untouched, not deleted)             # destroyed/pruned/unknown can't be re-enabled
        states = dict(meta.get("states") or {})
        states.pop(str(version), None)            # remove the 'disabled' mark -> active
        return {**meta, "states": states}, "ok"

    outcome = store.do(_META, name, mark)
    if outcome != "ok":
        _audit(request, actor, "enable", name, version, "not_found")
        raise not_found("secret" if outcome == "no-secret" else "secret version")
    _audit(request, actor, "enable", name, version, "allowed")
    return {"name": name, "version": version, "state": "enabled"}
