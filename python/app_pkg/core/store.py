"""Runtime `store` — the DURABLE key-value + sequence seam every domain writes its state through (never a
module-level dict). File-backed via DATABASE_PATH (survives restart — parity with the Go and Node stores), else
in-memory. THE CROSS-LANGUAGE CONTRACT (same in go/core.go and node/runtime.js):
  get(ns, key) · put(ns, key, value) · values(ns) · delete_(ns, key)    namespaces are EXPLICIT strings,
  next_id(name)                                                          identical across all three languages,
  do(ns, key, fn)                                                        so durability semantics line up.

CONCURRENCY (multi-worker safe): `next_id` is an ATOMIC upsert-returning under the database write lock — two
processes minting the same name get DISTINCT ids (no read-then-write race). WAL + a busy timeout let concurrent
readers and a writer coexist, so `uvicorn --workers N` is safe; rows survive a restart.
LIMITS: one DATABASE_PATH per machine (sqlite is single-file); `values()` scans a namespace — point reads are
sub-ms, full-namespace reads are O(rows). Swap THIS one file for a server DB (Postgres) in production at scale."""
import hashlib
import hmac
import json
import os
import secrets
import time

from .store_factory import get_driver
from .store_sqlite import StoreReentryError   # re-exported: domains/tests catch core.store.StoreReentryError

# The SQL backend lives behind a DRIVER (core/store_sqlite.py — the default; core/store_postgres.py when DATABASE_URL names Postgres), selected once by
# core/store_factory.get_driver() (lazy/memoized/fail-loud). This module is the FACADE: it owns (de)serialization +
# the public contract; the driver owns the connection, the schema, cross-process atomicity, and the reentry guard.
# Acquired at import so the open/schema happen exactly when they did before (zero behaviour change). The facade is
# backend-agnostic: durability and key semantics are identical over SQLite and Postgres.
_driver = get_driver()

__all__ = ["StoreReentryError", "get", "put", "values", "delete_", "next_id", "do",
           "session_create", "session_resolve", "session_rotate", "session_revoke", "session_revoke_all",
           "session_ttl_seconds", "api_key_resolve", "throttle"]


def get(ns: str, key: str):
    raw = _driver.get(ns, key)
    return json.loads(raw) if raw is not None else None


def put(ns: str, key: str, value) -> None:
    _driver.put(ns, key, json.dumps(value))


def values(ns: str) -> list:
    return [json.loads(r) for r in _driver.values(ns)]


def delete_(ns: str, key: str) -> None:
    _driver.delete(ns, key)


def next_id(name: str) -> int:
    """ONE durable monotonic counter per name. ATOMIC: the increment happens inside the database under the write
    lock (upsert-returning), so two processes minting the same name get DISTINCT ids — never a read-then-write
    race. Mirrors go NextID / node nextId; never a process-local counter — that would diverge across workers."""
    return _driver.next_id(name)


def do(ns: str, key: str, fn):
    """ATOMIC read-modify-write of ONE key, exclusive across PROCESSES: the driver takes the write lock BEFORE the
    read, so no other process can interleave between this read and this write. fn(current) -> (new_value | None,
    return_value); None leaves the row unwritten. This is the seam for claim/consume/append logic (exactly-once
    keys, single-use codes, chain appends) — get-then-put RACES across processes; do does not. Mirrors go
    (*KV).Do / node storeDo — one single-key semantic in all three languages.

    fn MUST be pure: it receives the current value and returns the next; it may NOT call the store (get/put/
    next_id/do) — a nested call raises StoreReentryError (the same loud failure go/node give), because a nested
    next_id/put would commit mid-transaction (breaking atomicity) and a nested get would deadlock the lock."""
    def raw_fn(raw_current):
        current = json.loads(raw_current) if raw_current is not None else None
        new, ret = fn(current)
        return (json.dumps(new) if new is not None else None), ret
    return _driver.do(ns, key, raw_fn)


# ── the cross-cutting AUTH/IDENTITY seam (core-owned sessions) ──────────────────────────────────────────────
# Sessions live in CORE, not the auth domain, so ANY domain can resolve the authenticated subject (via
# core.errors.require_identity) WITHOUT importing auth — the boundary rule holds (domains -> core only). auth
# DELEGATES session storage here (login -> session_create, /me -> session_resolve, logout -> session_revoke/_all,
# /refresh -> session_rotate). This module imports NO web framework — `now` is threaded in as an int by callers; a
# read enforces expiry against the wall clock. ns "_sessions"/"_session_index" are core's own
# (domain code never writes them).
#
# A bearer is "<id>.<secret>": the row is keyed by the public `id` and only sha256(secret) is stored, so a store/
# backup leak yields NO usable token (the secret is never persisted) and the compare is constant-time. The row
# carries an absolute `exp` (idle-sliding, extended on use) so a session is never immortal — every resolve enforces
# now < exp. Rotation (/refresh) mints a new secret +
# bumps `gen`; presenting the JUST-ROTATED (previous) secret again is theft -> the session is revoked; a secret
# matching NEITHER current nor previous is only rejected (a wrong guess on a known id must not force-logout the
# victim). Record field names are the cross-language contract (identical ×3 with go/node).
_SESSION_NS = "_sessions"
_SESSION_INDEX_NS = "_session_index"   # subject -> [session_id, ...] : revoke-all is O(k), never an O(n) scan


def _session_ttl() -> int:
    try:
        return max(60, int(os.getenv("SESSION_TTL_SECONDS", "604800")))    # default 7d (ASVS L1; 43200=12h for L2)
    except ValueError:
        return 604800


def _session_refresh() -> int:
    try:
        return max(1, int(os.getenv("SESSION_REFRESH_SECONDS", "86400")))  # idle-extend throttle: <= 1 write/day
    except ValueError:
        return 86400


def _session_reuse_grace() -> int:
    try:
        return max(0, int(os.getenv("SESSION_REUSE_GRACE_SECONDS", "10")))  # rotated-token reuse grace (benign retry)
    except ValueError:
        return 10


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _split_token(token: str):
    sid, dot, secret = (token or "").partition(".")
    if not dot or not sid or not secret:
        return None, None
    return sid, secret


def _index_add(subject: str, sid: str) -> None:
    def fn(cur):
        ids = list(cur) if cur else []
        if sid not in ids:
            ids.append(sid)
        return ids, None
    do(_SESSION_INDEX_NS, subject, fn)


def _index_remove(subject: str, sid: str) -> None:
    do(_SESSION_INDEX_NS, subject, lambda cur: ([i for i in (cur or []) if i != sid], None))


def session_create(subject: str, now: int = None) -> str:
    """Mint a durable "<id>.<secret>" bearer for an authenticated subject. Only sha256(secret) is stored; the
    secret is returned ONCE. Carries an absolute exp = now + SESSION_TTL_SECONDS (now defaults to the wall clock;
    callers thread the test clock for deterministic expiry tests). Parity with go/node."""
    now = int(time.time()) if now is None else int(now)
    sid = secrets.token_urlsafe(16)
    secret = secrets.token_urlsafe(32)
    put(_SESSION_NS, sid, {"subject": subject, "secret_hash": _sha256_hex(secret), "prev_hash": "", "prev_at": 0,
                           "exp": now + _session_ttl(), "created_at": now, "gen": 1})
    _index_add(subject, sid)
    return f"{sid}.{secret}"


def session_resolve(token: str):
    """"<id>.<secret>" -> subject (str) or None. Enforces now < exp against the wall clock, a constant-time secret
    check, and idle-sliding extension (a write at most once per SESSION_REFRESH_SECONDS). TEST SEAM: under
    APP_TEST_SESSIONS=1 a 'test:<subject>' token resolves to <subject> WITHOUT a stored session — INERT in
    production."""
    if os.getenv("APP_TEST_SESSIONS") == "1" and token.startswith("test:"):
        return token[5:] or None
    now = int(time.time())
    sid, secret = _split_token(token)
    if sid is None:
        return None
    rec = get(_SESSION_NS, sid)
    if not rec or now >= rec.get("exp", 0):
        return None
    if not hmac.compare_digest(_sha256_hex(secret), rec.get("secret_hash", "")):
        return None
    ttl = _session_ttl()
    if rec["exp"] - ttl + _session_refresh() <= now:        # idle-sliding extension, throttled
        def fn(cur):
            if not cur or now >= cur.get("exp", 0):
                return None, None                            # vanished/expired in the window -> don't resurrect
            nxt = dict(cur)
            nxt["exp"] = now + ttl
            return nxt, None
        do(_SESSION_NS, sid, fn)
    return rec["subject"]


# api_keys_records is a domain-owned namespace CORE reads directly for cross-cutting identity — the SAME pattern as
# rbac_roles (is_admin) and orgs_records (org_role): core names the NAMESPACE, never the domain. An api-key bearer
# authenticates AS the key's owner, so require_identity resolves it as a fallback AFTER a session miss.
_APIKEY_DUMMY_HASH = _sha256_hex("apikey-absent-record-filler")   # a fixed hash compared when the id is unknown


def api_key_resolve(token: str):
    """An api-key bearer 'ak_<id>_<secret>' -> its owner subject, or None. Constant-time + non-enumerable (ALWAYS
    one compare, a dummy hash when the id is unknown, so an unknown id and a wrong secret are indistinguishable —
    the same posture the api-key /verify route proves). Reads the api_keys_records namespace directly (core-owned
    cross-cutting read); reproduces the record hash with core's own sha256 (no part import). The secret may contain
    '_' (base64url), so the parse is maxsplit-2. Scopes stay advisory: a v1 key authenticates AS its owner."""
    if not token.startswith("ak_"):
        return None                                          # cheap short-circuit: not a key -> stay on the 401 path
    parts = token.split("_", 2)
    if len(parts) != 3:
        return None
    _, key_id, secret = parts
    rec = get("api_keys_records", key_id) if key_id else None
    stored = rec["secret_hash"] if rec else _APIKEY_DUMMY_HASH
    match = hmac.compare_digest(_sha256_hex(secret), stored)  # ALWAYS one constant-time compare (no timing oracle)
    if rec and rec.get("status") == "active" and match:
        return rec.get("owner")
    return None


def session_rotate(token: str, now: int = None):
    """Rotate a session's secret (/refresh) -> a new "<id>.<secret>" or None. Atomic per id. Presenting the
    just-rotated (previous) secret is REUSE -> the session is revoked (theft detection); a secret matching neither
    current nor previous is only rejected. Rotation + reuse detection are one atomic step on a single key."""
    now = int(time.time()) if now is None else int(now)
    sid, secret = _split_token(token)
    if sid is None:
        return None
    new_secret = secrets.token_urlsafe(32)
    out = {"token": None, "reuse": False, "subject": None}

    def fn(cur):
        if not cur or now >= cur.get("exp", 0):
            return None, None
        out["subject"] = cur.get("subject")
        sh = _sha256_hex(secret)
        if hmac.compare_digest(sh, cur.get("secret_hash", "")):
            nxt = dict(cur)
            nxt["prev_hash"] = cur.get("secret_hash", "")
            nxt["prev_at"] = now                             # when the prev secret was superseded (reuse-grace clock)
            nxt["secret_hash"] = _sha256_hex(new_secret)
            nxt["gen"] = cur.get("gen", 1) + 1
            nxt["exp"] = now + _session_ttl()
            out["token"] = f"{sid}.{new_secret}"
            return nxt, None
        if cur.get("prev_hash") and hmac.compare_digest(sh, cur["prev_hash"]):
            # the just-rotated secret presented again: a benign concurrent/retried /refresh WITHIN the grace window is
            # rejected but does NOT revoke (the rotated session lives); a stale reuse AFTER the grace is theft -> revoke.
            if now - cur.get("prev_at", 0) > _session_reuse_grace():
                out["reuse"] = True
        return None, None

    do(_SESSION_NS, sid, fn)
    if out["reuse"]:
        delete_(_SESSION_NS, sid)
        if out["subject"]:
            _index_remove(out["subject"], sid)
    return out["token"]


def session_revoke(token: str) -> None:
    """Drop a session (logout) by its public id; idempotent. Also de-indexes the subject."""
    sid, _secret = _split_token(token)
    if sid is None:
        return
    rec = get(_SESSION_NS, sid)
    delete_(_SESSION_NS, sid)
    if rec and rec.get("subject"):
        _index_remove(rec["subject"], sid)


def session_revoke_all(subject: str) -> None:
    """Drop ALL of a subject's sessions (logout-all / post-password-reset) — O(k) via the subject index."""
    ids = do(_SESSION_INDEX_NS, subject, lambda cur: ([], list(cur) if cur else []))
    for sid in (ids or []):
        delete_(_SESSION_NS, sid)


def session_ttl_seconds() -> int:
    """The active absolute session TTL (seconds) — auth reads it to fill the interop envelope's expires_in/at."""
    return _session_ttl()


# ── the cross-cutting THROTTLE seam (core-owned, store-backed) ──────────────────────────────────────────────
# A fixed-window counter every PRE-AUTH flow uses to bound abuse (login brute-force, reset/verify email-bomb)
# WITHOUT importing the ratelimit DOMAIN (boundary rule: domains -> core only) — the anti-automation seam.
def throttle(key: str, limit: int, window: int, now: int) -> bool:
    """Fixed-window rate limit, atomic across processes (the do seam). Returns True if ALLOWED (count <= limit in
    the window), False if over. Parity with go/node."""
    def fn(cur):
        if cur and now - cur.get("start", 0) < window:
            n = cur.get("count", 0) + 1
            return {"start": cur["start"], "count": n}, n <= limit
        return {"start": now, "count": 1}, True
    return do("_throttle", key, fn)
