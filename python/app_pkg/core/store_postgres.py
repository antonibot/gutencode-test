"""The Postgres store DRIVER — the same six-method interface as the SQLite driver, behind the store facade. Selected
by store_factory when DATABASE_URL names Postgres (Supabase or any). psycopg is an OPTIONAL dependency (a commented
line in requirements.txt) imported lazily, so the default install stays zero-dep.

The dangerous translation: SQLite's `do()` takes a whole-DB write lock with BEGIN IMMEDIATE *before* the read,
which serializes the insert-first/claim case (the exactly-once claim seam — single-use codes, the money path).
Postgres has no IMMEDIATE, and
`SELECT … FOR UPDATE` locks NOTHING on a not-yet-existing row — so it cannot serialize a claim. The correct analog is
`pg_advisory_xact_lock(<key>)` held for the whole transaction: exactly one transaction holds the per-key lock at a
time, so the read-decide-write is serialized even when the row is absent. The lock key is PG's own
`hashtextextended` over a LENGTH-PREFIXED `(ns,k)` encoding (64-bit, injective — distinct keys never collide via
ns‖k ambiguity, and identical across client languages since PG computes the hash).

Values are stored as `text` — byte-identical to the SQLite/​facade JSON, so the cross-language raw-value contract
holds (jsonb would CANONICALIZE — reorder keys / strip whitespace — diverging the stored bytes ×backend). The
`seq bigserial` gives `values()` a stable insertion order (SQLite's rowid has no PG equivalent). Track B (the
deferred query() pushdown) adds an expression index via `(v::jsonb)->>'field'` when a measured workload needs it."""
import psycopg

from .store_sqlite import StoreReentryError   # the SAME reentry exception ×backend (domains catch one class)


def scrub_dsn(url: str) -> str:
    """Redact userinfo from a DSN for an error/log line — never echo the password. postgres://u:p@h → postgres://u:***@h."""
    try:
        scheme, rest = url.split("://", 1)
        if "@" in rest:
            userinfo, host = rest.split("@", 1)
            user = userinfo.split(":", 1)[0]
            return f"{scheme}://{user}:***@{host}"
        return url
    except ValueError:
        return "<dsn>"


class PostgresDriver:
    """A single autocommit connection guarded by a process lock (the SQLite driver's model). Multi-worker safety:
    each worker process has its own connection; next_id is an atomic upsert-returning, do() is serialized across
    processes by a transaction-scoped advisory lock (pooler-safe — released at commit)."""

    def __init__(self, url: str):
        import os
        import threading
        # SCRUB-ON-DELETE HONESTY (a real security-property difference, made LOUD not silent): SQLite's global
        # `PRAGMA secure_delete=ON` zeroes a freed row's bytes on every DELETE — secrets_vault DESTROY relies on it
        # for a true revocation. Postgres has NO row-level equivalent: a DELETE (and even an overwrite — MVCC keeps
        # the old tuple) leaves the plaintext in dead heap tuples until VACUUM, and in any logical replica / backup.
        # At-rest encryption answers a DIFFERENT threat (disk theft), not a live read. So selecting Postgres SILENTLY
        # downgrades the scrub guarantee for EVERY domain — refuse to start until the operator ACKNOWLEDGES it. Set
        # SECURE_DELETE_ACK=1 to proceed (you accept deleted data may persist until VACUUM; rely on at-rest
        # encryption / crypto-shred). Crypto-shredding (a per-secret key destroyed on DESTROY) is the real upgrade.
        if not (os.environ.get("SECURE_DELETE_ACK") or "").strip():
            raise RuntimeError(
                "the Postgres backend cannot scrub deleted bytes on delete (SQLite's secure_delete has no Postgres "
                "equivalent) — deleted data may persist in dead tuples until VACUUM and in replicas/backups. Set "
                "SECURE_DELETE_ACK=1 to acknowledge and proceed, or use the SQLite backend for the scrub guarantee.")
        try:
            self._conn = psycopg.connect(url, autocommit=True)
        except psycopg.Error as e:
            raise RuntimeError(f"could not connect to DATABASE_URL ({scrub_dsn(url)}): {e.__class__.__name__}") from None
        self._lock = threading.Lock()
        self._local = threading.local()
        with self._lock:
            self._init_table("CREATE TABLE IF NOT EXISTS _kv (ns text, k text, v text, seq bigserial, PRIMARY KEY (ns, k))")
            self._init_table("CREATE TABLE IF NOT EXISTS _seq (name text PRIMARY KEY, n bigint)")

    def _init_table(self, ddl: str) -> None:
        # `CREATE TABLE IF NOT EXISTS` is NOT atomic in Postgres: two cold-starting workers can both pass the
        # existence check then collide ("relation already exists" / "duplicate key" / "tuple concurrently updated").
        # The table DOES exist after the race — treat it as success, not an error (parity with go's mustExecPG).
        try:
            self._conn.execute(ddl)
        except psycopg.Error as e:
            msg = str(e).lower()
            if "already exists" not in msg and "duplicate key" not in msg and "concurrently" not in msg:
                raise

    def _guard(self) -> None:
        if getattr(self._local, "in_do", False):
            raise StoreReentryError(
                "store call inside a do() callback: fn must be pure (no get/put/values/delete/next_id/do) — it gets "
                "the current value and returns the next")

    @staticmethod
    def _lock_arg(ns: str, key: str) -> str:
        # length-prefixed so the (ns,k) -> string map is INJECTIVE (distinct keys never share a lock); PG's
        # hashtextextended turns it into the 64-bit advisory-lock key, identically across client languages.
        return f"{len(ns)}:{ns}{key}"

    def get(self, ns: str, key: str):
        self._guard()
        with self._lock:
            row = self._conn.execute("SELECT v FROM _kv WHERE ns = %s AND k = %s", (ns, key)).fetchone()
        return row[0] if row else None

    def put(self, ns: str, key: str, raw: str) -> None:
        self._guard()
        with self._lock:
            self._conn.execute("INSERT INTO _kv (ns, k, v) VALUES (%s, %s, %s) "
                               "ON CONFLICT (ns, k) DO UPDATE SET v = EXCLUDED.v", (ns, key, raw))

    def values(self, ns: str) -> list:
        self._guard()
        with self._lock:
            rows = self._conn.execute("SELECT v FROM _kv WHERE ns = %s ORDER BY seq", (ns,)).fetchall()
        return [r[0] for r in rows]

    def delete(self, ns: str, key: str) -> None:
        self._guard()
        with self._lock:
            self._conn.execute("DELETE FROM _kv WHERE ns = %s AND k = %s", (ns, key))

    def next_id(self, name: str) -> int:
        self._guard()
        with self._lock:
            return self._conn.execute(
                "INSERT INTO _seq (name, n) VALUES (%s, 1) "
                "ON CONFLICT (name) DO UPDATE SET n = _seq.n + 1 RETURNING n", (name,)).fetchone()[0]

    def do(self, ns: str, key: str, raw_fn):
        """raw_fn(raw_current | None) -> (raw_next | None, ret). Serialized across processes by the per-key
        transaction-scoped advisory lock (the claim-safe analog of BEGIN IMMEDIATE)."""
        self._guard()
        with self._lock:
            with self._conn.transaction():
                self._conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (self._lock_arg(ns, key),))
                row = self._conn.execute("SELECT v FROM _kv WHERE ns = %s AND k = %s", (ns, key)).fetchone()
                raw_current = row[0] if row else None
                self._local.in_do = True
                try:
                    raw_next, ret = raw_fn(raw_current)
                finally:
                    self._local.in_do = False
                if raw_next is not None:
                    self._conn.execute("INSERT INTO _kv (ns, k, v) VALUES (%s, %s, %s) "
                                       "ON CONFLICT (ns, k) DO UPDATE SET v = EXCLUDED.v", (ns, key, raw_next))
            return ret
