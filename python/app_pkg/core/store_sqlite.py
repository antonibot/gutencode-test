"""The SQLite store DRIVER — the default, zero-dependency backend behind the store facade (store.py). It owns the
connection, the schema, cross-process atomicity (BEGIN IMMEDIATE = lock-before-read), and the reentry guard. It
speaks in RAW keys + RAW json strings; the facade owns (de)serialization, so a second driver (Postgres) implements
the SAME six-method interface and the facade is backend-agnostic. Selected by store_factory.get_driver()."""
import os
import sqlite3
import threading
import time


class StoreReentryError(RuntimeError):
    """Raised when a domain calls the store from inside a do() callback. fn MUST be pure — it receives the current
    value and returns the next; a nested get/put/next_id/do would deadlock python+go and (silently) only work on
    node, so the seam forbids it loudly and IDENTICALLY ×3 (mirrors go's reentry guard + node's)."""


class SqliteDriver:
    """The default backend. RAW interface: get/values return raw json (or None); put/do take raw json; the facade
    marshals. One DATABASE_PATH per process; multi-worker safe (the atomic mint + WAL)."""

    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA busy_timeout = 5000")                 # connection-local, never contends — wait up to 5s on a busy lock
        self._conn.execute("PRAGMA secure_delete = ON")                  # ZERO a freed page's bytes on delete (not just unlink it) —
        # so a DELETE actually scrubs the value rather than leaving it recoverable in the sqlite freelist of any DB-file copy /
        # backup. A real revocation MUST (secrets_vault DESTROY) — and a security-positive default for every domain. Identical ×3.
        if path != ":memory:":
            # CONVERGE to WAL: it appends instead of TRUNCATING a rollback journal, so the concurrent-journal-truncate
            # that surfaces as a transient disk-I/O error vanishes once every worker is in WAL. Best-effort — retry the
            # brief exclusive switch, but proceed if it ultimately can't (another worker owns WAL): perf, not correctness.
            self._retry_transient("PRAGMA journal_mode = WAL")
        self._lock = threading.Lock()                                    # guards this process's connection across threads
        self._local = threading.local()                                  # per-thread "inside a do() callback" flag
        # The schema MUST exist (correctness); both CREATEs are idempotent. Retry transient cold-start contention, fail loud on persistence.
        self._must_transient("CREATE TABLE IF NOT EXISTS _kv (ns TEXT, k TEXT, v TEXT, PRIMARY KEY (ns, k))")
        self._must_transient("CREATE TABLE IF NOT EXISTS _seq (name TEXT PRIMARY KEY, n INTEGER)")
        self._conn.commit()

    @staticmethod
    def _is_transient_cold_start(e: BaseException) -> bool:
        # Two+ workers opening one FRESH file race on the first writes; on Windows that surfaces as a lock
        # (busy/locked — busy_timeout does NOT wait on LOCKED) OR a transient `disk I/O error`
        # (SQLITE_IOERR_TRUNCATE — another worker truncating the rollback journal mid-setup). A PERSISTENT i/o error
        # (a real disk failure) survives the bounded retry and still fails loud.
        m = str(e).lower()
        return "locked" in m or "busy" in m or "i/o error" in m

    def _retry_transient(self, query: str) -> bool:
        # Run an idempotent statement, retrying transient cold-start contention with per-pid JITTERED backoff (desync
        # N workers so they don't re-race in lockstep). Bounded (~10s). Returns True on success, False if it gave up on
        # a still-transient error. Mirrors go's retryTransient + node's. The CREATEs make ultimate failure fatal (via
        # _must_transient); the WAL switch tolerates it (best-effort).
        err = None
        for i in range(30):
            try:
                self._conn.execute(query)
                return True
            except sqlite3.OperationalError as e:
                if not self._is_transient_cold_start(e):
                    raise   # a real error, not transient cold-start contention — surface it
                err = e
                jitter = ((os.getpid() * 7 + i * 13) % 25) / 1000.0
                time.sleep(0.015 * (i + 1) + jitter)
        return False if err is not None else True

    def _must_transient(self, query: str) -> None:
        if not self._retry_transient(query):
            raise RuntimeError(f"store init failed (transient lock/io after retries): {query}")

    def _guard(self) -> None:
        if getattr(self._local, "in_do", False):
            raise StoreReentryError(
                "store call inside a do() callback: fn must be pure (no get/put/values/delete/next_id/do) — it gets "
                "the current value and returns the next")

    def get(self, ns: str, key: str):
        self._guard()
        with self._lock:
            row = self._conn.execute("SELECT v FROM _kv WHERE ns = ? AND k = ?", (ns, key)).fetchone()
        return row[0] if row else None

    def put(self, ns: str, key: str, raw: str) -> None:
        self._guard()
        with self._lock:
            # in-place UPSERT (ON CONFLICT DO UPDATE, NOT OR REPLACE): REPLACE deletes+reinserts with a NEW rowid,
            # reordering values() (rowid-ordered) on every update; ON CONFLICT preserves the rowid, so insertion order
            # stays STABLE across updates — the contract values() promises (matches the postgres seq-preserving upsert).
            self._conn.execute("INSERT INTO _kv (ns, k, v) VALUES (?, ?, ?) ON CONFLICT(ns, k) DO UPDATE SET v = excluded.v", (ns, key, raw))
            self._conn.commit()

    def values(self, ns: str) -> list:
        self._guard()
        with self._lock:
            rows = self._conn.execute("SELECT v FROM _kv WHERE ns = ? ORDER BY rowid", (ns,)).fetchall()
        return [r[0] for r in rows]

    def delete(self, ns: str, key: str) -> None:
        self._guard()
        with self._lock:
            self._conn.execute("DELETE FROM _kv WHERE ns = ? AND k = ?", (ns, key))
            self._conn.commit()

    def next_id(self, name: str) -> int:
        self._guard()
        with self._lock:
            n = self._conn.execute(
                "INSERT INTO _seq (name, n) VALUES (?, 1) "
                "ON CONFLICT(name) DO UPDATE SET n = n + 1 RETURNING n", (name,)).fetchone()[0]
            self._conn.commit()
            return n

    def do(self, ns: str, key: str, raw_fn):
        """raw_fn(raw_current: str | None) -> (raw_next: str | None, ret). Atomic across processes via BEGIN
        IMMEDIATE (lock-before-read); raw_fn runs with the reentry flag set, so a nested store call raises."""
        self._guard()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute("SELECT v FROM _kv WHERE ns = ? AND k = ?", (ns, key)).fetchone()
                raw_current = row[0] if row else None
                self._local.in_do = True
                try:
                    raw_next, ret = raw_fn(raw_current)   # PURE: a store call here raises StoreReentryError (guarded)
                finally:
                    self._local.in_do = False
                if raw_next is not None:
                    self._conn.execute("INSERT INTO _kv (ns, k, v) VALUES (?, ?, ?) ON CONFLICT(ns, k) DO UPDATE SET v = excluded.v", (ns, key, raw_next))
                self._conn.commit()
                return ret
            except BaseException:
                self._conn.rollback()
                raise
