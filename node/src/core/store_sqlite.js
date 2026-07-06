import { DatabaseSync } from 'node:sqlite';

// The SQLite store DRIVER — the default, zero-dependency backend behind the store facade (store.js). It owns the
// connection, the schema, cross-process atomicity (BEGIN IMMEDIATE = lock-before-read), and the reentry guard. It
// speaks RAW (ns, key, rawJSON); the facade marshals, so a second driver (Postgres) implements the SAME interface
// and the facade is backend-agnostic. Built by store_factory.getDriver().

export function newSqliteDriver() {
  // Real persistence: SQLite via built-in node:sqlite (DATABASE_PATH or in-memory). WAL + a busy timeout let concurrent readers and a writer coexist, so multiple workers on one file are safe.
  const db = new DatabaseSync(process.env.DATABASE_PATH || ':memory:');
  db.exec('PRAGMA busy_timeout = 5000'); // connection-local, never contends
  db.exec('PRAGMA secure_delete = ON'); // ZERO a freed page's bytes on delete (scrub, not just unlink) so a DELETE can't be recovered from the sqlite freelist of a DB-file copy/backup — a real revocation MUST (secrets_vault DESTROY) + a security-positive default ×3

  // isTransientColdStart / retryTransient — mirror go's mustTransient + python's _retry_transient. Two+ workers
  // opening one FRESH file race on the first writes; on Windows that surfaces as a lock (busy/locked) OR a transient
  // `disk I/O error` (SQLITE_IOERR_TRUNCATE — another worker truncating the rollback journal mid-setup). RETRY any of
  // those with per-pid JITTERED backoff (desync the herd so they don't re-race in lockstep), bounded so a PERSISTENT
  // i/o error (a real disk failure) still fails loud. Sleep is synchronous (node:sqlite is sync) via Atomics.wait on a
  // throwaway SharedArrayBuffer.
  const isTransientColdStart = (e) => {
    const m = String(e).toLowerCase();
    return m.includes('locked') || m.includes('busy') || m.includes('i/o error');
  };
  const retryTransient = (query) => { // -> true on success; false if it gave up on a still-transient error
    for (let i = 0; i < 30; i++) {
      try { db.exec(query); return true; } catch (e) {
        if (!isTransientColdStart(e)) throw e; // a real error — surface it
        const jitter = (process.pid * 7 + i * 13) % 25;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 15 * (i + 1) + jitter); // synchronous backoff
      }
    }
    return false;
  };
  const mustTransient = (query) => { if (!retryTransient(query)) throw new Error(`store init failed (transient lock/io after retries): ${query}`); };

  if (process.env.DATABASE_PATH) {
    // CONVERGE to WAL: it appends instead of TRUNCATING a rollback journal, so the concurrent-journal-truncate that
    // produces the transient disk-I/O error vanishes once every worker is in WAL. Best-effort — retry the brief
    // exclusive switch, but proceed if it ultimately can't (another worker owns WAL / the FS can't): perf, not correctness.
    retryTransient('PRAGMA journal_mode = WAL');
  }
  mustTransient('CREATE TABLE IF NOT EXISTS _kv (ns TEXT, k TEXT, v TEXT, PRIMARY KEY (ns, k))');
  mustTransient('CREATE TABLE IF NOT EXISTS _seq (name TEXT PRIMARY KEY, n INTEGER)');

  // reentrancy guard: a domain must NOT call the store from inside a storeDo() callback (a nested write/commit would
  // break the transaction). node:sqlite is sync+single-threaded, so the flag is exact; a nested call throws ×3. fn PURE.
  let inDo = false;
  function guard() {
    if (inDo) {
      throw new Error('store call inside a storeDo() callback: fn must be pure (no storeGet/storePut/storeValues/'
        + 'storeDelete/nextId/storeDo) — it gets the current value and returns the next');
    }
  }

  // RAW interface: get/values return raw json strings (or undefined); put/do take raw json; the facade marshals.
  // The methods are `async` for surface parity with the Postgres driver, but node:sqlite is synchronous, so
  // each body runs to completion in one synchronous tick and resolves immediately — no behaviour change, and `do`
  // stays atomic (zero `await` between BEGIN IMMEDIATE and COMMIT, so no interleaving can split the transaction).
  return {
    db,
    async get(ns, key) {
      guard();
      const row = db.prepare('SELECT v FROM _kv WHERE ns = ? AND k = ?').get(ns, key);
      return row ? row.v : undefined;
    },
    async put(ns, key, raw) {
      guard();
      db.prepare('INSERT INTO _kv (ns, k, v) VALUES (?, ?, ?) ON CONFLICT(ns, k) DO UPDATE SET v = excluded.v').run(ns, key, raw);
    },
    async values(ns) {
      guard();
      return db.prepare('SELECT v FROM _kv WHERE ns = ? ORDER BY rowid').all(ns).map((r) => r.v);
    },
    async delete(ns, key) {
      guard();
      db.prepare('DELETE FROM _kv WHERE ns = ? AND k = ?').run(ns, key);
    },
    async nextId(name) {
      guard();
      const row = db
        .prepare('INSERT INTO _seq (name, n) VALUES (?, 1) ON CONFLICT(name) DO UPDATE SET n = n + 1 RETURNING n')
        .get(name);
      return row.n;
    },
    // do — raw read-modify-write under BEGIN IMMEDIATE (lock-before-read). fn(rawCur | undefined) -> [rawNext |
    // undefined, result]; undefined rawNext = leave unwritten. The flag makes a nested store call inside fn throw.
    // `async` for surface parity, but the body has NO `await` — it runs synchronously so the txn is uninterruptible.
    async do(ns, key, fn) {
      guard();
      db.exec('BEGIN IMMEDIATE'); // waits up to busy_timeout for the write lock; failure throws -> a loud 500
      try {
        const row = db.prepare('SELECT v FROM _kv WHERE ns = ? AND k = ?').get(ns, key);
        inDo = true;
        let rawNext, result;
        try {
          [rawNext, result] = fn(row ? row.v : undefined);
        } finally {
          inDo = false;
        }
        if (rawNext !== undefined) {
          db.prepare('INSERT INTO _kv (ns, k, v) VALUES (?, ?, ?) ON CONFLICT(ns, k) DO UPDATE SET v = excluded.v').run(ns, key, rawNext);
        }
        db.exec('COMMIT');
        return result;
      } catch (err) {
        try { db.exec('ROLLBACK'); } catch { /* the transaction never opened */ }
        throw err;
      }
    },
  };
}
