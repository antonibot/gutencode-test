package core

// The SQLite store DRIVER — the default, zero-dependency backend behind the KV facade (core.go). It owns the
// connection (pure-Go modernc.org/sqlite, no cgo), the schema, cross-process atomicity (BEGIN IMMEDIATE =
// lock-before-read), and — via the single pooled connection — the reentry guard. It speaks RAW (ns, key, rawJSON);
// the KV facade marshals, so a second driver (Postgres) implements the SAME interface and the facade is
// backend-agnostic. Selected by selectDriver() (store_factory.go).

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type sqliteDriver struct{ db *sql.DB }

// newSqliteDriver opens the DURABLE store backend: file-backed via DATABASE_PATH (survives restart — parity with
// the python and node runtimes), else in-memory. WAL + a busy timeout let concurrent readers and a writer coexist,
// so multiple workers on one file are safe.
func newSqliteDriver() *sqliteDriver {
	path := os.Getenv("DATABASE_PATH")
	if path == "" {
		path = ":memory:"
	}
	d, err := sql.Open("sqlite", path)
	if err != nil {
		panic(err)
	}
	d.SetMaxOpenConns(1)                      // one connection: writes serialize; an in-memory DB stays shared; the cross-goroutine reentry guard
	mustExec(d, `PRAGMA busy_timeout = 5000`) // connection-local, never contends — wait up to 5s on a busy lock
	mustExec(d, `PRAGMA secure_delete = ON`)  // ZERO a freed page's bytes on delete (scrub, not just unlink) so a DELETE
	// can't be recovered from the sqlite freelist of a DB-file copy/backup — a real revocation MUST (secrets_vault DESTROY)
	// + a security-positive default for every domain. Identical ×3 with python/node.
	if path != ":memory:" {
		// CONVERGE to WAL (concurrent readers + one writer). Beyond the perf win, WAL appends instead of TRUNCATING a
		// rollback journal — and concurrent journal TRUNCATE between cold-starting workers on Windows is exactly what
		// surfaced as a transient `disk I/O error (SQLITE_IOERR_TRUNCATE)`. So getting every worker to WAL removes the
		// race at its source. RETRY the brief exclusive mode-switch through the transient backoff; best-effort — proceed
		// if it ultimately can't (another worker owns WAL, or the FS can't): WAL is an optimization, not correctness.
		_ = retryTransient(d, `PRAGMA journal_mode = WAL`)
	}
	// The schema MUST exist (correctness); both CREATEs are idempotent. Retry the transient cold-start contention then
	// fail loud on a persistent error.
	mustTransient(d, `CREATE TABLE IF NOT EXISTS _kv (ns TEXT, k TEXT, v TEXT, PRIMARY KEY (ns, k))`)
	mustTransient(d, `CREATE TABLE IF NOT EXISTS _seq (name TEXT PRIMARY KEY, n INTEGER)`)
	return &sqliteDriver{db: d}
}

// mustExec — a write that MUST succeed; a dropped error here is the "no silent failure" law broken in code.
func mustExec(d *sql.DB, query string, args ...any) {
	if _, err := d.Exec(query, args...); err != nil {
		panic(fmt.Sprintf("store write failed: %v", err))
	}
}

// isTransientColdStart reports whether err is transient cold-start contention worth retrying. Two+ workers opening
// one FRESH file race on the first writes; on Windows that surfaces as a lock (SQLITE_BUSY/LOCKED — busy_timeout does
// NOT wait on LOCKED) OR a transient `disk I/O error` (SQLITE_IOERR_TRUNCATE) from another worker truncating the
// rollback journal mid-setup. A PERSISTENT i/o error (a real disk failure) survives the bounded retry and still fails
// loud — we only ride out the brief concurrent-cold-start window.
func isTransientColdStart(err error) bool {
	if err == nil {
		return false
	}
	e := strings.ToLower(err.Error())
	return strings.Contains(e, "locked") || strings.Contains(e, "busy") || strings.Contains(e, "i/o error")
}

// retryTransient runs an idempotent statement, retrying transient cold-start contention with JITTERED backoff — the
// per-pid jitter desynchronizes N workers so they don't collide on every retry (a thundering herd would just re-race).
// Bounded (~10s) so a persistent error still fails loud. Returns the last error (nil on success); the caller chooses
// whether ultimate failure is fatal (WAL = best-effort, the CREATEs = MUST). Mirrors python _init + node initSchema.
func retryTransient(d *sql.DB, query string) error {
	var err error
	for i := 0; i < 30; i++ {
		if _, err = d.Exec(query); err == nil {
			return nil
		}
		if !isTransientColdStart(err) {
			return err // a real error, not transient cold-start contention — surface it
		}
		jitter := time.Duration((os.Getpid()*7+i*13)%25) * time.Millisecond // desync workers without a rand seed
		time.Sleep(time.Duration(15*(i+1))*time.Millisecond + jitter)
	}
	return err
}

// mustTransient — the schema CREATEs MUST land; retry the transient cold-start window then fail loud.
func mustTransient(d *sql.DB, query string) {
	if err := retryTransient(d, query); err != nil {
		panic(fmt.Sprintf("store init failed: %v", err))
	}
}

func (s *sqliteDriver) get(ns, key string) (string, bool) {
	ctx, cancel := storeCtx()
	defer cancel()
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT v FROM _kv WHERE ns = ? AND k = ?`, ns, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false // genuinely absent — the ONLY non-error miss
	}
	if err != nil {
		panic(fmt.Sprintf("store get failed: %v", err)) // a real query failure is LOUD, never a silent miss
	}
	return raw, true
}

func (s *sqliteDriver) set(ns, key, raw string) {
	ctx, cancel := storeCtx()
	defer cancel()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO _kv (ns, k, v) VALUES (?, ?, ?) ON CONFLICT(ns, k) DO UPDATE SET v = excluded.v`, ns, key, raw); err != nil {
		panic(fmt.Sprintf("store write failed: %v", err))
	}
}

func (s *sqliteDriver) del(ns, key string) {
	ctx, cancel := storeCtx()
	defer cancel()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM _kv WHERE ns = ? AND k = ?`, ns, key); err != nil {
		panic(fmt.Sprintf("store delete failed: %v", err))
	}
}

func (s *sqliteDriver) all(ns string) []string {
	ctx, cancel := storeCtx()
	defer cancel()
	out := []string{}
	rows, err := s.db.QueryContext(ctx, `SELECT v FROM _kv WHERE ns = ? ORDER BY rowid`, ns)
	if err != nil {
		panic(fmt.Sprintf("store list failed: %v", err)) // a query failure is LOUD, not an empty list
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			panic(fmt.Sprintf("store list scan failed: %v", err))
		}
		out = append(out, raw)
	}
	if err := rows.Err(); err != nil {
		panic(fmt.Sprintf("store list iter failed: %v", err))
	}
	return out
}

func (s *sqliteDriver) nextID(name string) int {
	ctx, cancel := storeCtx()
	defer cancel()
	var n int
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO _seq (name, n) VALUES (?, 1) `+
			`ON CONFLICT(name) DO UPDATE SET n = n + 1 RETURNING n`, name).Scan(&n)
	if err != nil {
		panic(fmt.Sprintf("next_id failed: %v", err)) // a failed mint (incl. a call from inside Do) is loud
	}
	return n
}

// do — raw read-modify-write under BEGIN IMMEDIATE (lock-before-read). fn(rawCur, exists) -> (rawNext, write);
// write=false leaves the row untouched. The single pooled conn IS the cross-goroutine serializer: a nested store
// call from inside fn waits for the held conn, bounded by storeCtx, so it fails LOUD (ctx deadline -> panic -> 500)
// instead of hanging — identically for same-key and cross-key reentry. fn MUST be pure.
func (s *sqliteDriver) do(ns, key string, fn func(rawCur string, exists bool) (string, bool)) {
	ctx, cancel := storeCtx()
	defer cancel()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		panic(fmt.Sprintf("store conn failed (a store call inside a Do callback would do this): %v", err))
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		panic(fmt.Sprintf("store txn begin failed: %v", err)) // waited busy_timeout and still locked — loud
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, `ROLLBACK`)
		}
	}()
	var raw string
	exists := false
	if conn.QueryRowContext(ctx, `SELECT v FROM _kv WHERE ns = ? AND k = ?`, ns, key).Scan(&raw) == nil {
		exists = true
	}
	rawNext, write := fn(raw, exists)
	if write {
		if _, err := conn.ExecContext(ctx, `INSERT INTO _kv (ns, k, v) VALUES (?, ?, ?) ON CONFLICT(ns, k) DO UPDATE SET v = excluded.v`, ns, key, rawNext); err != nil {
			panic(fmt.Sprintf("store write failed: %v", err))
		}
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		panic(fmt.Sprintf("store commit failed: %v", err))
	}
	committed = true
}
