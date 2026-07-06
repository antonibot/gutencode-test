//go:build postgres

package core

// The Postgres store DRIVER — the same storeDriver interface as the SQLite driver, behind the KV facade. Built ONLY
// under `-tags postgres` (so the default binary stays pgx-free and go.mod unchanged); store_postgres_stub.go
// provides a fail-loud newPostgresDriver for the default build. Selected by selectDriver() when DATABASE_URL names
// Postgres.
//
// It uses pgx through database/sql with SetMaxOpenConns(1) — the SAME single-connection model as the SQLite driver,
// which means the PHYSICAL reentry guard (a nested store call inside a Do callback can't grab the held conn → ctx
// deadline → loud panic) keeps working WITHOUT a goroutine-scoped flag (Go has no goroutine-local; the
// single conn itself is the guard). Cross-PROCESS RMW is serialized by a transaction-
// scoped advisory lock (the claim-safe analog of BEGIN IMMEDIATE; FOR UPDATE locks nothing on an absent row).
//
// Values are stored as text (byte-identical to SQLite/the facade JSON — jsonb would canonicalize and diverge the
// stored bytes ×backend); `seq bigserial` gives values() a stable order.

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type postgresDriver struct{ db *sql.DB }

// scrubDSN redacts userinfo from a DSN for an error line — never echo the password. postgres://u:p@h → postgres://u:***@h.
func scrubDSN(url string) string {
	i := strings.Index(url, "://")
	if i < 0 {
		return "<dsn>"
	}
	scheme, rest := url[:i], url[i+3:]
	at := strings.Index(rest, "@")
	if at < 0 {
		return url
	}
	user := rest[:at]
	if c := strings.Index(user, ":"); c >= 0 {
		user = user[:c]
	}
	return scheme + "://" + user + ":***@" + rest[at+1:]
}

func newPostgresDriver(url string) storeDriver {
	// SCRUB-ON-DELETE HONESTY (a real security-property difference, made LOUD not silent): SQLite's global
	// `PRAGMA secure_delete=ON` zeroes a freed row's bytes on every DELETE — secrets_vault DESTROY relies on it for
	// a true revocation. Postgres has NO row-level equivalent: a DELETE (and even an overwrite — MVCC keeps the old
	// tuple) leaves plaintext in dead heap tuples until VACUUM, and in any logical replica / backup. At-rest
	// encryption answers a DIFFERENT threat (disk theft), not a live read. Selecting Postgres SILENTLY downgrades
	// the scrub for EVERY domain — refuse to start until the operator ACKNOWLEDGES it. Crypto-shred is the upgrade.
	if strings.TrimSpace(os.Getenv("SECURE_DELETE_ACK")) == "" {
		panic("the Postgres backend cannot scrub deleted bytes on delete (SQLite's secure_delete has no Postgres " +
			"equivalent) — deleted data may persist in dead tuples until VACUUM and in replicas/backups. Set " +
			"SECURE_DELETE_ACK=1 to acknowledge and proceed, or use the SQLite backend for the scrub guarantee.")
	}
	d, err := sql.Open("pgx", url)
	if err != nil {
		panic(fmt.Sprintf("could not open DATABASE_URL (%s): %v", scrubDSN(url), err))
	}
	d.SetMaxOpenConns(1) // single connection per process: the cross-goroutine reentry guard (same model as sqlite)
	if err := d.Ping(); err != nil {
		panic(fmt.Sprintf("could not connect to DATABASE_URL (%s): %v", scrubDSN(url), err))
	}
	mustExecPG(d, `CREATE TABLE IF NOT EXISTS _kv (ns text, k text, v text, seq bigserial, PRIMARY KEY (ns, k))`)
	mustExecPG(d, `CREATE TABLE IF NOT EXISTS _seq (name text PRIMARY KEY, n bigint)`)
	return &postgresDriver{db: d}
}

func mustExecPG(d *sql.DB, query string) {
	_, err := d.Exec(query)
	if err == nil {
		return
	}
	// `CREATE TABLE IF NOT EXISTS` is NOT atomic in Postgres: two cold-starting workers can both pass the existence
	// check then collide on the catalog insert ("relation already exists" / "duplicate key" / "tuple concurrently
	// updated"). The desired state IS achieved (the other worker created it) — treat the race as success, not a panic.
	e := strings.ToLower(err.Error())
	if strings.Contains(e, "already exists") || strings.Contains(e, "duplicate key") || strings.Contains(e, "concurrently") {
		return
	}
	panic(fmt.Sprintf("store init failed: %v", err))
}

// lockArg — length-prefixed (ns,k) so the map to a lock string is INJECTIVE (distinct keys never share a lock); PG's
// hashtextextended turns it into the 64-bit advisory-lock key, identically across client languages.
func lockArg(ns, key string) string {
	return fmt.Sprintf("%d:%s%s", len(ns), ns, key)
}

func (s *postgresDriver) get(ns, key string) (string, bool) {
	ctx, cancel := storeCtx()
	defer cancel()
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT v FROM _kv WHERE ns = $1 AND k = $2`, ns, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false
	}
	if err != nil {
		panic(fmt.Sprintf("store get failed: %v", err))
	}
	return raw, true
}

func (s *postgresDriver) set(ns, key, raw string) {
	ctx, cancel := storeCtx()
	defer cancel()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO _kv (ns, k, v) VALUES ($1, $2, $3) `+
		`ON CONFLICT (ns, k) DO UPDATE SET v = EXCLUDED.v`, ns, key, raw); err != nil {
		panic(fmt.Sprintf("store write failed: %v", err))
	}
}

func (s *postgresDriver) del(ns, key string) {
	ctx, cancel := storeCtx()
	defer cancel()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM _kv WHERE ns = $1 AND k = $2`, ns, key); err != nil {
		panic(fmt.Sprintf("store delete failed: %v", err))
	}
}

func (s *postgresDriver) all(ns string) []string {
	ctx, cancel := storeCtx()
	defer cancel()
	out := []string{}
	rows, err := s.db.QueryContext(ctx, `SELECT v FROM _kv WHERE ns = $1 ORDER BY seq`, ns)
	if err != nil {
		panic(fmt.Sprintf("store list failed: %v", err))
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

func (s *postgresDriver) nextID(name string) int {
	ctx, cancel := storeCtx()
	defer cancel()
	var n int
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO _seq (name, n) VALUES ($1, 1) `+
			`ON CONFLICT (name) DO UPDATE SET n = _seq.n + 1 RETURNING n`, name).Scan(&n)
	if err != nil {
		panic(fmt.Sprintf("next_id failed: %v", err))
	}
	return n
}

func (s *postgresDriver) do(ns, key string, fn func(rawCur string, exists bool) (string, bool)) {
	ctx, cancel := storeCtx()
	defer cancel()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		panic(fmt.Sprintf("store conn failed (a store call inside a Do callback would do this): %v", err))
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN`); err != nil {
		panic(fmt.Sprintf("store txn begin failed: %v", err))
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, `ROLLBACK`)
		}
	}()
	// the advisory lock is the SOLE serializer of the read-decide-write for the claim case (FOR UPDATE locks nothing
	// on an absent row); held for the whole transaction, so exactly one txn claims an absent key.
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockArg(ns, key)); err != nil {
		panic(fmt.Sprintf("store lock failed: %v", err))
	}
	var raw string
	exists := false
	if conn.QueryRowContext(ctx, `SELECT v FROM _kv WHERE ns = $1 AND k = $2`, ns, key).Scan(&raw) == nil {
		exists = true
	}
	rawNext, write := fn(raw, exists)
	if write {
		if _, err := conn.ExecContext(ctx, `INSERT INTO _kv (ns, k, v) VALUES ($1, $2, $3) `+
			`ON CONFLICT (ns, k) DO UPDATE SET v = EXCLUDED.v`, ns, key, rawNext); err != nil {
			panic(fmt.Sprintf("store write failed: %v", err))
		}
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		panic(fmt.Sprintf("store commit failed: %v", err))
	}
	committed = true
}
