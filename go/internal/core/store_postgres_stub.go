//go:build !postgres

package core

// The DEFAULT build carries NO Postgres backend (so the binary stays pgx-free and go.mod unchanged). If
// DATABASE_URL names Postgres here, fail LOUD with the rebuild instruction — never a silent fallback to SQLite that
// would mask a misconfigured production database. The real driver lives in store_postgres.go (//go:build postgres).
func newPostgresDriver(url string) storeDriver {
	panic("DATABASE_URL names Postgres, but this binary was built WITHOUT the Postgres backend. " +
		"Rebuild with `-tags postgres` (after `go get github.com/jackc/pgx/v5`). " +
		"Unset DATABASE_URL to use SQLite via DATABASE_PATH.")
}
