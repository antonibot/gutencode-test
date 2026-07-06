package core

// Select the store DRIVER once from the environment — fail-loud (mirrors python store_factory + node store_factory).
// DATABASE_URL=postgres://… selects the Postgres driver (behind //go:build postgres); anything else selects
// SQLite (DATABASE_PATH or in-memory). A DATABASE_URL naming a backend whose driver isn't built FAILS LOUD — never a
// silent fallback to SQLite, which would mask a misconfigured production database.

import (
	"os"
	"strings"
)

// storeDriver is the backend behind the KV facade — the raw (ns, rawKey, rawJSON) interface both the sqlite and
// postgres drivers implement, so KV[K,V] is backend-agnostic.
type storeDriver interface {
	get(ns, key string) (string, bool)
	set(ns, key, raw string)
	del(ns, key string)
	all(ns string) []string
	nextID(name string) int
	do(ns, key string, fn func(rawCur string, exists bool) (string, bool))
}

// driver — the one store backend for this process, opened at package init (parity with the previous `var db`).
var driver = selectDriver()

func selectDriver() storeDriver {
	url := os.Getenv("DATABASE_URL")
	if strings.HasPrefix(url, "postgres://") || strings.HasPrefix(url, "postgresql://") {
		return newPostgresDriver(url) // the real driver under -tags postgres; a fail-loud stub in the default build
	}
	return newSqliteDriver()
}
