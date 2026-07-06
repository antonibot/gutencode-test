import { newSqliteDriver } from './store_sqlite.js';
import { newPostgresDriver } from './store_postgres.js';

// Select the store DRIVER once from the environment — lazy, memoized, fail-loud. DATABASE_URL naming Postgres
// selects the Postgres driver; anything else selects SQLite (DATABASE_PATH or in-memory).
//
// getDriver() is SYNCHRONOUS so store.js's `export const db` and the Postgres driver's SECURE_DELETE_ACK fail-loud
// check both run at import (the app refuses to boot without the ack). The drivers' METHODS are async: the
// SQLite driver is sync inside and resolves immediately; the Postgres driver awaits pg (an optional dependency it
// dynamic-imports on first use, so the SQLite default never loads it). The store surface + all handlers are async.

let _driver = null;

export function getDriver() {
  if (!_driver) {
    const url = process.env.DATABASE_URL || '';
    _driver = (url.startsWith('postgres://') || url.startsWith('postgresql://'))
      ? newPostgresDriver(url)
      : newSqliteDriver();
  }
  return _driver;
}
