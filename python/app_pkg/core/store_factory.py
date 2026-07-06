"""Select the store DRIVER once from the environment — lazy, memoized, fail-loud (mirrors the storage domain's
get_provider()). DATABASE_URL=postgres://… selects the Postgres driver; anything else selects SQLite (DATABASE_PATH
or in-memory). A DATABASE_URL that names a backend whose driver isn't installed FAILS LOUD — never a silent
fallback to SQLite, which would mask a misconfigured production database."""
import os

from .store_sqlite import SqliteDriver

_driver = None


def get_driver():
    """The one store backend for this process (memoized). Scheme-sniff DATABASE_URL; default = SQLite."""
    global _driver
    if _driver is None:
        url = os.getenv("DATABASE_URL", "")
        if url.startswith("postgres://") or url.startswith("postgresql://"):
            try:
                from .store_postgres import PostgresDriver   # lazy: psycopg is an OPTIONAL dep (zero-dep default)
            except ImportError:
                raise RuntimeError(                          # fail loud — NEVER silently fall back to SQLite
                    "DATABASE_URL names Postgres, but the psycopg driver is not installed. "
                    "Install it: pip install 'psycopg[binary]'") from None
            _driver = PostgresDriver(url)
        else:
            _driver = SqliteDriver(os.getenv("DATABASE_PATH") or ":memory:")
    return _driver
