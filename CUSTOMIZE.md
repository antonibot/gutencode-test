# CUSTOMIZE.md — where your unique logic goes

> This is a **complete, working app** — green as shipped. You extend a green baseline; there are no gaps to fill.

## Add an endpoint (the pattern, per language)
The tree is **one domain = one module**, the same three folders everywhere: `core/` (the runtime substrate),
`parts/` (shared helpers like signing), `domains/` (one file/package per domain). Add yours the same way:

**python** — create `python/app_pkg/domains/<yours>.py` with an `APIRouter`, then register it in
`python/app_pkg/app.py` (`from .domains.<yours> import router as <yours>_router` +
`app.include_router(<yours>_router)`). Raise errors via the `..core.errors` helpers so every error keeps the
problem+json envelope.

**go** — create `go/internal/domains/<yours>/<yours>.go` (`package <yours>`, exported handlers) importing
`app/internal/core`, then add routes in `go/internal/app/app.go`
(`mux.HandleFunc("POST /your/path", <yours>.YourHandler)`). Use `core.DecodeJSON`/`core.WriteJSON`/`core.WriteProblem`.

**node** — create `node/src/domains/<yours>.js` exporting handler functions (import from `../core/runtime.js`),
then add rows to the routes table in `node/src/app.js`. Use `sendJSON`/`problem` from the runtime.

**Then declare your new route** so `verify.py` stays green: add it to `.gutencode/extensions.json` — a JSON list of
`{"method": "POST", "path": "/your/path"}` entries (add `"lang": "python"` if you added it in one language only).
This is the route counterpart of `accepted.json`: a route you declare is *yours*; a route in **neither** the
contract **nor** this list is flagged UNDECLARED, so a back-door endpoint can never hide. Also acknowledge the edit
to the shipped wiring file (`app.py` / `app.go` / `app.js`) in `.gutencode/accepted.json`.

## Use what's already here (don't re-implement)
- **State:** the durable store (`store` in python · `kvStore`/`nextID` in go · `storeGet/storePut/nextId` in node)
  — namespaced key-value + monotonic counters that survive restarts when `DATABASE_PATH` is set.
- **Signing:** HMAC helpers in `signing.*` (webhook-style + Stripe-style) — never inline crypto a second time.
- **Errors:** the problem+json helpers — one envelope everywhere.

## Ship a test with every change
Each language has a table-driven suite (`python/tests/test_app.py` · `go/app_test.go` · `node/app.test.js`).
Add your cases in the same shape: method · path · body · expected status · expected body keys.

## Run on Postgres (Supabase or any) — optional, one env var
By default the app uses **SQLite** (zero extra deps). To run on **Postgres** instead, set **`DATABASE_URL`** — no code
change. **All three runtimes — python, go, and node — support it.** One install step per language:
- **python:** `pip install 'psycopg[binary]'` — then `DATABASE_URL=postgres://… SECURE_DELETE_ACK=1 uvicorn …`
- **go:** `go get github.com/jackc/pgx/v5` then build with the tag: `go build -tags postgres ./cmd/server` — run with
  `DATABASE_URL=… SECURE_DELETE_ACK=1`
- **node:** `npm install pg` (optional dependency, lazy-loaded only for Postgres — the SQLite default stays zero-dep) —
  then `DATABASE_URL=… SECURE_DELETE_ACK=1 npm start`
- **Supabase:** use the **connection pooler** endpoint (transaction mode, port `6543`) when running serverless / many
  workers. See `.env.example` for the exact DSN shapes.

**Prove your wiring:** with `DATABASE_URL` set, `python verify.py` runs an extra **`code/durability-pg`** check that
seeds → restarts → re-checks against *your* Postgres (writes test data — use a test/staging DB).

**⚠ `secure_delete` caveat (security).** SQLite scrubs a deleted row's bytes (`PRAGMA secure_delete`), which any
secret-revocation / irreversible-delete flow relies on for a true byte scrub. **Postgres has no row-level equivalent** —
a `DELETE` leaves the plaintext in dead tuples until `VACUUM`, and in any replica/backup. So the Postgres backend
**refuses to start** until you set **`SECURE_DELETE_ACK=1`**, acknowledging the degraded guarantee. For real secret
revocation on Postgres, rely on at-rest encryption (Supabase default) plus a key-destruction (crypto-shred) scheme.

## Secrets and knobs
Wire new configuration through environment variables with safe defaults, and document them in `.env.example`
(the shipped knobs are listed there — e.g. `WEBHOOK_SECRET`). Rotate demo secrets before production.

## Keep the verifier meaningful
`python verify.py` reports: your NEW files as *custom* (info), edits to shipped files as *drift* (warn), and a new
ROUTE you add as *undeclared* unless you list it in `.gutencode/extensions.json` (see "Add an endpoint" above).
If you intentionally modify a shipped file, add its path to `.gutencode/accepted.json` so the report stays clean —
and never delete `tests/invariants/`; they prove the properties your users rely on.
