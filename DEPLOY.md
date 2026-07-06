# DEPLOY.md — from a green folder to a live URL

**The 60-second picture.** One process, one port — `PORT`, default **8080** (python: pass it to uvicorn as
`--port`). State is **one SQLite file** (`DATABASE_PATH`) or **Postgres** (`DATABASE_URL`). Logs are JSON
lines on stderr. Liveness probe: **GET /health**. **Containers and PaaS need `HOST=0.0.0.0`** — the
shipped Dockerfiles set it; outside a container the default stays `127.0.0.1` (local-only) on purpose.

Each language tree ships its own container recipe — `python/Dockerfile`, `go/Dockerfile`, `node/Dockerfile`:
non-root user, port 8080, `HOST=0.0.0.0`, and `DATABASE_PATH=/data/app.db` on a `/data` volume so state
survives restarts. All three are part of the printed baseline — `python verify.py` proves the recipe you
deploy is the recipe that shipped.

## Railway — fastest URL

1. New project → **Deploy from GitHub repo** → pick your copy of this repo.
2. Set the service **Root Directory** to `python/`, `go/`, or `node/` — the Dockerfile is auto-detected.
3. Add a **volume** mounted at **`/data`** — without it every redeploy starts from an empty database (the
   image keeps state at `/data/app.db`).
4. Deploy — the URL is live. Rotate the secrets (below) before you share it. Railway injects `PORT`; the
   images honor it.

## Render / Fly.io

- **Render** — New Web Service → runtime **Docker** → set **Root Directory** to one language tree → add a
  **persistent disk** mounted at `/data`.
- **Fly.io** — run `fly launch` inside the language directory, create a volume (`fly volumes create data`)
  and mount it in `fly.toml`:

      [mounts]
      source = "data"
      destination = "/data"

  The image already binds `0.0.0.0` and serves on 8080.

## docker compose — local prod-sim

Pick ONE language profile:

    docker compose --profile python up --build
    docker compose --profile go up --build
    docker compose --profile node up --build

Postgres instead of SQLite: add the `postgres` profile — e.g.
`docker compose --profile node --profile postgres up --build` — then uncomment `DATABASE_URL` and
`SECURE_DELETE_ACK` in `docker-compose.yml` (and read the acknowledgement note below first).

## Supabase / any Postgres

1. Set `DATABASE_URL=postgres://…` **plus `SECURE_DELETE_ACK=1`**. The app refuses to boot on Postgres
   without the acknowledgement, and it means something: Postgres cannot scrub a deleted row's bytes the
   way SQLite's secure-delete pragma does (dead tuples persist until VACUUM, and in replicas/backups) —
   for true secret revocation rely on at-rest encryption or key destruction.
2. Supabase: use the **connection pooler** DSN (transaction mode, port **6543**). That is safe here by
   construction — the app's claim locks are transaction-scoped, so they work behind the pooler.
3. Install the driver: python `pip install 'psycopg[binary]'` · node `npm install --no-save pg`
   (`--no-save` keeps `package.json` byte-identical, so the baseline stays green) · go needs a rebuild —
   `go get github.com/jackc/pgx/v5 && go build -tags postgres ./cmd/server` — which edits
   `go.mod`/`go.sum`; the verifier reports that as drift, so acknowledge both files in
   `.gutencode/accepted.json` (or simply pick python or node for the Postgres path).
4. Prove it: run `python verify.py` once with `DATABASE_URL` set — it seeds, restarts, and re-checks
   durability **on your database**.

## VPS / systemd

Copy the binary (or the tree) onto the box, then — go binary shown:

    [Unit]
    Description=app
    After=network.target

    [Service]
    Environment=HOST=127.0.0.1 PORT=8080 DATABASE_PATH=/var/lib/app/app.db
    ExecStart=/usr/local/bin/server
    Restart=on-failure
    User=app

    [Install]
    WantedBy=multi-user.target

Keep `HOST` loopback here — the reverse proxy is the public face, and TLS is two lines of Caddyfile:

    api.example.com {
        reverse_proxy 127.0.0.1:8080
    }

(Railway, Render, and Fly terminate HTTPS for you; a VPS needs Caddy or nginx in front.)

## Secrets — rotate all four before the URL is public

The shipped defaults are **public knowledge** (anyone can read this code). Rotate:

    ADMIN_TOKEN            # break-glass operator endpoints -- separate from the app admin role below
    SERVICE_TOKEN          # internal service credential: background-job claim/complete + audit-event ingestion
    WEBHOOK_SECRETS        # inbound webhook signature verification
    STRIPE_WEBHOOK_SECRET  # payment webhook signature verification

One-liner for strong values: `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
`SERVICE_TOKEN` is the one operators miss — treat it like a root credential.

## Seed the first admin

There is deliberately **no magic bootstrap account**: a pre-named seed would be a claimable username —
whoever registered it first would inherit the role. So the first grant is a two-step operator action:

1. Register your own account through the app (**POST /auth/register**).
2. With the same environment the app uses (`DATABASE_PATH` or `DATABASE_URL`):

       python scripts/grant_admin.py you@example.com

   It refuses a subject that never registered, is idempotent, and works on SQLite and Postgres. No Python
   on the host? The script's header documents the raw SQL equivalent — the row layout is identical on
   both backends.

Note: `ADMIN_TOKEN` above does **not** grant this role — they are separate keys to separate doors.

## Ops notes

- **Backups** — SQLite: snapshot `/data/app.db` **and its `-wal` sibling** (or use SQLite's `.backup`);
  Postgres: provider snapshots/PITR.
- **Log drain** — logs are already structured JSON on stderr: `{level, request_id, method, path, status, ms}`.
  Point your platform's drain at stderr; `LOG_LEVEL=silent` silences access logs.
- **Scaling** — one `DATABASE_PATH` file = one machine (python `--workers N` may share that file on the one
  machine). Multiple machines = Postgres.
- **Rate limiting — honest note** — the built-in rate-limit module *computes* budgets; nothing *enforces*
  them on other routes (login has its own throttle). Put your platform's limiter or a WAF in front for a
  public launch.
- **Request timeouts** — go and node enforce their own; python delegates to the platform proxy — the
  shipped python image passes `--timeout-keep-alive 10` to uvicorn.
- **Graceful shutdown** — python (uvicorn) drains in-flight requests on SIGTERM; go and node currently
  close immediately on redeploy, so brief in-flight drops are possible on those two.
- **Interactive API docs** — python serves Swagger UI at `/docs` and the schema at `/openapi.json`
  (python-only; go and node expose no equivalent). The source is public anyway, so this reveals nothing
  new — but front it with platform access rules if you'd rather not advertise it.

## Production checklist

    [ ] State is durable: DATABASE_PATH on a volume (the /data default in the shipped images) -- or
        DATABASE_URL=postgres://... plus SECURE_DELETE_ACK=1. Unset = IN-MEMORY: a restart wipes everything.
    [ ] Secrets rotated, all FOUR: ADMIN_TOKEN, SERVICE_TOKEN, WEBHOOK_SECRETS, STRIPE_WEBHOOK_SECRET
        (the shipped defaults are public knowledge).
    [ ] First admin seeded: register your account, then  python scripts/grant_admin.py you@example.com
    [ ] HOST=0.0.0.0 in containers/PaaS (the shipped Dockerfiles set it) -- loopback is the local-dev default.
    [ ] HTTPS terminated by the platform (Railway/Render/Fly do) -- on a VPS put Caddy or nginx in front.
    [ ] APP_TEST_SESSIONS and APP_TEST_CLOCK are NOT set (test seams; inert unless exactly "1").
    [ ] Backups: SQLite -> snapshot /data/app.db + its -wal sibling. Postgres -> provider snapshots/PITR.
    [ ] Log drain pointed at stderr (JSON lines: level, request_id, method, path, status, ms).
    [ ] Rate limits enforced by your platform/WAF -- the built-in module computes budgets, it does not
        police other routes.
    [ ] python only: /docs + /openapi.json are public -- intended? (go and node expose nothing.)
    [ ] Re-run the proof against the deployed config: python verify.py (with DATABASE_URL set if on Postgres).

Eleven boxes — ticking them all is the difference between "it deployed" and "it is production".
