# Security

`spine` is a generated backend whose security-relevant behavior is **mechanically verified** — every property
below is checked by the shipped `python verify.py` (invariants + the three test suites) and holds **identically
across the python, go, and node** implementations. This file states what is enforced, what you must harden before
production, the known limits, and how to report a vulnerability.

## What the code enforces (proven in all three languages)

- **Authentication** — bearer sessions are minted at login; identity-gated routes reject a missing / invalid /
  expired token with `401`. Session **TTL, rotation (with reuse-detection), and revocation** (logout, logout-all)
  all hold.
- **Owner-scoping** — a resource that isn't yours reads back as **`404`**, never `403`, so existence never leaks.
- **Org / membership walls** — org-scoped routes require an ACTIVE membership; a pending invite confers nothing.
- **Mass-assignment discard** — only declared fields are accepted; smuggled fields (`owner`, `id`, `is_admin`,
  computed totals) are dropped, never stored.
- **Derived-field recompute** — money and other derived fields are recomputed server-side; a client-supplied total
  is ignored.
- **Exactly-once money** — charge / authorize / capture paths are idempotent under the same key across concurrent
  processes (one winner; replays return the stored result).
- **Constant-time compares** — tokens, secrets, and signatures are compared in constant time (no timing oracle).
- **No `eval` / `exec` / `system`** anywhere; strict integer coercion; one uniform problem+json error envelope.
- **Test seams are INERT by default** — `APP_TEST_SESSIONS`, `APP_TEST_CLOCK`, and the `?now` clock override do
  nothing unless explicitly enabled. **Never set them in production.**
- **Postgres delete honesty** — on Postgres the app refuses to start without `SECURE_DELETE_ACK=1`, because Postgres
  cannot scrub a deleted row's bytes the way SQLite's `secure_delete` does (deleted data persists in dead tuples
  until `VACUUM`, and in replicas / backups).

## Harden before production (the dangerous defaults)

The repo ships rotatable **`*_change_me`** placeholder secrets so it runs out of the box. Before any public deploy:

- **Rotate every secret** — `SERVICE_TOKEN`, `WEBHOOK_SECRETS` / `STRIPE_WEBHOOK_SECRET`, and the admin bearer
  (`ADMIN_TOKEN`). See `.env.example` and `DEPLOY.md`; generate with
  `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
- **Serve behind HTTPS** — terminate TLS at your platform or reverse proxy.
- **Bind correctly** — default `HOST=127.0.0.1` (this machine only); set `0.0.0.0` only when a proxy or container
  fronts it.
- **Seed the first admin** (`scripts/grant_admin.py`) and keep admin routes behind a real account.
- **Scope CORS** — set `CORS_ALLOWED_ORIGINS` to your exact frontend origin(s); unset = CORS off.

## Known limits (stated, not hidden)

- **Rate limiting is opt-in.** A rate-limiter is provided but does not globally enforce; wire it to the routes you
  want bounded (`RATELIMIT_LIMIT` / `RATELIMIT_WINDOW`).
- **Secret storage at-rest** — vaulted secret values are stored plaintext-at-rest unless you set a key-encryption
  key (`SECRETS_VAULT_KEK`); on Postgres, deleted rows persist until `VACUUM` (see the delete-honesty note above).
- This is a **backend** — it does not provide a WAF, DDoS protection, or bot mitigation. Put those at the edge.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue. Email the maintainer with the details and
a reproduction; you will get an acknowledgement and a fix timeline.

> **Before you publish this repo:** replace this line with your real security contact (an email or a GitHub Security
> Advisory link), so a researcher knows exactly where to send a private report.
