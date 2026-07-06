# spine — a backend your coding agent can't silently break

> A **complete, working, tested** backend in **python · go · node** that ships with its **own offline verifier**.
> Point your AI agent at it and build: the moment the agent adds an undeclared route, breaks an invariant, or drifts
> the three languages apart, **`python verify.py` goes RED** instead of shipping. You extend a green baseline that
> *stays* green — **don't trust us, run the verifier.** Agents: read **`AGENT.md`** first.

<!-- ★ THE MONEY SHOT (record before launch): agent adds a route → `python verify.py` RED (it names the undeclared
     route) → declare it in .gutencode/extensions.json → GREEN. Capture a ~90-second terminal GIF of that loop and
     embed it right here — it is the single most convincing thing on this page. -->

<sub>43 domains · 169 routes · 3 languages · 1 verifier · MIT — you own the code.</sub>

<!-- CI badge — after you push to GitHub, uncomment this and fix the org/repo slug (see REPO_SETUP.md):
[![verify](https://github.com/YOUR-ORG/YOUR-REPO/actions/workflows/verify.yml/badge.svg)](https://github.com/YOUR-ORG/YOUR-REPO/actions/workflows/verify.yml)
-->

## Will this fit my app? Almost certainly — here's the map

You don't build a backend from scratch; you **wire what's already here and build only the part that's yours.**
Find your app below — the tagged pieces are shipped, proven, and identical in Python/Go/Node:

| If you're building… | …most of it is already shipped | You build |
|---|---|---|
| **AI notes / writing app** | accounts, synced storage, search + *ask-your-notes* (RAG), an AI seam that never fakes output, a vault for each user's key | your note format + the AI assist flow |
| **B2B SaaS (teams + billing)** | orgs, teams, roles, invites, subscription billing, API keys, audit trail | the data your product manages |
| **AI agent / copilot** | agent runtime + tools, a metered model gateway, threads + memory, retrieval — and it's already an MCP server | your agent's tools + its task |
| **API / developer platform** | key auth, rate limits, metered usage → billing, signed webhooks, replay-safe writes | the API you sell |
| **Marketplace / payments** | double-entry ledger, exactly-once money, buyers/sellers, listings, receipts | listings + matching |

**Point your coding agent at this repo:** it reads `AGENT.md`, runs `python verify.py` → GREEN, maps your app to
the domains above, and builds the rest **on a foundation it can't accidentally break.** The full method +
per-app domain lists are in `AGENT.md` §2.

## First 10 minutes
- `python dev.py` — serve whichever runtime this machine has, on one port (**:8080**)
- **`TOUR.md`** — the 10-minute copy-paste walkthrough: first request → sign up → create → AI → money → prove it
- `requests.http` — every route as a clickable request (VS Code REST Client / JetBrains); the login token chains itself
- `python scripts/seed.py` — fill the running app with demo data through its own public API
- Your agent can drive this backend natively — `.mcp.json` + `mcp_server.py` make every route a callable MCP
  tool (same auth, same walls, zero new authority); see `AGENT.md`
- Pushing to GitHub? `REPO_SETUP.md` (badge, topics, social preview) · `.devcontainer/` gives Codespaces all three toolchains

## Quickstart (each language is independently runnable)
**python**
```bash
cd python
pip install -r requirements.txt
python -m pytest -q                      # the test suite
uvicorn app_pkg.app:app --port 8080      # serve (8080 is the one port all the docs use)
```
**go**
```bash
cd go
go test ./internal/app                   # the test suite (it lives in internal/app)
go run ./cmd/server                      # serves on :8080 (PORT env to change)
```
**node**
```bash
cd node
npm test                                 # the test suite (node --test)
npm start                                # serves on :8080 (PORT env to change)
```
**then, from the repo root**
```bash
python verify.py                         # prove everything works before you touch anything
```

## What's inside — 43 domains, 169 identical routes, 3 languages
Every domain below ships in all three languages with the same routes and the same behavior, plus its tests.
The machine-readable map is `.gutencode/contract.json` (every route + the test contract per route);
`INDEX.md` describes every file in one line.

### Identity & access
| domain | what it gives you |
|---|---|
| `admin` | admin-only actions behind a bearer token, every action logged immutably |
| `api_keys` | issue, verify, rotate, and revoke scoped API keys — secrets hashed, shown only once |
| `auth` | email/password auth with sessions, refresh, logout, password reset, and verification |
| `oauth` | OAuth 2.0 authorization-code flow (server side) |
| `rbac` | role-based access control — deny by default, admin-gated changes |
| `secrets_vault` | versioned secret storage — reveal-once reads, irreversible destroy, access audit |
| `users` | user profiles + lifecycle, separate from auth credentials |

### Organizations & multi-tenancy
| domain | what it gives you |
|---|---|
| `invitations` | invite + accept flow with single-use, expiring tokens |
| `orgs` | organizations/workspaces with roles, member invites, and exactly one owner |
| `teams` | teams within an org — managed only by that org's owners and admins |
| `tenancy` | tenant isolation — another tenant's rows are invisible, not just forbidden |

### Money & billing
| domain | what it gives you |
|---|---|
| `billing` | subscription billing — plans from a fixed catalog, prices never client-set |
| `invoices` | multi-line invoices — totals always recomputed server-side, never client-set |
| `ledger` | double-entry ledger — every transaction balances, balances are derived |
| `llm_usage` | per-call LLM token and cost metering — server-priced, deduplicated, integer-exact |
| `payments` | provider-agnostic payment intents with idempotent, race-safe creation |
| `stripe` | Stripe-compatible charges and webhook verification with secret rotation |

### AI & agents
| domain | what it gives you |
|---|---|
| `agent` | AI agent runtime — sessions, tool calls, and a bounded run loop that always stops |
| `ai_memory` | long-term agent memory with TTL, size caps, and per-user isolation |
| `ai_provider` | one LLM gateway for completions — caching, usage metering, swappable providers |
| `ai_tools` | a typed tool registry agents call over HTTP — arguments validated, errors contained |
| `ai_workflow` | multi-step AI pipelines that always terminate — failures return a trace, not a crash |
| `chat_threads` | durable chat threads with ordered message history, per-user isolation, and size caps |
| `crew` | multi-agent orchestration — handoffs always terminate, even when roles loop |
| `evals` | score model outputs against frozen golden suites — deterministic and offline |
| `prompt_registry` | versioned, immutable prompt templates with movable labels and safe {{var}} rendering |
| `rag` | retrieval pipeline — chunk, embed, rank, and cite over each user's own documents |
| `vectorstore` | embedding index + top-k cosine retrieval — per-user and deterministic |

### Data & content
| domain | what it gives you |
|---|---|
| `file_store` | store and serve real file bytes with per-user quotas and content-addressed etags |
| `records` | typed, owner-scoped CRUD records — the substrate to model your app's objects on |
| `reporting` | owner-scoped analytics — ingest facts, run group-by rollups with exact sums |
| `search` | token full-text search over each user's own documents |
| `settings` | owner-scoped settings with a fixed, typed schema |
| `storage` | object storage behind a swappable provider — per-user keys, content-addressed etags |

### Platform & reliability
| domain | what it gives you |
|---|---|
| `audit_log` | append-only, hash-chained audit trail — tampering is detectable |
| `email_outbox` | outbound email with exactly-once sends and header-injection protection |
| `feature_flags` | feature flags with deterministic percentage rollout — no flapping mid-ramp |
| `health` | liveness probe at GET /health |
| `idempotency` | replay-safe writes via Idempotency-Key — a retry can never double-charge |
| `job_queue` | background job queue with leases, retries with backoff, and dead-lettering |
| `notifications` | in-app notifications with forgery-proof senders and read-state |
| `ratelimit` | fixed-window rate limiting that holds under concurrent processes |
| `webhooks` | signed outbound + verified inbound webhooks with secret rotation and replay dedup |

## Verify everything (the one command)
```bash
python verify.py            # offline: baseline intact · all three suites · invariants · routes vs contract ·
                            #          cross-language parity · error-envelope shape · restart durability ·
                            #          domain boundaries · shared helpers implemented once
python verify.py --strict   # also fail (not just warn) when generated files were modified
```
Two reports: **BASELINE** (is the shipped baseline intact?) and **CODE** (do the apps still pass their contract?).
Files you ADD are reported as custom (info). Files from the printed baseline you MODIFY are reported as drift
(warn; acknowledge intentional changes in `.gutencode/accepted.json`). The verifier and the contract themselves
are PROTECTED — modifying them is always a failure, so the guardrails can't be weakened silently.

**No Python?** Run the offline **integrity** proof in your own runtime — `node check-baseline.js` or
`go run check-baseline.go` (zero deps). It recomputes every baseline file's hash against `.gutencode/manifest.json`
(the "is this the code I was given, unmodified?" check) and exits non-zero on any tamper. Pair it with your own
suite (`npm test` / `go test ./internal/app`) for a complete check without Python; `python verify.py` remains the
full cross-language proof.

## Configuration
Copy `.env.example` to `.env`-style env vars for your process manager. Defaults work out of the box;
`DATABASE_PATH` makes SQLite state durable on disk (unset = in-memory). Auth work factors, rate limits, and
AI caps are tunable the same way — `.env.example` documents the knobs by domain.

**Interactive API docs (python-only):** the python app serves Swagger UI at `/docs` and the raw schema at
`/openapi.json` — a FastAPI default; go and node expose no equivalent surface. Both are public on a deployed
python instance (the source is open anyway) — see `DEPLOY.md` if you'd rather gate them.

### Storage backend: SQLite (default) or Postgres / Supabase
The same code runs on either backend. Default is **SQLite** (zero extra deps). To run on **Postgres / Supabase**,
set **`DATABASE_URL=postgres://…`** plus **`SECURE_DELETE_ACK=1`** (required — see the note below) and one install
step per language. **All three runtimes — python, go, and node — support Postgres** (node loads the optional `pg`
package only when `DATABASE_URL` names Postgres, so the SQLite default stays dependency-free). Full steps + the
Supabase pooler DSN are in `.env.example` and `CUSTOMIZE.md`.

> **`SECURE_DELETE_ACK`** — Postgres cannot scrub a deleted row's bytes the way SQLite does (they linger in dead
> tuples until `VACUUM`, and in backups/replicas), so secret-revocation is weaker there; the app refuses to start on
> Postgres until you acknowledge this. With `DATABASE_URL` set, `python verify.py` also proves durability on *your*
> Postgres.

## Extend it
See `CUSTOMIZE.md` — add your endpoints/logic per language, declare new routes in `.gutencode/extensions.json`,
ship a test with every change, keep `verify.py` green. For a whole feature, start from `PRD_TEMPLATE.md`
(spec → build → test → review).

**Building a UI on it?** See `FRONTEND.md` — a centralized API client, safe retries with backoff, and the
loading/error/empty wiring that stops the blank-screen bug, all built on this backend's one error shape +
machine-readable contract. Hand it to your coding agent and the frontend gets wired right the first time.

## Deploy it
See `DEPLOY.md` — per-language Dockerfiles (already in each tree), `docker-compose.yml`, a GitHub Actions
workflow (`.github/workflows/verify.yml`) that re-runs the full proof on every push, Railway/Render/Fly/VPS
walkthroughs, first-admin seeding (`scripts/grant_admin.py`), and an 11-line go-live checklist.

## Upgrading
This is **edition `1c7ca5fc0e0b55aa`**. To take a newer edition without losing your changes, see `UPGRADE.md`
(a normal `git merge` against a pristine baseline branch — deterministic exports make the diff meaningful).

## What this is NOT
- **Not a no-code/visual builder.** You (or your coding agent) still write your product's unique logic — this is
  the proven foundation under it, not a drag-and-drop app maker.
- **Not a hosted service or BaaS you rent.** It's a real repo you **own** (MIT). It runs on your infrastructure;
  nothing phones home; there's no dashboard to log into and no vendor to depend on.
- **Not a frontend or UI kit.** This is the backend spine. Bring your own web/mobile/desktop UI — it talks to
  these routes (or drives them as MCP tools). See `FRONTEND.md` for wiring one up.
- **Not an AI that writes your whole app for you.** It's the opposite: a fixed, tested foundation your AI builds
  **on top of** and **cannot silently break** (an undeclared route or a weakened test is a hard fail). The AI does
  the creative part; the guardrails keep it honest.
- **Not a new framework to learn.** Idiomatic, standard-stack code in each language — no bespoke DSL, no magic. If
  you know FastAPI / Go net/http / Node, you already know how to read it.
- **Not "everything configured for production" on unzip.** Some seams are deliberately yours to wire (e.g. a real
  AI provider adapter is opt-in and **fails loud** until you configure it — never a fake). The docs say which.
- **Not a lock-in to three languages.** Keep the one you ship; delete the other two — the verifier still proves the
  kept language green (`SINGLE_LANGUAGE.md`).
- **Not a database or an ORM.** It's the whole backend, with a store seam that runs on SQLite (zero-dep default) or
  Postgres/Supabase — not a library you assemble an app around.

---
*Edition `1c7ca5fc0e0b55aa` · licensed under `LICENSE` (MIT — you own this code).*
