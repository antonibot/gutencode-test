# AGENT.md — operating law for this codebase

You are working in a **generated, verified backend** shipped with its own offline audit. This file is short and
authoritative: read it first, every time.

## 1 · Identity
- Three apps — `python/` · `go/` · `node/` — implement the **same 169 routes with the same behavior**.
  Domains (43): admin, agent, ai_memory, ai_provider, ai_tools, ai_workflow, api_keys, audit_log, auth, billing, chat_threads, crew, email_outbox, evals, feature_flags, file_store, health, idempotency, invitations, invoices, job_queue, ledger, llm_usage, notifications, oauth, orgs, payments, prompt_registry, rag, ratelimit, rbac, records, reporting, search, secrets_vault, settings, storage, stripe, teams, tenancy, users, vectorstore, webhooks.
- **The map is `.gutencode/contract.json`** (routes + the test contract per route). Query it before searching code.
  `INDEX.md` describes every file in one line; the per-domain pitch table is in `README.md`. Do not guess
  structure — the contract and `INDEX.md` are authoritative.
- `.gutencode/manifest.json` is the **printed baseline**: every shipped file and its hash. `python verify.py`
  compares the tree against it, so all your changes are visible — additions show as *custom*, edits to baseline
  files as *drift*.

## 2 · Build YOUR product on what's already here (map before you build)

Most of your product already exists as a domain. The job is to **wire what's shipped, then build only the part
that's genuinely yours.** Re-implementing something the catalog ships (the store, auth, search, a signing
helper) is wasted work — and often a hard failure (`code/primitives` flags a duplicated security primitive;
`code/boundaries` flags reaching into a sibling domain).

**Do this first, before any code:**
1. **Write your product as a list of capabilities** — one plain-language line each.
2. **Map each to a domain** via the pitch table in `README.md` + `.gutencode/contract.json`. Most map directly —
   reuse them **as-is** (call their routes; compose their helpers per `HELPERS.md`).
3. **Maps but needs a field/route** → a small extension of that shape (declare it in `.gutencode/extensions.json`).
4. **Maps to nothing** → that's your genuinely-new domain, the only part you truly build. Take it through
   `PRD_TEMPLATE.md` (spec → build → test → adversarial review).

**See your product in one of these — most of it is already a domain (→ = the part only you build):**

<!-- product-examples:start — the domain names below are illustrative onboarding recipes; your authoritative, always-current set is `.gutencode/contract.json` + the pitch table in `README.md`. -->

- **AI notes / writing app** — `auth`+`users` (private accounts) · `records`+`storage` (content, synced,
  survives restart) · `search`+`vectorstore` (search / *ask your notes*, RAG) · `ai_provider`+`ai_tools`
  (rewrite/expand through one seam that **fails loud**, never a silent fake) · `secrets_vault` (each user's
  provider key) · `oauth`+`idempotency` (connect an account, post/schedule, no double-post).
  **→ your note schema + the assist orchestration.**

- **B2B SaaS (teams + billing)** — `orgs`+`teams`+`rbac`+`tenancy` (workspaces, roles, isolation) ·
  `invitations` (invite teammates) · `billing`+`stripe`+`feature_flags` (plans & gating) · `api_keys`+`ratelimit`
  (programmatic access) · `webhooks`+`audit_log`+`admin` (events & an immutable trail).
  **→ the domain data your product actually manages.**

- **Agent product / copilot** — `agent`+`ai_tools`+`ai_workflow`+`crew` (the runtime & orchestration) ·
  `ai_provider`+`llm_usage` (the model seam, metered) · `chat_threads`+`ai_memory` (conversation & memory) ·
  `vectorstore` (retrieval over your corpus) · `secrets_vault` (keys). This backend is **already its own MCP
  server** (§8).
  **→ your agent's specific tools + the task it performs.**

- **API / developer platform** — `api_keys`+`oauth` (authenticated access) · `ratelimit` (per-key limits) ·
  `llm_usage`→`billing`+`stripe` (metered usage → charges) · `webhooks` (signed callbacks) · `idempotency`
  (replay-safe writes) · `tenancy`+`orgs` (isolation).
  **→ the actual API capability you sell.**

- **Marketplace / payments** — `ledger` (double-entry) + `payments`+`stripe` (money, exactly-once) ·
  `idempotency` (no double-charge) · `auth`+`users`+`orgs` (buyers & sellers) · `records`+`search` (listings) ·
  `notifications`+`webhooks` (receipts & events) · `audit_log` (trust trail).
  **→ your listings, matching, and the marketplace rules.**

<!-- product-examples:end -->

Different apps, same move: **the boring 90% is already here and proven — you build the part only you can.** The
authoritative domain set is `.gutencode/contract.json`; the one-line pitch per domain is in `README.md`. Building
the frontend too? Point your coding tool at `FRONTEND.md` (a centralized client, safe retries, no blank screens).

## 3 · Rules (each one is mechanically checked by `python verify.py` — not prose)
1. **Run `python verify.py` before AND after your work.** Done means: it exits 0 and your change ships a test.
2. **Never weaken a test, an invariant, or the verifier to get green.** The verifier and the contract are
   PROTECTED files — editing them is always a failure. Fix the code, or change an expectation WITH its test.
3. **`tests/invariants/` are correctness proofs** (money conservation, signature tamper-rejection). They must
   stay green; if your feature legitimately changes one, change the proof in the same commit, acknowledge the
   file in `.gutencode/accepted.json`, and say so.
4. **A change in one language lands in all three** — `code/parity` flags routes that exist in some languages
   only; clear the warning or state the asymmetry in your summary.
5. **State must survive a restart** — keep new state in the shipped store (`code/durability` reboots the apps
   and checks); an in-memory map will be flagged.
6. **Errors keep the one envelope** — every error path returns the same problem+json shape (`code/error-shape`
   probes all languages live).
7. **Domains never import sibling domains** — share via `core/` or `parts/` (`code/boundaries` scans imports).
8. **Prefer adding your own files** over modifying baseline files; intentional baseline edits are fine but must
   be acknowledged (`.gutencode/accepted.json`) so the drift report stays meaningful.
9. **A new route is declared, not smuggled** — list every endpoint you add in `.gutencode/extensions.json`
   (`{"method","path"}`, optional `"lang"` for a single-language addition). The contract is PROTECTED, so this is
   how `code/routes` learns your route is intentional; an undeclared route (in neither the contract nor this file)
   is a hard failure by design.

## 4 · Commands
```bash
python verify.py                        # the whole bar (baseline + all three suites + invariants + routes)
node check-baseline.js                  # baseline integrity ONLY — no Python (go: go run check-baseline.go)
cd python && python -m pytest -q        # fastest inner loop, python only
cd go && go test ./...                  # go only
cd node && npm test                     # node only
```
Run the smallest relevant check while iterating; run `python verify.py` before declaring done.

## 5 · Change process
1. Find the route/domain in `.gutencode/contract.json` and the files via `INDEX.md`.
2. Write the failing test first (each language you touch).
3. Implement; keep error responses in the same problem+json envelope the app already uses.
   The core/parts API reference is `HELPERS.md` (identity · the store · errors · validation · pagination ·
   signing · the clock) — compose those helpers, never re-implement them.
4. `python verify.py` → report: files changed · tests added · verify result. Blocked = say blocked, loudly.

## 6 · Environment knobs
Configuration knobs are documented in `.env.example`. Notable: `DATABASE_PATH` (durable SQLite state; unset = in-memory),
`PORT` (go/node serve port). `APP_TEST_CLOCK=1` is set by the test suites themselves — never set it in production;
it enables deterministic time for tests only.

## 7 · Storage backend — SQLite (default) or Postgres
The store works through a driver seam, so the **same code** runs on either backend; the domains never change.
- **SQLite** (default, zero extra deps): file-backed via `DATABASE_PATH`, else in-memory.
- **Postgres** (Supabase or any): set **`DATABASE_URL=postgres://…`** and it is used instead of SQLite. **All three
  runtimes — python, go, AND node — support Postgres.** One install step per language (see `CUSTOMIZE.md`):
  `pip install 'psycopg[binary]'` · `go get github.com/jackc/pgx/v5 && go build -tags postgres ./...` ·
  `npm install pg` (an optional dependency, lazy-loaded only when `DATABASE_URL` names Postgres — the SQLite default
  stays zero-dep).
- **⚠ `SECURE_DELETE_ACK=1` is REQUIRED on Postgres** — and the app **refuses to start without it**. SQLite scrubs a
  deleted row's bytes; Postgres cannot (deleted rows persist in dead tuples until `VACUUM`, and in replicas/backups), so
  any secret-revocation flow is weaker on Postgres unless you add at-rest encryption / crypto-shredding. Setting the
  knob acknowledges that. Do NOT remove this guard or fall back to SQLite silently when `DATABASE_URL` is set.
- **Cross-language rule still holds:** keys are stored RAW and values JSON, identically on both backends — never
  re-encode store keys per language.

## 8 · Drive it over MCP (optional)
This repo is also a Model Context Protocol server: `mcp_server.py` (stdlib-only, stdio) reads
`.gutencode/contract.json` at launch and exposes every route as a callable tool, forwarding each call to the
running backend over HTTP. `.mcp.json` is the drop-in project config (Claude Code / Cursor / Windsurf) — clients
ask for approval before starting it, and `claude mcp add` is the manual alternative.
- Start the backend first (`python dev.py`); the shipped config points tool calls at `http://127.0.0.1:8080`.
  Serving elsewhere? Set `MCP_BASE_URL` (or pass `--base-url`).
- **Trust model — zero new authority.** The server holds no credential and mints nothing: it forwards the bearer
  you provide (`MCP_BEARER` env, or an `authorization` argument per call), so every backend wall — identity,
  roles, Idempotency-Key checks, request caps — applies unchanged. A tool call can do nothing a `curl` with the
  same token could not; with no token, authenticated routes answer their normal 401.
- Tool names derive from the route (method + path segments, `{param}` → `by_<param>`); GET tools carry
  `readOnlyHint`, mutations `destructiveHint`. Input schemas are advisory hints mined from the contract's example
  cases — the backend's own validation is the real authority (a bad argument is a contained 4xx, never a crash).
