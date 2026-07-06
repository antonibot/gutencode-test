# HELPERS.md — the built-in helper API (core + parts)

Every cross-cutting concern in this codebase is already written once and shipped as a helper: identity, the
durable store, the error envelope, strict validation, pagination, signing, and the clock. **Use these — never
re-implement them.** The verifier enforces it: `code/primitives` fails when a security primitive (HMAC
constructor, database open, password hashing) appears twice in one language, and `code/error-shape` fails any
error that leaves the shared envelope. Names below are exact; the three columns are the same behavior ×3.

Import helpers exactly as the existing modules do:

| language | core | parts |
|---|---|---|
| python — files in `python/app_pkg/domains/` | `from ..core import store, clock` · `from ..core.errors import invalid, require_identity` | `from ..parts.paginate import paginate` |
| go — packages in `go/internal/domains/` | `import "app/internal/core"` | `import "app/internal/parts/paginate"` |
| node — files in `node/src/domains/` | `import { problem, requireIdentity } from '../core/runtime.js'` | `import { paginate } from '../parts/paginate.js'` |

Node core/part helpers that touch the store are `async` — always `await` them.

## 1 · Identity — who is calling?

Never parse the Authorization header yourself; the subject always comes from these seams.

| what | python (`..core.errors`) | go (`core.`) | node (`../core/runtime.js`) |
|---|---|---|---|
| authenticated subject, else 401 | `subject: str = Depends(require_identity)` | `subject, ok := core.RequireIdentity(w, r)` — writes the 401, check `ok` | `const subject = await requireIdentity(req, res); if (subject === null) return;` |
| admin-only subject (401 / 403) | `Depends(require_admin)` | `core.RequireAdmin(w, r)` | `await requireAdmin(req, res)` |
| does a subject hold the admin role? | `is_admin(subject)` | `core.IsAdmin(subject)` | `await isAdmin(subject)` |
| role inside an organization | `org_role(org, subject)` — owner · admin · member, else `None` | `role, ok := core.OrgRole(org, subject)` | `await orgRole(org, subject)` |
| trusted service caller, else 401 | `Depends(require_service)` | `core.RequireService(w, r)` | `requireService(req, res)` — constant-time match against the env `SERVICE_TOKEN` |
| log out the current token | `revoke_current(request)` | `core.RevokeCurrent(r)` | `await revokeCurrent(req)` |

Ownership pattern: stamp the owner from the authenticated subject at create (never from a body field), and answer
404 — not 403 — when a caller asks for a resource that is not theirs.

## 2 · The store — durable state (never a module-level map)

State must survive a restart (`code/durability` reboots the apps and checks). Namespaces are explicit strings —
prefix yours with your feature name. String keys are stored raw and values as JSON, byte-identical across the
three languages, so all three read the same database.

| what | python (`..core.store`) | go (`core.`) | node (`../core/runtime.js`, all async) |
|---|---|---|---|
| point read / write / delete | `store.get(ns, key)` · `store.put(ns, key, value)` · `store.delete_(ns, key)` | `kv := core.NewKV[string, V]("my_ns")` then `kv.Get(k)` · `kv.Set(k, v)` · `kv.Delete(k)` | `storeGet(ns, key)` · `storePut(ns, key, value)` · `storeDelete(ns, key)` |
| all values in a namespace | `store.values(ns)` | `kv.All()` | `storeValues(ns)` |
| durable unique id | `store.next_id(name)` | `core.NextID(name)` | `nextId(name)` |
| atomic read-modify-write | `store.do(ns, key, fn)` — `fn(current) -> (new_or_None, result)` | `kv.Do(k, fn)` — `fn(cur, exists) -> (next, write)` | `storeDo(ns, key, fn)` — `fn(cur) => [next_or_undefined, result]` |

The atomicity contract of `do`: your function runs with the database write lock held **before** the read, so no
other process can slip in between that read and your write — use it for claim/consume/append logic; a bare
get-then-put races. The function must be pure: a nested store call inside it fails loudly by design.

For exactly-once writes there is a ready composition: `claim_once(ns, key, rec)` (python) ·
`idempotent_claim.ClaimOnce(kv, key, rec)` (go) · `await claimOnce(ns, key, rec)` (node) — writes `rec` only if
the key is unclaimed and always returns the settled winner. Scope any Idempotency-Key slot to the caller with
`scoped_key(route, caller, key)` from the digest part (go: `digest.ScopedKey` · node: `scopedKey`) — never use
the raw header value as a key.

## 3 · Errors — one problem+json envelope

Every error is `application/problem+json` with `{type, title, status, detail}`. The verifier probes 404 · 405 ·
413 · 422 live in all three languages and fails a divergent shape.

- **python** — raise the helper from `..core.errors`: `invalid(detail)` 422 · `not_found(resource)` 404 ·
  `conflict(detail)` 409 · `forbidden(detail)` 403 · `unauthorized(detail)` 401 · `bad_request(detail)` 400 ·
  `too_many(detail)` 429 · `gone(detail)` 410.
- **go** — `core.WriteProblem(w, status, detail)` for errors, `core.WriteJSON(w, status, v)` for success. Decode
  every body with `core.DecodeJSON[T](w, r)` — it writes the 413/422 for you and rejects trailing bytes.
- **node** — `problem(res, status, detail)` for errors, `sendJSON(res, status, value)` for success.

Semantics: 422 = well-formed request, invalid content · 409 = conflict with current state · 404 = missing OR not
yours · 401 = no valid identity · 403 = valid identity, insufficient rights.

## 4 · Validation — strict by default

- **Body integers** are strict AND bounded to ±(2^53−1), the range every language holds exactly. python: declare
  the field `SafeInt` (from `..core.errors`). go: decode the field as `json.RawMessage`, then
  `core.RequireIntRaw(raw)` (a `json.Number` variant `core.RequireInt(n)` exists; the bound is `core.MaxSafeInt`).
  node: `isStrictInt(body, 'field')`. A float `5.0`, a string `"5"`, or an oversized magnitude rejects ×3.
- **Path ids**: python `thing_id: IntPath` · go `strconv.Atoi` on the segment · node `intParam(raw)` (null on a
  malformed segment).
- **Identifiers / free-text keys** (≤1024 chars, no control characters — blocks log injection and composite-key
  forgery): python `WellFormedStr` model field or `require_well_formed(value, what)` / `is_well_formed(value)`;
  go `well_formed.IsWellFormed(value)` / `well_formed.MakeWellFormed(value)`; node `isWellFormed(value)` /
  `makeWellFormed(value)`.
- **Free-form JSON payloads**: `sanitize_json(name, value)` / `well_formed.SanitizeJSON` / `sanitizeJson` walk a
  nested value and reject bad strings/numbers; `safe_number` / `well_formed.SafeNumber` / `safeNumber` for one
  numeric field.
- **Money codes**: `is_currency(code)` / `currency.IsCurrency(code)` / `isCurrency(code)` — the ISO-4217 active
  set, case-insensitive.
- **Env knobs**: parse every integer knob through `env_int(raw, default, *bounds)` / `env_int.EnvInt(raw, def,
  bounds...)` / `envInt(raw, def, ...bounds)` — uniform malformed-value handling and clamping ×3.

## 5 · Pagination — the bounded list envelope

Every list endpoint returns `{"results": [...], "next_cursor": "..." | null}` — never an unbounded bare array.
Feed the raw `cursor` and `limit` query strings to the part and 422 on a malformed pair:

- python: `page, nxt, ok = paginate(items, cursor, limit)` — `ok` False ⇒ `raise invalid(...)`.
- go: `page, next, ok := paginate.Paginate(items, cursor, limit)`.
- node: `const { items: page, next, ok } = paginate(items, cursor, limit);`

Defaults: page size 50, max 200. Cursors are opaque and canonical — accept them as-is, never construct one.

## 6 · Signing & secrets — never inline crypto

- **Webhook signatures**: `sign_v1(secret, msg_id, timestamp, payload)` / `verify_v1(...)` implement the
  `v1,<base64>` scheme (go: `signing.SignV1` / `signing.VerifyV1` · node: `signV1` / `verifyV1`); the
  `t=…,v1=…` header scheme ships as `stripe_sign(secret, timestamp, payload)` / `stripe_verify(secret, header,
  payload, now, tolerance)` (go: `signing.StripeSign` / `signing.StripeVerify` · node: `stripeSign` /
  `stripeVerify`). Verification is constant-time with a replay-tolerance window — reuse it, do not hand-roll HMAC.
- **Fingerprints**: `digest_hex(*parts)` / `digest.DigestHex(parts...)` / `digestHex(...parts)` — one canonical
  sha256-hex convention, byte-identical ×3.
- **Passwords**: `hash_password(password, salt_b64, iterations)` + `verify_password(password, salt_b64,
  iterations, hash_b64)` (go: `password_hash.HashPassword` / `password_hash.VerifyPassword` · node:
  `hashPassword` / `verifyPassword`) — salted PBKDF2, constant-time verify. The one password primitive per app.

## 7 · The clock and the test seams (inert in production)

- **Time**: read seconds via `clock.current(request)` (python) · `core.TestNow(r)` (go) · `testNow(req)` (node).
  Under `APP_TEST_CLOCK=1` a `?now=<unix-seconds>` query overrides time for deterministic tests; without the env
  the parameter is **ignored** — a client can never set your production clock. The shipped suites set the env
  themselves.
- **Authenticated tests**: under `APP_TEST_SESSIONS=1` a header `Authorization: Bearer test:<subject>` resolves
  to `<subject>` without a stored session, and the fixed subject `root` is recognized as holding the admin role —
  so tests can exercise authenticated and admin paths without seeding. Both knobs are for test runs only:
  **NEVER set `APP_TEST_CLOCK` or `APP_TEST_SESSIONS` in production.** Unset, both seams are inert.

When you add behavior, compose these helpers; if you believe a helper itself must change, land the change in all
three languages and acknowledge the edited baseline files in `.gutencode/accepted.json` (see `AGENT.md`).
