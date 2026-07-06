# PRD_TEMPLATE.md — spec a feature, build it to the bar, prove it with a review

> **What this is.** A fill-in-the-blanks Product Requirements Document **and process** for adding a feature (or a
> whole new domain) on top of this codebase. It is a *forcing function*: fill the spec, hand it to your coding
> agent, and the build → test → review flow makes it **structurally hard to ship mediocre code**. We did the heavy
> lift — you fill the blanks; your agent follows the recipe and runs its own adversarial review before calling it done.

---

## ⚡ Read this in 60 seconds

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  THE FLOW (no phase skips — depth scales with feature size):                   │
│                                                                                │
│   1. SPEC      you write §1–§7 in plain language (the human)                   │
│   2. PRE-FLIGHT your agent reads the code it will touch, IN FULL (§8)          │
│   3. BUILD     test-first, root-cause only, reuse what's here (§9–§10)         │
│   4. TEST      the hostile battery — not just the happy path (§11–§12)         │
│   5. REVIEW    3–5 INDEPENDENT adversarial agents attack the code (§13–§17)    │
│   6. DONE      verify.py green + review clean + every box checked (§18)        │
│                                                                                │
│  THE LAW:  "done" = `python verify.py` exits 0  AND  the review found nothing  │
│            unaddressed  AND  every acceptance criterion in §6 is proven by a   │
│            test. Anything less is NOT done — it is in progress.                │
│                                                                                │
│  THE STANDARD:  100% on what you build (not 98%). No TODOs, no placeholders,   │
│            no skipped/disabled tests, no "good enough". Fix the root cause,    │
│            not the symptom. If you wrote it, it must work.                     │
└──────────────────────────────────────────────────────────────────────────────┘
```

**How to use this:** copy this file to `prd/<feature>.md`. The human fills §1–§7 (plain language — no code
needed). The agent reads `AGENT.md` + `INDEX.md` + `.gutencode/contract.json` first, then executes §8 onward and
fills in the technical blanks. The review in Part 4 is **not optional** — it is the step that turns "it runs" into
"it's right."

---

# PART 1 · THE SPEC  *(the human fills this — plain language)*

## §1 · The feature in one paragraph
*What does it do, for whom, and why? The outcome, not the implementation.*

> …

## §2 · The data it owns
- **Domain name:** `__________` — lowercase, `snake_case`, **must not collide** with an existing domain (check
  `INDEX.md`) or a language built-in — a bare word like `email`, `jobs`, `time`, or `json` is risky; a qualified name
  of your own (for example `email_queue` or `task_runner`) is safe.
- **Record shape:**

  | field | type (`text`/`number`/`boolean`/`date`/`datetime`/`select`/`json`) | required? | notes |
  |---|---|---|---|
  | `title` | text | yes | example row — replace |
  | … | | | |

- **Ownership:** who may see a record? *(Almost always: only the authenticated caller who created it.)*

## §3 · The endpoints

| method | path | what it does | request body | success (status + body) | error statuses |
|---|---|---|---|---|---|
| POST | `/<domain>` | create | `{key, fields:{…}}` | 201 + the record | 401, 422 |
| GET | `/<domain>` | list (mine only, paginated) | — | 200 + `{results, next_cursor}` | 401 |
| GET | `/<domain>/{id}` | get one | — | 200 + the record | 401, 404 |
| PATCH | `/<domain>/{id}` | update | `{fields:{…}}` | 200 + the record | 401, 404, 422 |
| DELETE | `/<domain>/{id}` | delete | — | 204 | 401, 404 |

*Convention: routes live under `/<domain>`; reuse the shipped problem+json error envelope; a by-id request for a
record you don't own returns **404**, not 403 (existence must never leak).*

## §4 · The dangerous property (the invariant) — name exactly ONE
The single thing that must **always** hold, even under concurrency, restart, or hostile input:

- [ ] **money / quantity conserves** (no double-spend) · [ ] **at-most-once** (a repeat is idempotent)
- [ ] **owner isolation** (not-yours == 404; existence never leaks) · [ ] **deny-by-default**
- [ ] **durability** (committed state survives a restart) · [ ] other: `__________`

> If you cannot name the dangerous property, you do not yet understand the feature well enough to build it safely.
> This single line is the highest-leverage decision in the document.

## §5 · Languages to target
- [ ] **all three** (python + go + node) — the default; preserves the verified ×3 parity guarantee
- [ ] **one only:** `__________` — implement + test in one language (see `SINGLE_LANGUAGE.md` for both supported postures)

> **When is one language acceptable?** When your team has committed to a single stack and will only ever deploy that
> one. Then implement + test in just that language and declare your routes with `"lang"` so `code/parity` treats the
> single-language addition as intentional (no warning). You still **keep all three directories** (they are the
> verified baseline) — the shipped ×3 guarantee stays intact for the baseline; you simply don't extend the other
> two. Prefer **all three** when you want that same cross-language proof for YOUR new code, or might switch stacks later.
>
> A new endpoint must be declared in `.gutencode/extensions.json` (`{"method","path"}`, add `"lang"` if single-language)
> so `code/routes` + `code/parity` stay green; the contract is PROTECTED, so that file is how you declare intent.

## §6 · Acceptance criteria — what must be TRUE for "100% done" *(the forcing function)*
Write these as **testable** statements; every one becomes a test in §11. Tag each with **Impact** so your agent can
**size effort and sequence the work** — build and prove the *Critical* rows first, and let the highest Impact present
set the review size in §13 (any Critical → 5 reviewers + 100% rigor). If a criterion is hard to test, the feature is
under-specified — fix the spec, not the test.

| # | Criterion (must be TRUE) | Impact | Proven by (a test in §11) |
|---|---|---|---|
| 1 | A caller can create → read → list → update → delete their own `<domain>` record | High | §11.A |
| 2 | A caller **cannot** see/edit/delete another caller's record (gets 404) | **Critical** | §11.B + §11.E |
| 3 | Creating with the same key twice returns the same record (no duplicate) | **Critical** | §11.B |
| 4 | State survives a restart | High | §11.D |
| 5 | Every bad input (wrong type, missing field, oversize, hostile bytes) → clean 4xx, never 500 | High | §11.B/C |
| 6 | `<your invariant from §4>` holds under concurrent access | **Critical** | §11.E |
| … | … add the criteria specific to YOUR feature … | | |

> **Impact = production blast radius** (money · security · data-loss · tenant-isolation = **Critical**), *not* how
> hard it is to build. It tells the agent what to get right **first**, where 100% is non-negotiable, and how big a
> review the feature earns (§13). A feature with any Critical row is a "medium/large" for review purposes.

## §7 · Non-goals *(what you are explicitly NOT building)*
> List what's out of scope. This prevents scope-creep and keeps the build testable. Building beyond the spec is a
> defect, not a bonus.

---

# PART 2 · THE BUILD  *(the agent executes this, in order)*

## §8 · Pre-flight — read before you write (do NOT skip)
1. **Map before you build (`AGENT.md` §2).** List your feature's capabilities; map each to an existing domain.
   Reuse what maps; **only what maps to NOTHING is a new domain worth this document.** Rebuilding a shipped
   domain is a defect, not initiative.
2. **Read `AGENT.md` in full** — it is the operating law for this codebase.
3. **Read `INDEX.md`** (every file, one line) and **`.gutencode/contract.json`** (every route + the test contract).
   Query these before searching code — they are authoritative.
4. **Find the closest existing domain of the same shape and read it IN FULL** — its three implementations, its
   tests, its store usage, its error handling. You will copy its shape. *Reading the whole sibling file prevents the
   single most common failure: a change on line 15 that breaks an assumption on line 200.*
5. **List what already exists that you can reuse** — the store, the signing/HMAC helpers, the error envelope, any
   shared validators. Re-implementing one of these is a defect, not initiative.

## §9 · The build recipe
1. **State lives in the shipped store** (`store` python · `kvStore` go · `storeGet/storePut` node) — never an
   in-memory map (the durability check reboots the app and will catch it). Mint ids with the runtime counter.
2. **Concurrency:** any read-modify-write (claim, consume, append, counter) goes through the **atomic seam**
   (`do`/`Do`/`storeDo`), never a get-then-put. A dedup/idempotency key derives from the **caller** + the key, never
   the raw client value.
3. **Owner scoping:** stamp the owner from the **authenticated subject**, never a body field. A by-id read of another
   caller's row is 404.
4. **Reuse, don't re-implement:** the problem+json error envelope, the signing helpers, the well-formed/sanitize
   helpers. Never inline crypto or a second error shape.
5. **Declare new routes** in `.gutencode/extensions.json`; acknowledge edits to a shipped wiring file
   (`app.py`/`app.go`/`app.js`) in `.gutencode/accepted.json`.
6. **Land it in every language you committed to in §5** — the three apps are one contract.

## §10 · Test-first (the cycle, per change)
```
RED      write the failing test first — prove it fails for the right reason
GREEN    write the minimal code to pass — no gold-plating
REFACTOR clean it up — tests stay green
VERIFY   run it against the REAL app (not a mock), then `python verify.py`
```
> Fix the **first** failure first, then re-run; never skip to an easier one. Trace each failure to its **root
> cause** (infrastructure → compilation → logic → polish) — a surface fix breeds a recurring bug.

---

# PART 3 · THE TESTS  *(this IS the feature — half your effort lives here)*

## §11 · The test battery
Add table-driven cases to your language's suite (`python/tests/test_app.py` · `go/internal/app/app_test.go` ·
`node/test/app.test.js`) in the shipped `method · path · body · expected status · expected body keys` shape.

**A. Happy path** — create → get → list → update → delete, asserting status + body keys at each step.

**B. The hostile cases** *(this is what separates production-grade from "it worked once")*:
- wrong type for each field; a missing required field; an empty string where text is required
- a number beyond **±(2⁵³ − 1)** — accepted/rejected **identically** in every language you target
- a control character / lone surrogate / a body over the size cap — *contained* (clean 4xx), never a 500
- a **cross-owner** access (caller B requests caller A's id) → **404**
- a **duplicate create** with the same key → idempotent (same record, no second row)
- **trailing garbage** after the JSON object → rejected

**C. Known failure modes** *(test the failure paths, not just the sunny day)*:
- **the store:** a write that loses a race, a re-delete, a read of a missing row
- **input:** null / out-of-range / wrong-shape on every field
- **logic:** division by zero, an empty collection, an invalid state transition

**D. Durability** — a `persistence` seed→check pair whose check value is **impossible** unless state survived a restart.

**E. The invariant proof** — a test under `tests/invariants/` that drives the **real handler** (imports it or hits
the live route — never a re-implementation) and exits `0` iff the §4 property holds, `1` if violated. For a
concurrency invariant, force the worst-case interleaving with a barrier (two callers read a snapshot → sync → both
write) — a single clean natural-timing run proves nothing.

## §12 · What "a real test" means
> **A test that cannot fail proves nothing.** Before trusting a green suite: did the test actually run (not skip)?
> Would it go red if you broke the behavior on purpose? Does it assert the *result*, not just a 200? A mock-blind or
> tautological test is worse than no test — it manufactures false confidence. Delete it or make it real.

---

# PART 4 · THE POST-BUILD REVIEW  *(3–5 independent adversarial agents — MANDATORY)*

> The build proves the code *runs*. The review proves it's *right*. An independent adversarial pass routinely finds
> ~2× the real defects that solo building does — and it is cheap: 15–30 minutes that saves hours of production
> debugging. **This phase is not optional.** "Reviewed" is the difference between "done" and "shipped a bug."

## §13 · How many reviewers (scale to feature size)
| feature size | reviewers | lenses (from §15) |
|---|---|---|
| **small** (one endpoint, no new state machine) | **3** | correctness · security/ownership · tests-are-real |
| **medium / large** (new domain, money or authentication, multi-step) | **5** | + cross-language parity · invariant/red-team |

If your tool can spawn subagents, launch them **in parallel, in one message**. If it can't, run **3–5 independent
review passes** with a fresh context each — the point is *independence*, not concurrency.

## §14 · The reviewer's mandate (every reviewer does BOTH)
**(A) BREAK IT** — assume the code is wrong and try to break it. Do not summarize the code; attack it.
**(B) MAKE IT BETTER** — note the quick-win, the simpler/clearer/safer approach, the missing guard.

**The iron rule — reproduce, don't assert.** A finding counts only if it's demonstrated against the **live code**:
a throwaway script, a mutated input, a real `curl`, a failing test. "I think this could…" is a hypothesis (label it).
"I ran X and got Y" is a finding. No claim without a run.

## §15 · The lenses (give each reviewer ONE)
1. **Correctness & concurrency** — wrong results, off-by-one, mishandled null/empty/duplicate; the read-modify-write
   races (two callers, the worst-case interleave); does it lose or double-write under contention?
2. **Security & ownership** — the cross-owner access (IDOR) — can caller B touch caller A's row? deny-by-default
   honored? input validated? secrets out of code? unbounded/expensive input (DoS)?
3. **Tests-are-real** — are the new tests tautological or mock-blind? what behavior would stay green if you broke
   it? which hostile case (§11.B) is missing? does a "pass" hide a skip?
4. **Cross-language parity** — same input, all targeted languages: not just the status code but the **decision**
   (the `>2⁵³` int, the trailing byte, the unicode case). Where do they silently differ?
5. **The invariant / red-team** — attack the §4 property directly on the live app: replay, restart-loss, double-spend,
   auth bypass, the boundary cases the happy-path tests never reach.

## §16 · The finding format (every reviewer, every finding)
```
[CRITICAL | HIGH | MED | LOW]  <file>:<line> — the issue — the exact input/state that triggers it — the fix
```
Rank by **production blast radius**, not cleverness. For each real defect also ask: *should this become a regression
test?* — and add it. End every review with a **VERIFIED-CLEAN ledger**: what you tried to break and *couldn't*
(this calibrates trust and stops anyone "fixing" code that's already correct).

## §17 · Close the loop
- Every **CRITICAL/HIGH** is fixed at the **root cause** (no bridges, no `TODO: later`) — then a regression test is
  added so the class can't come back — then `python verify.py` is re-run green.
- Every **MED/LOW** is fixed, or explicitly deferred with a one-line reason recorded in the PRD.
- A finding two reviewers hit independently is high-confidence; a lone CRITICAL gets a hand-check before you act.
- Re-run the review if the fixes were substantial — fresh eyes on the changed code.

---

# PART 5 · DEFINITION OF DONE  *(the gate — every box, no exceptions)*

```
[ ] python verify.py is GREEN (or green with only intended [SKIP]s for languages you don't target)
[ ] every acceptance criterion in §6 is proven by a test in §11
[ ] the hostile battery (§11.B), known failure modes (§11.C), durability (§11.D) all covered
[ ] the invariant proof (§4 → §11.E) exists and passes — driving the REAL handler
[ ] the post-build review (§13–§17) ran with 3–5 independent reviewers; every CRITICAL/HIGH fixed + regression-tested
[ ] the VERIFIED-CLEAN ledger is recorded; MED/LOW are fixed or deferred-with-reason
[ ] new routes declared in .gutencode/extensions.json; baseline edits acknowledged in .gutencode/accepted.json
[ ] the change landed in EVERY language committed to in §5 (or the asymmetry is intentional and declared)
[ ] no new dependency (or it's pinned + intended); no security primitive duplicated
[ ] zero TODOs, zero placeholders, zero skipped/disabled tests in what you shipped
```

> If any box is unchecked, the feature is **in progress**, not done. Say so plainly — "blocked on X" beats a false
> "done". Clean code compounds: the 5% you skip today is the bug you debug for a week next month.

---

## Appendix · The review brief (copy-paste, one per reviewer)

> You are reviewing a feature just built on this codebase. Your lens is **<LENS from §15>**. Read `AGENT.md`,
> `.gutencode/contract.json`, the new `<domain>` files, and the new tests. Do **both**: (A) try to **BREAK IT** —
> bugs, races, missing ownership checks, weak/blind tests, cross-language drift, a violated invariant — and (B) say
> how to **MAKE IT BETTER**. **Check the test tiers and hunt the stale-green traps** (a recurring failure class):
> confirm the new tests ACTUALLY RAN — a `[SKIP]` for an absent toolchain/dep is **not** a pass; a suite that would
> stay green if you broke the behavior on purpose proves nothing; and `code/durability` / `code/parity` /
> `code/error-shape` must have truly exercised THIS domain, not no-op'd over it. For each §6 acceptance criterion,
> find the test that proves it and confirm it can go red. **Reproduce every finding against the live app** (a
> throwaway script, a mutated input, a real request, a failing test) — no claim without a run; mark anything you
> couldn't run *unverified*. Report each
> finding as `[SEVERITY] file:line — issue — trigger — fix`, ranked by blast radius, each with "needs a regression
> test? which?". End with a **VERIFIED-CLEAN** list: what you tried to break and couldn't. **Do not edit code —
> report only.**

---
*Built on a deterministic, verified codebase. The verifier is your contract; the review is your conscience. Green +
clean = done.*
