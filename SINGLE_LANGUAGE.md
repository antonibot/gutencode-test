# SINGLE_LANGUAGE.md — using only one of the three languages

This backend ships three times — `python/`, `go/`, `node/` — with identical routes and behavior, and the three
implementations cross-check each other (`python verify.py` proves it). Most teams deploy exactly one. Both of
these postures are supported; pick the one that fits how you work.

## Posture 1 — keep all three on disk, run one (zero config — recommended)

1. Install only your language's toolchain and deps; skip the other two.
2. Develop, test, and deploy your language only (see README.md Quickstart).
3. `python verify.py` stays GREEN: the languages you don't run show a loud
   `[SKIP] code/tests-go  toolchain not installed — install Go: …` — never a silent pass, never a failure.

The unused trees cost **nothing at runtime** — they are dormant files. The checks that read source instead of
running it (baseline integrity, route tables, cross-language parity, boundaries, security primitives) still
cover all three, so you keep the full cross-checked guarantee while running one.

## Posture 2 — delete the trees you don't want (acknowledged removal)

If you want a one-language repo on disk, the verifier supports removal — but it must be **acknowledged**, so a
missing tree is always a decision on record, never an accident it stays quiet about.

1. **Delete the whole tree(s)** you don't want (e.g. `go/` and `node/` — whole directories, not single files).
2. **Acknowledge the removal** in `.gutencode/accepted.json` (a file you own; it ships as `[]`). Change it to:

   ```json
   {
     "files": [],
     "removed_languages": ["go", "node"]
   }
   ```

   `files` is the same list of acknowledged file edits the plain form holds today (a plain list still works);
   `removed_languages` names the deleted trees. For go-only keep `["python", "node"]`, and so on.
3. **Run `python verify.py`** — it stays meaningful and can still end `==== VERIFY: GREEN ====`.

What the verifier does after an acknowledged removal:

| check | behavior |
|---|---|
| baseline | one loud line per removed tree — `[ OK ] baseline/removed  go/ removed by owner (acknowledged)` — and every remaining file is still hash-checked |
| suites · routes · error envelope · durability (removed languages) | one visible `[SKIP] … removed by owner` per language — never silent |
| cross-language parity | two languages left → they are compared; one left → `[SKIP]` with a loud note |
| your kept language | everything still runs: its test suite, the invariant proofs, route coverage, error-envelope probes, restart durability, boundaries, primitives, dependency surface |
| protected files | unchanged — editing `verify.py`, `check-baseline.js`/`.go`, or `.gutencode/contract.json` is still an unconditional failure; removal can never weaken the verifier itself |

Deleting a tree **without** the acknowledgment is a loud FAIL (`baseline/complete … MISSING`), never a crash —
the report tells you exactly which key to add.

## What you give up

The **cross-language parity proof** — three independent implementations agreeing on every route and every error
byte is the strongest evidence this backend does exactly what the printed contract says. Once a tree is gone,
that proof is off (the verifier says so on every run). To get it back, restore the trees from your `git` history
(or re-clone the original) and set `removed_languages` back to `[]`.

## One honest note about the offline checkers

`check-baseline.js` and `check-baseline.go` (the no-Python integrity helpers) verify the **full printed
baseline** and don't read the acknowledgment — after a removal they will report the deleted files as missing.
That is expected: after removing a language, `python verify.py` is the check to run. The two helpers remain
exact on an intact tree.

## Adding your own endpoints in one language

Unchanged by either posture: declare each route you add in `.gutencode/extensions.json` with a `"lang"` key so
the route check knows it is intentional — CUSTOMIZE.md and AGENT.md show the shape. And note `verify.py` itself
is a Python script: even a go-only or node-only box needs a stock Python interpreter to run it (the Python
*app* deps are not required — their absence is just another loud SKIP).
