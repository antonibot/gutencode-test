# Upgrading this codebase to a newer edition

> This export is **edition `1c7ca5fc0e0b55aa`** (also in `.gutencode/contract.json` and the README footer). You
> OWN this code — there is no hosted service and nothing phones home. When a newer edition is published, you
> take what you want with a normal `git merge`, because every export is **deterministic**: the same edition
> always produces byte-identical files, so a diff is meaningful.

## The one-time setup (do this right after you receive the export)
```bash
git init && git add -A && git commit -m "spine 1c7ca5fc0e0b55aa"
git branch gutencode-baseline          # a pristine branch that mirrors the export, untouched
git checkout main                      # do ALL your work on main
```
Keep `gutencode-baseline` as the untouched factory output. Build your unique logic on `main`.

## When a newer edition arrives
```bash
git checkout gutencode-baseline
#   replace the tree with the new edition's files (unzip / copy over), then:
git add -A && git commit -m "spine <new-version>"
git checkout main
git merge gutencode-baseline           # git 3-way-merges the factory changes with YOUR changes
```
Git resolves everything that doesn't conflict automatically. You only review real conflicts — places where the
factory changed a line you also changed. Your custom files (anything not in the baseline) are never touched.

## What helps the merge stay clean
- **`python verify.py` after merging** — it re-checks the baseline integrity, all three suites, the invariants,
  and the route contract, so a bad merge is caught immediately.
- **`.gutencode/accepted.json`** lists baseline files you intentionally modified — keep it current so the drift
  report (and the merge) stays meaningful.
- **Prefer adding your logic in new files** over editing baseline files; new files never conflict.

## What this is NOT
There is no auto-migration and no lifecycle service — by design. You hold the code; the edition stamp + git are
the whole upgrade mechanism. That is the point: no lock-in, no dependency on us continuing to exist.
