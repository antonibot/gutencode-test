"""evals — a deterministic, OFFLINE scoring harness for model outputs. Store an IMMUTABLE owner-scoped golden SUITE
(a named set of cases, each {id, scorer, expected}), then SCORE caller-PROVIDED outputs against it. evals NEVER calls
a model — it scores the text you give it (the offline harness shape; the real judge/LLM-rubric/generated-output
harness swaps in behind these routes, INTEROP.md).

The dangerous property is SCORE-SOUNDNESS: the verdict is SERVER-DERIVED over a FROZEN suite (a client cannot forge a
pass — the score body carries ONLY outputs; a smuggled pass/passed is never read), and DETERMINISTIC ×3 — score(scorer,
output, expected) is a PURE function whose per-case pass is byte-identical in python==go==node and reproducible across
runs/restart. Two owner-scoping walls: the suite store key is the composite <owner>\\x1f<name> (caller B can NEVER
clobber caller A's suite name — the \\x1f separator is a control char is_well_formed rejects, so the key can't be
forged), and every read filters on the authenticated owner FIELD (not-yours == 404, existence never leaks). The owner
is stamped from the token, never a body field. A suite is IMMUTABLE-on-create: a second create of the same name is a
409 via the atomic do() claim seam, so a scored run is reproducible against a frozen golden set.

Scorers are authored HERE (the ×3 source of truth) and proven identical across python/go/node by the conformance suite:
exact/contains/starts_with/ends_with are raw code-point ops; iexact/icontains use an ASCII case-fold (A-Z<->a-z, every
non-ASCII byte raw — a byte-range map identical ×3; full Unicode casefold ß/Turkish-i lives in golang.org/x/text, which
the modernc-only go build can't import, so it is a documented v2); equals_int parses a CANONICAL integer bounded to
±(2^53-1) (the JS-safe range, so >2^53 rejects uniformly ×3). Scoring is STATELESS (returns, does not store); the pass
verdict + integer counts are pinned, never a float (the rag determinism lesson). Regex (RE2≠PCRE≠ECMAScript),
float-similarity (BLEU/ROUGE/cosine), and json_equal (the ×3 number-canonicalization surface) are DELIBERATELY v2."""
import os
import re

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, StrictStr
from typing import Annotated, Literal

from ..core import clock, store
from ..core.errors import conflict, invalid, not_found, require_identity
from ..parts.env_int import env_int
from ..parts.paginate import paginate
from ..parts.well_formed import WellFormedStr, is_well_formed, make_well_formed

router = APIRouter(prefix="/evals", tags=["evals"])
# state in `store`: ns "evals_suites" "<owner>\x1f<name>" -> {name, owner, cases:[{id,scorer,expected}], case_count,
# created_at}. the composite key partitions by owner (no cross-owner clobber); the `owner` field also scopes every read.

_MAX_SAFE_INT = 9007199254740991                                   # 2**53-1: the magnitude every language holds exactly
_MAX_CASES = env_int(os.getenv("EVALS_MAX_CASES"), 500, 1)         # soft-DoS: a suite with more cases is rejected 422
_MAX_EXPECTED = env_int(os.getenv("EVALS_MAX_EXPECTED_BYTES"), 8192, 1)
_MAX_OUTPUT = env_int(os.getenv("EVALS_MAX_OUTPUT_BYTES"), 65536, 1)

# the closed scorer vocabulary — a Literal so an unknown scorer is a 422 (×3 with the go/node membership check)
Scorer = Literal["exact", "contains", "starts_with", "ends_with", "iexact", "icontains", "equals_int"]


def _ascii_fold(s: str) -> str:
    # ASCII case-fold: A-Z -> a-z, every other code point RAW. A pure byte-range map, byte-identical ×3 (unlike locale
    # .lower()/ToLower/toLowerCase, which diverge on ß/Turkish-i; full Unicode casefold needs x/text -> v2).
    return "".join(chr(ord(ch) + 32) if "A" <= ch <= "Z" else ch for ch in s)


def _strict_int(s: str):
    # a CANONICAL integer string within ±(2^53-1), else None. `re.fullmatch` + `[0-9]` (not \d, which is Unicode in
    # python) + no leading zero -> accept/reject IDENTICALLY ×3; the magnitude bound rejects >2^53 uniformly.
    if not re.fullmatch(r"-?(0|[1-9][0-9]*)", s):
        return None
    v = int(s)
    return v if -_MAX_SAFE_INT <= v <= _MAX_SAFE_INT else None


def _score(scorer: str, output: str, expected: str) -> bool:
    # the PURE deterministic verdict — a code-shaped output/expected is scored as plain TEXT, never executed/regex-compiled
    # (the no-execute-the-output property). Both sides are already contained.
    if scorer == "exact":
        return output == expected
    if scorer == "contains":
        return expected in output
    if scorer == "starts_with":
        return output.startswith(expected)
    if scorer == "ends_with":
        return output.endswith(expected)
    if scorer == "iexact":
        return _ascii_fold(output) == _ascii_fold(expected)
    if scorer == "icontains":
        return _ascii_fold(expected) in _ascii_fold(output)
    if scorer == "equals_int":
        eo, ee = _strict_int(output), _strict_int(expected)
        return eo is not None and ee is not None and eo == ee
    return False                                                   # unreachable: the scorer is a validated Literal


class CaseIn(BaseModel):
    id: WellFormedStr
    scorer: Scorer
    expected: StrictStr                                            # any string; contained + capped + per-scorer-checked below


class CreateSuiteIn(BaseModel):
    name: WellFormedStr
    cases: Annotated[list[CaseIn], Field(min_length=1)]           # >=1 case; the cap is EVALS_MAX_CASES (handler)


class ScoreIn(BaseModel):
    outputs: dict                                                 # {case_id: output}; per-value type checked in the handler


@router.post("/suites", status_code=201)
def create_suite(data: CreateSuiteIn, request: Request, owner: str = Depends(require_identity)) -> dict:
    # authenticated mutation (no/invalid token -> 401, BEFORE any 422). owner from the token, never a body field.
    if len(data.cases) > _MAX_CASES:
        raise invalid(f"a suite may have at most {_MAX_CASES} cases")
    seen, cases = set(), []
    for c in data.cases:
        if c.id in seen:
            raise invalid(f"duplicate case id '{c.id}'")
        seen.add(c.id)
        if len(c.expected) > _MAX_EXPECTED:
            raise invalid(f"case '{c.id}' expected exceeds {_MAX_EXPECTED} code points")
        expected = make_well_formed(c.expected)                    # contain BEFORE store/compare (lone surrogate -> U+FFFD)
        if c.scorer == "equals_int" and _strict_int(expected) is None:
            raise invalid(f"case '{c.id}' equals_int expected must be a canonical integer within the safe range")
        cases.append({"id": c.id, "scorer": c.scorer, "expected": expected})
    cases.sort(key=lambda x: x["id"])                              # deterministic order: every read/score walks cases id-asc ×3
    created_at = clock.current(request)                            # server clock (test seam ?now under APP_TEST_CLOCK); never client-set
    record = {"name": data.name, "owner": owner, "cases": cases, "case_count": len(cases), "created_at": created_at}

    def _claim(cur):
        # IMMUTABLE create-once through the atomic do() seam: two racers -> exactly one writes (201), the other -> 409.
        return (None, "conflict") if cur is not None else (record, "ok")

    if store.do("evals_suites", f"{owner}\x1f{data.name}", _claim) == "conflict":
        raise conflict("a suite with this name already exists")
    # expose owner + created_at (server-set, proves the mass-assign discard) + case_count (server-derived)
    return {"name": data.name, "owner": owner, "case_count": len(cases), "created_at": created_at}


@router.get("/suites")
def list_suites(owner: str = Depends(require_identity), limit: str = "", cursor: str = "") -> dict:
    # read-scope: only the caller's own suites leave the store (filtered on the authenticated owner FIELD), name-sorted
    # for a stable paged walk (store.values() order is NOT stable ×3), then a BOUNDED page. A stranger -> empty page, never 403.
    items = [_meta(s) for s in sorted(store.values("evals_suites"), key=lambda s: s["name"]) if s.get("owner") == owner]
    page, nxt, ok = paginate(items, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/suites/{name}")
def get_suite(name: str, owner: str = Depends(require_identity)) -> dict:
    # read-scope: a malformed or cross-owner name lands in a different slot / fails validation -> 404 (existence never leaks)
    if not is_well_formed(name):
        raise not_found("suite")
    s = store.get("evals_suites", f"{owner}\x1f{name}")
    if s is None:
        raise not_found("suite")
    return {"name": s["name"], "owner": s["owner"], "case_count": s["case_count"],
            "created_at": s["created_at"], "cases": s["cases"]}


@router.post("/suites/{name}/score")
def score(name: str, data: ScoreIn, owner: str = Depends(require_identity)) -> dict:
    # STATELESS: score caller-PROVIDED outputs against the FROZEN suite; return the verdict, store nothing. The body
    # carries ONLY outputs -> a smuggled pass/passed/all_pass is never read (SCORE-SOUNDNESS; proven by I-SCORE-DERIVED).
    if not is_well_formed(name):
        raise not_found("suite")
    s = store.get("evals_suites", f"{owner}\x1f{name}")            # read-scope: cross-owner name -> 404
    if s is None:
        raise not_found("suite")
    results, passed = [], 0
    for c in s["cases"]:                                           # stored id-asc -> deterministic result order ×3
        out = data.outputs.get(c["id"])
        if not isinstance(out, str):                               # a missing (None) or non-string output -> 422
            raise invalid(f"missing or non-string output for case '{c['id']}'")
        if len(out) > _MAX_OUTPUT:
            raise invalid(f"output for case '{c['id']}' exceeds {_MAX_OUTPUT} code points")
        p = _score(c["scorer"], make_well_formed(out), c["expected"])   # contain the output BEFORE compare (no 5xx on a surrogate)
        results.append({"case_id": c["id"], "pass": p})
        passed += 1 if p else 0
    total = len(results)                                          # server-derived verdict — never a client field
    return {"results": results, "passed": passed, "total": total, "all_pass": passed == total}


def _meta(s: dict) -> dict:
    return {"name": s["name"], "owner": s["owner"], "case_count": s["case_count"], "created_at": s["created_at"]}
