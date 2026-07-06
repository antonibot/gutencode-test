"""EVALS INVARIANTS — correctness proofs for this domain's dangerous property (SCORE-SOUNDNESS + DETERMINISM). Run
from the app's python tree (cwd = <app>/python). Credited by EXIT CODE ONLY. Drives the REAL routes (TestClient) and
checks them against an INDEPENDENT in-test oracle (a re-derived ascii-fold + contain + strict-int) — never the shipped
code path (rule 9).

Proves:  I-SCORE-DERIVED  the verdict is SERVER-derived: a score body smuggling passed/all_pass/a per-case pass is
                         DISCARDED (only `outputs` is read); the returned pass == the server's recompute. Delete the
                         defense (trust the client pass) and a should-fail case would report pass -> RED.
         I-IMMUTABLE     a created suite is frozen: a 2nd create of the same name is 409 and GET still returns the
                         ORIGINAL cases (a blind overwrite would leak the new content -> RED).
         I-DETERMINISM   each per-case pass == the independent oracle for (scorer, output, expected) on REACHING inputs
                         (ascii-fold HELLO/hello, raw NFC!=NFD café, strict-int); repeated scores are byte-identical.
                         Delete the ascii-fold (raw compare) and iexact HELLO/hello flips -> RED.
         I-OWN           cross-owner isolation: the composite <owner>\\x1f<name> key keeps alice's + bob's same-name
                         suites DISTINCT (no clobber), a cross-owner GET/score is 404, and the list excludes others.
         I-CONTAIN       a lone-surrogate expected (at create) and output (at score) are CONTAINED to U+FFFD BEFORE
                         store/compare: create is 201, GET echoes no raw surrogate, score never 5xxs.
         I-NO-EXEC       a code/regex-shaped expected is scored as a LITERAL, never compiled/executed: contains '.*'
                         does NOT match 'abc' (a regex engine would) -> the no-execute-the-output property."""
import os
import re
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # the test-session seam: `test:<subject>` resolves to <subject> (inert in prod)
os.environ["APP_TEST_CLOCK"] = "1"      # the test-clock seam: ?now is honored (inert in prod)

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


# ----- the INDEPENDENT oracle (re-derived in the test, NOT imported from the shipped evals.py) -----
def _wf(s):     # lone surrogate -> U+FFFD: what the handler stores/compares, so the test knows the contained value
    return "".join("�" if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in s)


def _fold(s):   # ASCII case-fold, re-derived
    return "".join(chr(ord(ch) + 32) if "A" <= ch <= "Z" else ch for ch in s)


def _si(x):     # strict canonical int in the safe range, re-derived
    if not re.fullmatch(r"-?(0|[1-9][0-9]*)", x):
        return None
    v = int(x)
    return v if abs(v) <= 9007199254740991 else None


def _oracle(scorer, output, expected):
    o, e = _wf(output), _wf(expected)                              # both contained, as the server does
    if scorer == "exact":
        return o == e
    if scorer == "contains":
        return e in o
    if scorer == "starts_with":
        return o.startswith(e)
    if scorer == "ends_with":
        return o.endswith(e)
    if scorer == "iexact":
        return _fold(o) == _fold(e)
    if scorer == "icontains":
        return _fold(e) in _fold(o)
    if scorer == "equals_int":
        return _si(o) is not None and _si(o) == _si(e)
    return False


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        def H(sub):
            return {"Authorization": f"Bearer test:{sub}"}

        def create(sub, name, cases, now=1700000000):
            return c.post(f"/evals/suites?now={now}", json={"name": name, "cases": cases}, headers=H(sub))

        def score(sub, name, outputs):
            return c.post(f"/evals/suites/{name}/score", json={"outputs": outputs}, headers=H(sub))

        # I-SCORE-DERIVED — the verdict is server-derived; a smuggled pass/passed/all_pass in the body is ignored
        check("I-SCORE-DERIVED a create -> 201", create("alice", "sd", [{"id": "c", "scorer": "exact", "expected": "yes"}]).status_code == 201)
        smug = c.post("/evals/suites/sd/score", json={"outputs": {"c": "no"}, "passed": 999, "total": 999,
                      "all_pass": True, "results": [{"case_id": "c", "pass": True}]}, headers=H("alice")).json()
        check("I-SCORE-DERIVED a smuggled passed=999 is discarded (server recomputes 0)", smug["passed"] == 0)
        check("I-SCORE-DERIVED a smuggled all_pass=true is discarded", smug["all_pass"] is False)
        check("I-SCORE-DERIVED the per-case pass is server-derived ('no' fails exact:'yes')",
              smug["results"] == [{"case_id": "c", "pass": False}])

        # I-IMMUTABLE — a frozen suite; a 2nd create is 409 and the original cases survive
        create("alice", "im", [{"id": "c", "scorer": "exact", "expected": "v1"}])
        r2 = create("alice", "im", [{"id": "c", "scorer": "exact", "expected": "v2"}])
        check("I-IMMUTABLE a re-create of the same name -> 409", r2.status_code == 409)
        gim = c.get("/evals/suites/im", headers=H("alice")).json()
        check("I-IMMUTABLE the frozen suite keeps its ORIGINAL cases (no overwrite)",
              gim["cases"] == [{"id": "c", "scorer": "exact", "expected": "v1"}])

        # I-DETERMINISM — each per-case pass == the independent oracle on REACHING inputs; repeated scores identical
        cases = [
            {"id": "a", "scorer": "iexact", "expected": "HELLO"},         # ascii-fold reaching input (delete the fold -> RED)
            {"id": "b", "scorer": "exact", "expected": "café"},          # NFC; an NFD output must FAIL (raw code-point)
            {"id": "d", "scorer": "equals_int", "expected": "5"},        # strict int
            {"id": "e", "scorer": "icontains", "expected": "WORLD"},
        ]
        create("alice", "det", cases)
        outs = {"a": "hello", "b": "café", "d": "5", "e": "say HELLO WORLD ok"}   # b: NFD café (e + combining acute)
        r1 = score("alice", "det", outs).json()
        r2b = score("alice", "det", outs).json()
        check("I-DETERMINISM repeated identical scores are byte-identical", r1 == r2b)
        stored_expected = {c["id"]: _wf(c["expected"]) for c in cases}
        for res in r1["results"]:
            cid = res["case_id"]
            scorer = next(x["scorer"] for x in cases if x["id"] == cid)
            want = _oracle(scorer, outs[cid], stored_expected[cid])
            check(f"I-DETERMINISM case {cid} ({scorer}) pass matches the independent oracle",
                  res["pass"] == want, f"got {res['pass']} want {want}")
        check("I-DETERMINISM the NFD 'café' output FAILS the NFC exact expected (raw code-point, ×3-safe)",
              [x for x in r1["results"] if x["case_id"] == "b"][0]["pass"] is False)

        # I-OWN — the composite key keeps two owners' same-name suites distinct; cross-owner is 404; the list excludes
        create("alice", "own", [{"id": "c", "scorer": "exact", "expected": "alice-data"}])
        create("bob", "own", [{"id": "c", "scorer": "exact", "expected": "bob-data"}])   # SAME name, different owner
        ga = c.get("/evals/suites/own", headers=H("alice")).json()
        gb = c.get("/evals/suites/own", headers=H("bob")).json()
        check("I-OWN a alice's 'own' is intact (no clobber by bob's same-name create)",
              ga["cases"][0]["expected"] == "alice-data")
        check("I-OWN b bob's 'own' is his own (the composite key kept them distinct)",
              gb["cases"][0]["expected"] == "bob-data")
        check("I-OWN c bob cannot GET alice's 'im' suite (cross-owner -> 404, existence never leaks)",
              c.get("/evals/suites/im", headers=H("bob")).status_code == 404)
        check("I-OWN d bob cannot SCORE alice's 'im' suite (404)",
              c.post("/evals/suites/im/score", json={"outputs": {}}, headers=H("bob")).status_code == 404)
        names = {x["name"] for x in c.get("/evals/suites", headers=H("bob")).json()["results"]}
        check("I-OWN e bob's list has ONLY his own suites (excludes alice's sd/im/det)",
              names == {"own"}, f"got {names}")

        # I-CONTAIN — a lone-surrogate expected (create) + output (score) are contained to U+FFFD; no raw surrogate, no 5xx
        raw = '{"name": "uni", "cases": [{"id": "c", "scorer": "exact", "expected": "x\\ud800y"}]}'
        ru = c.post("/evals/suites?now=1700000000", content=raw, headers={**H("alice"), "content-type": "application/json"})
        check("I-CONTAIN a a lone-surrogate expected create -> 201", ru.status_code == 201, f"got {ru.status_code}")
        exp = c.get("/evals/suites/uni", headers=H("alice")).json()["cases"][0]["expected"]
        check("I-CONTAIN b no raw lone surrogate is ever echoed (U+FFFD substituted)",
              all(not 0xD800 <= ord(ch) <= 0xDFFF for ch in exp))
        raw2 = '{"outputs": {"c": "x\\ud800y"}}'
        rs = c.post("/evals/suites/uni/score", content=raw2, headers={**H("alice"), "content-type": "application/json"})
        check("I-CONTAIN c a lone-surrogate output scores WITHOUT a 5xx (200)", rs.status_code == 200, f"got {rs.status_code}")
        check("I-CONTAIN d the contained output (x?y) exact-matches the contained expected", rs.json()["passed"] == 1)

        # I-NO-EXEC — a regex-shaped expected is a LITERAL, never compiled (a regex engine would match '.*' to 'abc')
        create("alice", "noexec", [{"id": "c", "scorer": "contains", "expected": ".*"}])
        check("I-NO-EXEC '.*' is a literal substring, NOT a regex ('abc' does not contain '.*')",
              score("alice", "noexec", {"c": "abc"}).json()["passed"] == 0)
        check("I-NO-EXEC the literal '.*' IS found when actually present",
              score("alice", "noexec", {"c": "x.*y"}).json()["passed"] == 1)

    print(f"EVALS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
