"""AI_WORKFLOW INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the BUILT
python app (cwd = <app>/python). Credited by EXIT CODE ONLY.

Proves:  I1 TERMINATION — a workflow defined with MORE steps than the budget runs at most MAX_STEPS and
            reports ok:false (the budget breach is loud, never silent truncation-as-success).
         I2 CONTAINMENT — an unknown op mid-pipeline stops the run gracefully: ok:false, the trace holds the
            steps that DID run, the value so far is returned, and the app keeps serving.
         I3 THREADING — step N's output is exactly step N+1's input (checked along the whole trace).
         I4 determinism — the same definition + input runs identically, repeatedly.
         I5 codepoint semantics — truncate/length count CODEPOINTS, proven with non-BMP input (an emoji is
            one unit, not two).
         I6 strict input."""
import os
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # test seam: a `test:<subject>` bearer resolves to <subject> (inert in prod); mutations are authenticated
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        c.headers["Authorization"] = "Bearer test:inv"   # Every mutating request authenticates via the test-session seam
        def create(steps):
            return c.post("/workflows", json={"steps": steps})

        def run(wid, value):
            return c.post(f"/workflows/{wid}/run", json={"input": value})

        # I1 — termination: 60 appends defined, at most 50 run, the breach is reported
        big = create([{"op": "append", "text": "x"} for _ in range(60)]).json()
        r = run(big["id"], "")
        check("I1a the run stopped at the budget", r.json()["steps_run"] == 50, f"got {r.json()['steps_run']}")
        check("I1b the value reflects exactly the budget", r.json()["output"] == "x" * 50)
        check("I1c the budget breach is LOUD (ok:false)", r.json()["ok"] is False)

        # I2 — containment: a poison step mid-pipeline
        poisoned = create([{"op": "append", "text": "a"}, {"op": "explode"}, {"op": "append", "text": "z"}]).json()
        r = run(poisoned["id"], "seed").json()
        check("I2a the run stopped at the poison step", r["steps_run"] == 1 and r["ok"] is False)
        check("I2b the value so far is returned, the tail never ran", r["output"] == "seeda")
        check("I2c the app keeps serving after containment", run(poisoned["id"], "again").status_code == 200)

        # I3 — threading along the trace
        chain = create([{"op": "append", "text": "-1"}, {"op": "append", "text": "-2"},
                        {"op": "prepend", "text": "0"}, {"op": "length"}]).json()
        r = run(chain["id"], "seed").json()
        outputs = [s["output"] for s in r["trace"]]
        check("I3 each step builds on the previous (trace is a chain)",
              outputs == ["seed-1", "seed-1-2", "0seed-1-2", "9"], f"got {outputs}")

        # I4 — determinism
        check("I4 identical runs are identical", all(run(chain["id"], "seed").json() == r for _ in range(3)))

        # I5 — codepoint semantics with non-BMP input (🔑 is ONE codepoint, two UTF-16 units, four bytes)
        uni = create([{"op": "truncate", "n": 3}]).json()
        check("I5a truncate counts codepoints", run(uni["id"], "🔑ab中").json()["output"] == "🔑ab")
        meas = create([{"op": "length"}]).json()
        check("I5b length counts codepoints", run(meas["id"], "🔑ab中").json()["output"] == "4")

        # I6 — strict input
        for bad in ({"steps": []}, {"steps": "x"}, {"steps": [{"text": "no op"}]}, {"steps": [{"op": 7}]},
                    {"steps": [None]}):
            check(f"I6 invalid definition {bad!r} -> 422", create(bad["steps"]).status_code == 422)
        check("I6 run with no input -> 422", c.post(f"/workflows/{chain['id']}/run", json={}).status_code == 422)

    print(f"AI_WORKFLOW INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
