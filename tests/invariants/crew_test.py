"""CREW INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the python
app (cwd = <app>/python). Credited by EXIT CODE ONLY.

Proves:  I1 TERMINATION UNDER CYCLES — a two-role ping-pong AND a single-role self-loop both stop at exactly
            MAX_HANDOFFS with terminated:false (the bound is reported, never disguised as success).
         I2 CONTAINMENT — an unknown handoff stops the run gracefully with the trace so far; the app keeps
            serving afterwards.
         I3 THREADING — every trace entry builds on the previous (each output extends the prior by its tag).
         I4 a clean chain finishes terminated:true with exactly its role count.
         I5 determinism — identical runs are identical.
         I6 strict input — malformed crews and runs are rejected (incl. duplicate role names).
         I7 deny-by-default — every mutating route is 401 without a valid bearer token (the core identity seam)."""
import os
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # enable the core test-session seam: `test:<subject>` resolves to <subject>

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
        H = {"Authorization": "Bearer test:u1"}   # the authenticated caller (every mutation needs a token)

        def create(roles):
            return c.post("/crews", json={"roles": roles}, headers=H)

        def run(cid, value):
            return c.post(f"/crews/{cid}/run", json={"input": value}, headers=H)

        # I7 — deny-by-default: a mutating route is 401 without a valid bearer token (no / forged token)
        check("I7a create no token -> 401", c.post("/crews", json={"roles": [{"name": "x"}]}).status_code == 401)
        check("I7b run no token -> 401", c.post("/crews/1/run", json={"input": "x"}).status_code == 401)
        check("I7c forged token -> 401",
              c.post("/crews", json={"roles": [{"name": "x"}]},
                     headers={"Authorization": "Bearer nosuchtoken"}).status_code == 401)

        # I1 — termination under cycles: ping-pong and self-loop
        pp = create([{"name": "ping", "next": "pong"}, {"name": "pong", "next": "ping"}]).json()
        r = run(pp["id"], "x").json()
        check("I1a a two-role cycle stops at exactly the bound",
              r["handoffs"] == 25 and r["terminated"] is False)
        selfloop = create([{"name": "ouro", "next": "ouro"}]).json()
        r2 = run(selfloop["id"], "x").json()
        check("I1b a SELF-loop stops at exactly the bound", r2["handoffs"] == 25 and r2["terminated"] is False)
        check("I1c the bounded trace is complete (25 entries, every one tagged)",
              len(r2["trace"]) == 25 and all("[ouro]" in s["output"] for s in r2["trace"]))

        # I2 — containment: unknown handoff
        ghost = create([{"name": "real", "next": "imaginary"}]).json()
        g = run(ghost["id"], "seed").json()
        check("I2a an unknown handoff stops gracefully with the trace so far",
              g["handoffs"] == 1 and g["terminated"] is False and g["output"] == "seed [real]")
        check("I2b the app keeps serving after containment", run(ghost["id"], "again").status_code == 200)

        # I3 + I4 — threading along a clean chain
        chain = create([{"name": "a", "next": "b"}, {"name": "b", "next": "d"},
                        {"name": "d"}, {"name": "unreached"}]).json()
        r = run(chain["id"], "go").json()
        outputs = [s["output"] for s in r["trace"]]
        check("I3 each handoff threads the prior output",
              outputs == ["go [a]", "go [a] [b]", "go [a] [b] [d]"], f"got {outputs}")
        check("I4 a clean chain finishes terminated:true with its exact handoff count",
              r["terminated"] is True and r["handoffs"] == 3)

        # I5 — determinism
        check("I5 identical runs are identical", all(run(chain["id"], "go").json() == r for _ in range(3)))

        # I6 — strict input
        for bad in ([], "nope", [{"next": "b"}], [{"name": 7}], [{"name": "a"}, {"name": "a"}],
                    [None], [{"name": "a", "next": 7}]):
            check(f"I6 invalid roles {bad!r} -> 422",
                  c.post("/crews", json={"roles": bad}, headers=H).status_code == 422)
        check("I6 run without input -> 422", c.post(f"/crews/{chain['id']}/run", json={}, headers=H).status_code == 422)

    print(f"CREW INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
