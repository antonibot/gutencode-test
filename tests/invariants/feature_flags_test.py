"""FEATURE_FLAGS INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the python app (cwd =
<app>/python). Credited by EXIT CODE ONLY.

Proves:  I1 DETERMINISM — evaluating the same (flag, subject) repeatedly always returns the same answer.
         I2 MONOTONICITY — ramping the rollout 0->100, each subject's enabled flips false->true AT MOST ONCE
            and NEVER back (no subject already in is ever dropped by raising the percentage — the no-flapping
            property that makes ramps safe).
         I3 boundary — enabled iff bucket < rollout: at rollout 0 nobody, at 100 everybody.
         I4 distribution — over many subjects at rollout 50, the enabled fraction is ~half (stable bucketing
            spreads subjects, it isn't all-or-nothing).
         I5 unknown flag 404; missing subject 422.
         I6 WRITES ARE ADMIN-ONLY, READS STAY OPEN — create/set-rollout need the admin role (no token 401,
            a non-admin 403); evaluate + get-flag work with NO token (the runtime hot path must not be gated)."""
import os
import sys

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

failures = []

# feature_flags WRITES are ADMIN-ONLY: enable the test-session seam (Bearer test:<subject>, inert in prod) and
# send every WRITE as the inert test admin 'root' by default. The READS are open and harmlessly inherit the header
# (I6 below proves reads also work with NO token, via a separate tokenless client).
os.environ["APP_TEST_SESSIONS"] = "1"
ADMIN = {"Authorization": "Bearer test:root"}


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def main():
    with TestClient(app, raise_server_exceptions=False, headers=ADMIN) as c:
        c.post("/feature_flags", json={"key": "exp", "rollout": 0})

        def setr(r):
            c.put("/feature_flags/exp", json={"rollout": r})

        def ev(subject):
            return c.get("/feature_flags/exp/evaluate", params={"subject": subject}).json()["enabled"]

        subjects = [f"user{i:03d}" for i in range(200)]

        # I1 — determinism
        setr(50)
        check("I1 same eval repeats identically", all(ev("user001") == ev("user001") for _ in range(5)))

        # I2 — monotonicity across a full ramp
        flipped_at = {}
        prev = {s: False for s in subjects}
        monotonic = True
        for r in range(0, 101):
            setr(r)
            for s in subjects:
                now = ev(s)
                if prev[s] and not now:
                    monotonic = False          # a subject that was in got dropped by raising rollout — forbidden
                if now and s not in flipped_at:
                    flipped_at[s] = r
                prev[s] = now
        check("I2 no subject is ever dropped as rollout increases (monotonic)", monotonic)
        check("I2b every subject is enabled by rollout 100", all(prev.values()))

        # I3 — boundary
        setr(0)
        check("I3a rollout 0 -> nobody", not any(ev(s) for s in subjects[:50]))
        setr(100)
        check("I3b rollout 100 -> everybody", all(ev(s) for s in subjects[:50]))

        # I4 — distribution at 50% is roughly half (stable bucketing, not all-or-nothing)
        setr(50)
        enabled = sum(ev(s) for s in subjects)
        check("I4 ~half enabled at rollout 50", 70 <= enabled <= 130, f"enabled {enabled}/200")

        # I5 — errors
        check("I5a unknown flag -> 404", c.get("/feature_flags/ghost/evaluate", params={"subject": "x"}).status_code == 404)
        check("I5b missing subject -> 422", c.get("/feature_flags/exp/evaluate").status_code == 422)

    # I6 — WRITES are admin-only, READS stay open. A fresh tokenless client (no default header) probes the wall.
    with TestClient(app, raise_server_exceptions=False) as anon:
        # writes: no token -> 401 (before any 422 body validation), a valid non-admin -> 403
        check("I6a anonymous create -> 401", anon.post("/feature_flags", json={"key": "anon", "rollout": 50}).status_code == 401)
        check("I6b non-admin create -> 403",
              anon.post("/feature_flags", json={"key": "anon", "rollout": 50},
                        headers={"Authorization": "Bearer test:alice"}).status_code == 403)
        check("I6c anonymous set-rollout -> 401", anon.put("/feature_flags/exp", json={"rollout": 50}).status_code == 401)
        check("I6d non-admin set-rollout -> 403",
              anon.put("/feature_flags/exp", json={"rollout": 50},
                       headers={"Authorization": "Bearer test:alice"}).status_code == 403)
        check("I6e anonymous bad-body create still 401 (auth before validation)",
              anon.post("/feature_flags", json={"key": ""}).status_code == 401)
        # reads: the runtime hot path MUST work with NO token
        check("I6f anonymous evaluate stays OPEN -> 200",
              anon.get("/feature_flags/exp/evaluate", params={"subject": "bob"}).status_code == 200)
        check("I6g anonymous get-flag stays OPEN -> 200", anon.get("/feature_flags/exp").status_code == 200)

    print(f"FEATURE_FLAGS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
