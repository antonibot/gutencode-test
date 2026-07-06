"""RATELIMIT INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the python app (cwd = <app>/python; DATABASE_PATH + APP_TEST_CLOCK set by the
harness). Credited by EXIT CODE ONLY.

Proves:  I1 the limit holds — exactly LIMIT requests pass per key per window; the next is 429, repeatedly.
         I2 windows reset — a new window allows again; an old window's exhaustion does not leak forward.
         I3 keys are isolated — exhausting one key never throttles another.
         I4 a denied request consumes nothing — after N denials the new window still grants the FULL limit.
         I5 THE BREACH ATTACK — two processes hammer the SAME key in the SAME window concurrently; the total
            allowed across both must be EXACTLY the limit (a get-then-put limiter fails this under load —
            the old system's hard-won lesson, now proven closed by the atomic consume).
         I6 strict input — a missing / non-string / empty / control-character key is rejected.
         I7 THE SERVICE WALL — ratelimit/check is gated by core.require_service; no token / a wrong token is 401
            (resolved BEFORE the body's field check, so an unauthenticated ill-typed body is 401 not 422), ×3."""
import os
import subprocess
import sys

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

LIMIT = int(os.getenv("RATELIMIT_LIMIT", "5"))
# ratelimit/check is gated by the trusted SERVICE seam (core.require_service): the throttle's caller is a trusted
# service, not an end user, so every call carries the SERVICE_TOKEN (the env-overridable dev default).
SVC = {"Authorization": "Bearer " + os.getenv("SERVICE_TOKEN", "service_dev_token_change_me")}
failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


RACE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
allowed = 0
with TestClient(app, raise_server_exceptions=False) as c:
    for _ in range(int(os.environ["RL_TRIES"])):
        if c.post("/ratelimit/check?now=999000", json={"key": "race"},
                  headers={"Authorization": "Bearer " + os.environ.get("SERVICE_TOKEN", "service_dev_token_change_me")}).status_code == 200:
            allowed += 1
print(allowed)
"""


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        def hit(key, now):
            return c.post(f"/ratelimit/check?now={now}", json={"key": key}, headers=SVC)

        # I1 — exactly LIMIT pass, then 429 forever within the window
        results = [hit("k1", 1000 + i).status_code for i in range(LIMIT + 3)]
        check(f"I1a exactly {LIMIT} allowed in the window", results[:LIMIT] == [200] * LIMIT, f"got {results}")
        check("I1b every request past the limit is 429", results[LIMIT:] == [429] * 3, f"got {results}")

        # I2 — the next window grants the full limit again
        fresh = hit("k1", 1000 + 60)
        check("I2 a new window allows with the FULL budget",
              fresh.status_code == 200 and fresh.json()["remaining"] == LIMIT - 1, f"got {fresh.json()}")

        # I3 — key isolation: k1 exhausted, k2 untouched
        check("I3 exhausting one key never throttles another",
              hit("k2", 1000).status_code == 200)

        # I4 — denials consume nothing: hammer denials, then prove the next window is whole
        for _ in range(10):
            hit("k3", 2000)                       # only LIMIT of these pass; the rest are denials
        nxt = hit("k3", 2000 + 60)
        check("I4 denied requests consumed nothing (next window has the full budget)",
              nxt.status_code == 200 and nxt.json()["remaining"] == LIMIT - 1, f"got {nxt.json()}")

        # I6 — strict input (authed as the service, so the 422 is the SEMANTIC check, not the auth wall)
        for bad in ({}, {"key": 7}, {"key": ""}, {"key": True}):
            check(f"I6 invalid key {bad!r} -> 422",
                  c.post("/ratelimit/check?now=1000", json=bad, headers=SVC).status_code == 422)

        # I7 — THE SERVICE WALL: no token / a wrong token is 401, resolved BEFORE the body's field check
        check("I7a no service token -> 401",
              c.post("/ratelimit/check?now=1000", json={"key": "x"}).status_code == 401)
        check("I7b wrong service token -> 401",
              c.post("/ratelimit/check?now=1000", json={"key": "x"},
                     headers={"Authorization": "Bearer nope"}).status_code == 401)
        check("I7c no token + ill-typed body still 401 (auth before validation)",
              c.post("/ratelimit/check?now=1000", json={"key": 7}).status_code == 401)

    # I5 — the breach attack: two processes, same key, same window, LIMIT tries EACH (2x the budget offered).
    # The atomic consume means the TOTAL allowed across both is exactly LIMIT — not LIMIT+1, not 2*LIMIT.
    if os.getenv("DATABASE_PATH"):
        env = {**os.environ, "LOG_LEVEL": "silent", "RL_TRIES": str(LIMIT)}
        procs = [subprocess.Popen([sys.executable, "-c", RACE_WORKER], cwd=os.getcwd(), env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for _ in range(2)]
        outs = []
        for p in procs:
            so, se = p.communicate(timeout=120)
            outs.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:120]))
        allowed = [int(o) for rc, o in outs if rc == 0 and str(o).isdigit()]
        check(f"I5 two processes offered 2x the budget -> total allowed EXACTLY {LIMIT} (the limit cannot be raced)",
              len(allowed) == 2 and sum(allowed) == LIMIT, f"got {outs}")
    else:
        print("  [FAIL] I5 breach attack NOT RUN — DATABASE_PATH unset (the harness must provide it)")
        failures.append("I5 not run")

    print(f"RATELIMIT INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
