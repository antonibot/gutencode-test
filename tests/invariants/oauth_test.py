"""OAUTH INVARIANTS — correctness proofs for this domain's dangerous properties.
Run against the python app (cwd = <app>/python; DATABASE_PATH set by the harness). Credited by EXIT CODE
ONLY.

Proves:  I1 CSRF deny-by-default — a callback with no matching pending flow is 403, and it creates NOTHING
            (a forged probe can never plant a flow).
         I2 single-use — the first exchange succeeds; every replay is 409, forever.
         I3 provider binding — a state issued for one provider is 403 for another, even with the right code.
         I4 no resurrection — after a consume, re-authorizing the SAME provider+state is 409; the code stays
            dead (a naive implementation would re-open consumed flows; this proves the door is closed).
         I5 THE CONSUME RACE — two processes exchange the SAME code concurrently: exactly ONE gets a token,
            the other gets 409 (atomic single-use across processes).
         I6 deny-by-default providers + strict input."""
import os
import subprocess
import sys

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.core import store  # noqa: E402
from app_pkg.app import app  # noqa: E402

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
with TestClient(app, raise_server_exceptions=False) as c:
    r = c.post("/oauth/callback", json={"provider": "google", "state": "srace", "code": "crace"})
    print(r.status_code)
"""


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        def auth(provider, state):
            return c.post("/oauth/authorize", json={"provider": provider, "state": state})

        def cb(provider, state, code):
            return c.post("/oauth/callback", json={"provider": provider, "state": state, "code": code})

        # I1 — a forged callback is 403 and plants nothing
        forged = cb("google", "never_issued", "cX")
        check("I1a forged state -> 403", forged.status_code == 403)
        check("I1b the forged probe planted NO flow", store.get("oauth_flows", "google:never_issued") is None)

        # I2 — single-use
        auth("google", "sA")
        first = cb("google", "sA", "cA")
        check("I2a the first exchange succeeds with a token",
              first.status_code == 200 and first.json()["access_token"].startswith("tok_"))
        for _ in range(3):
            check("I2b every replay is 409", cb("google", "sA", "cA").status_code == 409)

        # I3 — provider binding: github's state is not google's
        auth("github", "sB")
        check("I3a the state is invalid for the WRONG provider (403, not a token)",
              cb("google", "sB", "cB").status_code == 403)
        check("I3b ...and still valid for the right one", cb("github", "sB", "cB").status_code == 200)

        # I4 — no resurrection: a consumed state can never be re-opened
        check("I4a re-authorize after consume -> 409", auth("google", "sA").status_code == 409)
        check("I4b the code stays dead after the resurrection attempt", cb("google", "sA", "cA").status_code == 409)
        white = store.get("oauth_flows", "google:sA")
        check("I4c white-box: the flow is still consumed", white is not None and white["status"] == "consumed")

        # I6 — deny-by-default + strict input
        check("I6a unknown provider on authorize -> 422", auth("myspace", "x").status_code == 422)
        check("I6b unknown provider on callback -> 422", cb("myspace", "x", "c").status_code == 422)
        for bad in ({"provider": "google"}, {"provider": "google", "state": ""}, {"provider": 7, "state": "x"}):
            check(f"I6c invalid authorize body {bad!r} -> 422",
                  c.post("/oauth/authorize", json=bad).status_code == 422)

        # I7 — the access token is UNGUESSABLE (CSPRNG), never a forgeable digest of the client inputs:
        # two flows that differ ONLY in state yield different tokens, and a token is NOT the old deterministic
        # `tok_<sha256(provider:state:code)>` an attacker could compute offline.
        import hashlib
        auth("google", "sTok1")
        t1 = cb("google", "sTok1", "cZ").json()["access_token"]
        auth("google", "sTok2")
        t2 = cb("google", "sTok2", "cZ").json()["access_token"]
        check("I7a distinct flows -> DISTINCT tokens (not a deterministic function of the inputs)", t1 != t2)
        forgeable = "tok_" + hashlib.sha256(b"google:sTok1:cZ").hexdigest()[:24]
        check("I7b the token is NOT the forgeable digest of (provider, state, code)", t1 != forgeable,
              f"token equals the offline-computable digest: {t1}")
        check("I7c the token carries CSPRNG entropy (tok_ + >=24 chars)", t1.startswith("tok_") and len(t1) >= 28)

        # set up the race flow before spawning the workers
        check("race setup: pending flow issued", auth("google", "srace").status_code == 201)

    # I5 — the consume race: two processes, one code — exactly one token may be minted
    if os.getenv("DATABASE_PATH"):
        procs = [subprocess.Popen([sys.executable, "-c", RACE_WORKER], cwd=os.getcwd(),
                                  env={**os.environ, "LOG_LEVEL": "silent"},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for _ in range(2)]
        outs = []
        for p in procs:
            so, se = p.communicate(timeout=120)
            outs.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:120]))
        statuses = sorted(int(o) for rc, o in outs if rc == 0 and str(o).isdigit())
        check("I5 two processes racing one code -> exactly one 200 and one 409",
              statuses == [200, 409], f"got {outs}")
    else:
        print("  [FAIL] I5 consume race NOT RUN — DATABASE_PATH unset (the harness must provide it)")
        failures.append("I5 not run")

    print(f"OAUTH INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
