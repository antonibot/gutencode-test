"""USERS INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the python app (cwd =
<app>/python; DATABASE_PATH set by the harness). Credited by EXIT CODE ONLY.

Proves:  I1 handle uniqueness — a duplicate create is 409 and the ORIGINAL profile survives intact.
         I2 THE HANDLE RACE — two processes create the SAME handle concurrently: exactly one user exists
            (one 201 and one 409, and the survivor is internally consistent).
         I3 monotonic lifecycle — deactivate is idempotent and terminal; re-creating a deactivated user's
            handle is 409 (deactivation never frees the handle for capture).
         I4 honest 404s — missing handles 404 on read and deactivate alike.
         I5 strict input.
         I6 IDENTITY — CREATE is authenticated-self (no token 401, handle != caller 403); DEACTIVATE is
            self-or-admin (no token 401, a non-admin non-self 403, the owner OR an admin 200).
         I7 AUTHENTICATED READ — GET /{handle} needs a valid session (no/invalid token 401); any logged-in
            caller may read any profile (not owner-scoped), but the anonymous public cannot.

users mutations AND reads are authenticated: enable the test-session seam (Bearer test:<subject>, inert in
prod) and act as the right subject per call — CREATE must be the handle itself (authenticated-self), DEACTIVATE works
as the inert test admin 'root' (self-or-admin), READS work as any authenticated caller. The white-box-free store is
reached only through the API here."""
import os
import subprocess
import sys

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

failures = []

os.environ["APP_TEST_SESSIONS"] = "1"
ADMIN = {"Authorization": "Bearer test:root"}     # root is the inert test admin (self-or-admin deactivate)
READER = {"Authorization": "Bearer test:reader"}  # any authenticated caller may READ any profile (authenticated read)


def _self(handle):
    return {"Authorization": f"Bearer test:{handle}"}   # the caller IS the handle (authenticated-self create)


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


RACE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
with TestClient(app, raise_server_exceptions=False, headers={"Authorization": "Bearer test:raced"}) as c:
    r = c.post("/users", json={"handle": "raced", "display_name": "Racer"})
    print(r.status_code)
"""


def main():
    # NO client-default Authorization — each call sets its own (a per-request {} would MERGE with a default and
    # not clear it, so the no-token checks must send genuinely no Authorization header).
    with TestClient(app, raise_server_exceptions=False) as c:
        # I1 — uniqueness + original survives (create is authenticated-self -> act as alice)
        original = c.post("/users", json={"handle": "alice", "display_name": "Alice"}, headers=_self("alice")).json()
        check("I1a duplicate handle -> 409",
              c.post("/users", json={"handle": "alice", "display_name": "Imposter"},
                     headers=_self("alice")).status_code == 409)
        check("I1b the original profile survives intact", c.get("/users/alice", headers=READER).json() == original)

        # I3 — monotonic lifecycle (deactivate as admin: self-or-admin)
        c.post("/users/alice/deactivate", headers=ADMIN)
        again = c.post("/users/alice/deactivate", headers=ADMIN)
        check("I3a deactivate is idempotent", again.status_code == 200 and again.json()["status"] == "deactivated")
        check("I3b a deactivated handle can never be re-captured",
              c.post("/users", json={"handle": "alice", "display_name": "Capture"},
                     headers=_self("alice")).status_code == 409)
        check("I3c the deactivated profile keeps its identity",
              c.get("/users/alice", headers=READER).json()["display_name"] == "Alice")

        # I4 — honest 404s (deactivate ghost as admin so authz passes and the 404 is reached)
        check("I4 missing handles 404 on read and deactivate",
              c.get("/users/ghost", headers=READER).status_code == 404
              and c.post("/users/ghost/deactivate", headers=ADMIN).status_code == 404)

        # I5 — strict input (body invalid -> 422 fires before the authz check; any valid token reaches it)
        for bad in ({"display_name": "x"}, {"handle": "", "display_name": "x"}, {"handle": 7, "display_name": "x"},
                    {"handle": "x"}, {"handle": "x", "display_name": ""}):
            check(f"I5 invalid create {bad!r} -> 422", c.post("/users", json=bad, headers=ADMIN).status_code == 422)

        # I6 — IDENTITY
        # create authenticated-self
        check("I6a create with NO token -> 401",
              c.post("/users", json={"handle": "dave", "display_name": "Dave"}).status_code == 401)
        check("I6b create someone else's handle -> 403",
              c.post("/users", json={"handle": "dave", "display_name": "Dave"},
                     headers=_self("eve")).status_code == 403)
        check("I6c create your OWN handle -> 201",
              c.post("/users", json={"handle": "dave", "display_name": "Dave"},
                     headers=_self("dave")).status_code == 201)
        # deactivate self-or-admin
        check("I6d deactivate with NO token -> 401",
              c.post("/users/dave/deactivate").status_code == 401)
        check("I6e deactivate someone else's account as a non-admin non-self -> 403",
              c.post("/users/dave/deactivate", headers=_self("eve")).status_code == 403)
        check("I6f the OWNER may deactivate their own account -> 200",
              c.post("/users/dave/deactivate", headers=_self("dave")).status_code == 200)
        check("I6g an ADMIN may deactivate any account -> 200",
              c.post("/users", json={"handle": "frank", "display_name": "Frank"},
                     headers=_self("frank")).status_code == 201
              and c.post("/users/frank/deactivate", headers=ADMIN).status_code == 200)

        # I7 — AUTHENTICATED READ: the profile directory needs a valid session; the anonymous public cannot
        # read it, but ANY logged-in caller may read ANY profile (not owner-scoped). 'dave' exists from I6c.
        check("I7a read with NO token -> 401", c.get("/users/dave").status_code == 401)
        check("I7b read with a wrong token -> 401",
              c.get("/users/dave", headers={"Authorization": "Bearer nosuchtoken"}).status_code == 401)
        check("I7c any authenticated caller may read any profile -> 200",
              c.get("/users/dave", headers=_self("zara")).status_code == 200)

    # I2 — the handle race: two processes, one handle — exactly one user (each worker acts as 'raced', self)
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
        check("I2 two processes racing one handle -> exactly one 201 and one 409",
              statuses == [201, 409], f"got {outs}")
    else:
        print("  [FAIL] I2 handle race NOT RUN — DATABASE_PATH unset")
        failures.append("I2 not run")

    print(f"USERS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
