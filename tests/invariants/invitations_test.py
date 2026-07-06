"""INVITATIONS INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the python app (cwd =
<app>/python; DATABASE_PATH + APP_TEST_CLOCK set by the harness). Credited by EXIT CODE ONLY. The token is
server-minted and unguessable, so the full create->accept flow lives HERE (the manifest can only pin the
deterministic create fields).

TWO auth models: CREATE requires identity (we mint create requests under APP_TEST_SESSIONS=1 with a
`Bearer test:<subj>` header) and STAMPS the inviter = the caller, derived from the token. ACCEPT is PUBLIC — the
capability token IS the credential — so every accept here is deliberately TOKEN-LESS and the proven single-use /
expiry / race property must still hold with no session.

Proves:  I1 single-use — the first accept succeeds; every replay is 409, forever.
         I2 EXPIRY BEATS AVAILABILITY — a never-accepted token past its expiry is 410, not acceptable.
         I3 expiry is exact at the boundary — accept AT expires_at succeeds; one second later is 410.
         I4 THE ACCEPT RACE — two processes accept the SAME fresh token concurrently: exactly one 200, one 409.
         I5 tokens are unguessable + isolated — distinct invites get distinct high-entropy tokens; accepting
            one does not touch another.
         I6 unknown/garbage tokens 404/422; bad create bodies 422 (authed).
         I7 CREATE IS AUTHENTICATED + the inviter is the TOKEN's — no-token/forged create is 401, and a smuggled
            body `inviter` cannot override the authenticated caller.
         I8 ACCEPT IS PUBLIC — accept succeeds with NO Authorization header (the token is the only credential)."""
import os
import subprocess
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # the `Bearer test:<subj>` seam resolves only under this flag

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


# the race worker reads the token to contend for from argv (the parent mints it, shares it, then forks)
RACE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
token = sys.argv[1]
with TestClient(app, raise_server_exceptions=False) as c:
    r = c.post(f"/invitations/{token}/accept?now=1000")
    print(r.status_code)
"""


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        def invite(email, now, ttl=None, subj="inviter1"):
            body = {"email": email} if ttl is None else {"email": email, "ttl": ttl}
            return c.post(f"/invitations?now={now}", json=body,
                          headers={"Authorization": f"Bearer test:{subj}"}).json()   # CREATE is authed

        def accept(token, now):
            return c.post(f"/invitations/{token}/accept?now={now}")   # ACCEPT is PUBLIC — no token, ever

        # I1 — single-use
        a = invite("a@x.com", 1000, ttl=100)
        first = accept(a["token"], 1050)
        check("I1a first accept -> 200 accepted", first.status_code == 200 and first.json()["status"] == "accepted")
        for _ in range(3):
            check("I1b every replay -> 409", accept(a["token"], 1060).status_code == 409)

        # I2 — expiry beats availability (never accepted, but past expiry)
        b = invite("b@x.com", 1000, ttl=100)        # expires_at = 1100
        check("I2 a never-used token past expiry -> 410", accept(b["token"], 5000).status_code == 410)

        # I3 — boundary: AT expiry ok, one past is gone
        c1 = invite("c@x.com", 1000, ttl=100)       # expires_at = 1100
        check("I3a accept AT expires_at succeeds", accept(c1["token"], 1100).status_code == 200)
        d = invite("d@x.com", 1000, ttl=100)
        check("I3b accept one second past expiry -> 410", accept(d["token"], 1101).status_code == 410)

        # I5 — unguessable + isolated
        e1, e2 = invite("e@x.com", 1000), invite("f@x.com", 1000)
        check("I5a distinct invites get distinct high-entropy tokens",
              e1["token"] != e2["token"] and len(e1["token"]) >= 24)
        accept(e1["token"], 1000)
        check("I5b accepting one leaves the other pending (acceptable)", accept(e2["token"], 1000).status_code == 200)

        # I6 — unknown / garbage / bad create (create is authed, so bad bodies are 422 only WITH a valid token)
        AUTH = {"Authorization": "Bearer test:inviter1"}
        check("I6a unknown token -> 404", accept("no-such-token", 1000).status_code == 404)
        check("I6b control-char token -> 422", c.post("/invitations/p%1Fq/accept?now=1000").status_code == 422)
        for bad in ({}, {"email": ""}, {"email": 7}, {"email": "x@y.com", "ttl": 0}, {"email": "x@y.com", "ttl": -5}):
            check(f"I6c invalid create {bad!r} -> 422", c.post("/invitations?now=1000", json=bad, headers=AUTH).status_code == 422)

        # I7 — CREATE is authenticated AND the inviter is the TOKEN's (never a body field)
        check("I7a create with no token -> 401", c.post("/invitations?now=1000", json={"email": "g@x.com"}).status_code == 401)
        check("I7b create with a forged token -> 401",
              c.post("/invitations?now=1000", json={"email": "g@x.com"}, headers={"Authorization": "Bearer deadbeef"}).status_code == 401)
        check("I7c create with a malformed scheme -> 401",
              c.post("/invitations?now=1000", json={"email": "g@x.com"}, headers={"Authorization": "test:inviter1"}).status_code == 401)
        stamped = invite("h@x.com", 1000, subj="realcaller")
        check("I7d the stored inviter is the token's subject", stamped["inviter"] == "realcaller")
        smug = c.post("/invitations?now=1000", json={"email": "i@x.com", "inviter": "victim"},
                      headers={"Authorization": "Bearer test:realcaller"}).json()
        check("I7e a smuggled body `inviter` cannot override the token's subject", smug["inviter"] == "realcaller")

        # I8 — ACCEPT is PUBLIC: a token-less accept of a freshly-minted invite still succeeds (the token is the credential)
        pub = invite("public@x.com", 1000, ttl=100)["token"]
        check("I8 accept with NO Authorization header succeeds", accept(pub, 1050).status_code == 200)

        # mint the fresh token the race will contend for
        raced = invite("race@x.com", 1000, ttl=100)["token"]

    # I4 — the accept race: two processes, one token, exactly one acceptance
    if os.getenv("DATABASE_PATH"):
        procs = [subprocess.Popen([sys.executable, "-c", RACE_WORKER, raced], cwd=os.getcwd(),
                                  env={**os.environ, "LOG_LEVEL": "silent", "APP_TEST_CLOCK": "1"},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for _ in range(2)]
        outs = []
        for p in procs:
            so, se = p.communicate(timeout=120)
            outs.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:120]))
        statuses = sorted(int(o) for rc, o in outs if rc == 0 and str(o).isdigit())
        check("I4 two processes racing one token -> exactly one 200 and one 409", statuses == [200, 409], f"got {outs}")
    else:
        print("  [FAIL] I4 accept race NOT RUN — DATABASE_PATH unset")
        failures.append("I4 not run")

    print(f"INVITATIONS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
