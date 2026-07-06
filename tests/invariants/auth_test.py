"""AUTH INVARIANTS — correctness proofs for this domain's dangerous properties (the full session lifecycle).
Run against the python app (cwd = <app>/python). Credited by EXIT CODE ONLY: prints are for humans, sys.exit(0|1)
is the verdict. The ×3 SHAPE parity is proven by the conformance suite; this proves the deep,
chained BEHAVIOUR that independent per-route cases (no token capture) cannot.

Proves:  I1 no-plaintext + record shape · I2 per-user salting · I3 no LOGIN enumeration · I4 deny-by-default +
         the issued token authenticates · I5 ENUMERATION-SAFE register (no 409 oracle) + claim-once not overwritten
         · I6 no secret leakage (envelope carries no salt/hash) · I7 session TTL: an expired session never resolves
         · I8 rotation + theft detection: /refresh rotates (old dies), reusing the rotated token revokes the session
         · I9 scoped logout (local + global) · I10 password reset (single-use, revokes ALL sessions, old pw dies)
         · I11 email verify (single-use, sets the bound subject verified) · I12 token->subject binding (a token
         minted for A never acts on B)."""
import base64
import os
import sys

os.environ["AUTH_THROTTLE_LIMIT"] = "1000000"   # the throttle is proven separately; keep it out of these flows
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.core import store  # noqa: E402
from app_pkg.app import app  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def reg(c, email, pw):
    return c.post("/auth/register", json={"email": email, "password": pw})


def login(c, email, pw, now=None):
    q = f"?now={now}" if now is not None else ""
    return c.post(f"/auth/login{q}", json={"email": email, "password": pw})


def outbox_token(kind, to):
    rec = store.get("auth_outbox", f"{kind}:{to}")
    return rec["token"] if rec else None


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        PW = "a strong enough password"
        # I1 + I2 — two users, SAME password; storage is salted hashes (never plaintext), distinct per user
        reg(c, "alice@ex.com", PW)
        reg(c, "bob@ex.com", PW)
        alice, bob = store.get("auth_users", "alice@ex.com"), store.get("auth_users", "bob@ex.com")
        check("I1a record holds salt+hash+email_verified+created_at, not the password",
              set(alice) == {"salt", "hash", "email_verified", "created_at"} and PW not in (alice["salt"] + alice["hash"]))
        check("I1b the hash is a real 32-byte derived key", len(base64.b64decode(alice["hash"])) == 32)
        check("I2 same password -> DIFFERENT salt and hash per user",
              alice["salt"] != bob["salt"] and alice["hash"] != bob["hash"])

        # I3 — LOGIN enumeration resistance: unknown user vs wrong password are indistinguishable
        wrong = login(c, "alice@ex.com", "the WRONG password")
        ghost = login(c, "ghost@ex.com", "the WRONG password")
        check("I3 unknown user == wrong password (same status + body)",
              wrong.status_code == 401 and ghost.status_code == 401 and wrong.json() == ghost.json())

        # I4 — deny-by-default; the issued token authenticates as the right user
        tok = login(c, "alice@ex.com", PW).json()["access_token"]
        check("I4a no token -> 401", c.get("/auth/me").status_code == 401)
        check("I4b malformed scheme -> 401",
              c.get("/auth/me", headers={"Authorization": f"Token {tok}"}).status_code == 401)
        me = c.get("/auth/me", headers={"Authorization": f"Bearer {tok}"})
        check("I4c the exact token authenticates as the right user",
              me.status_code == 200 and me.json()["email"] == "alice@ex.com")
        forged = tok[:-2] + ("AA" if not tok.endswith("AA") else "BB")
        check("I4d a forged near-miss secret -> 401",
              c.get("/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401)

        # I5 — ENUMERATION-SAFE register: an existing email returns 200 (no 409 oracle); claim-once not overwritten
        retake = reg(c, "alice@ex.com", "attacker chosen password")
        check("I5a duplicate register -> 200 (enumeration-safe, no 409)", retake.status_code == 200)
        check("I5b original password STILL logs in (claim-once: credential not overwritten)",
              login(c, "alice@ex.com", PW).status_code == 200)
        check("I5c attacker password does NOT log in",
              login(c, "alice@ex.com", "attacker chosen password").status_code == 401)

        # I6 — no secret leaves: the envelope carries the interop shape, never salt/hash/password
        env = login(c, "alice@ex.com", PW).json()
        check("I6a envelope shape", set(env) >= {"access_token", "refresh_token", "token_type", "expires_in", "expires_at", "user"})
        flat = base64.b64encode(repr(env).encode()).decode()  # noqa: F841 (silence linters; we check the dict below)
        check("I6b no salt/hash/password anywhere in the envelope",
              not any(k in env or k in env["user"] for k in ("salt", "hash", "password")))

        # I7 — session TTL: a session created far in the past (test clock) does not resolve
        expired = login(c, "alice@ex.com", PW, now=1000).json()["access_token"]
        check("I7 an expired session never resolves",
              c.get("/auth/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401)

        # I8 — rotation + the reuse-grace theft model: a benign concurrent/retried /refresh within the
        # grace is rejected but does NOT destroy the session; a STALE reuse after the grace is theft -> revoke-all.
        T = 2000000000   # a fixed future test-clock instant so the rotated session's exp stays > the wall clock
        t0 = login(c, "alice@ex.com", PW, now=T).json()["access_token"]   # create at T so the session is live at T
        t1 = c.post(f"/auth/refresh?now={T}", json={"token": t0}).json()["access_token"]
        check("I8a /refresh rotates to a NEW token", t1 != t0)
        check("I8b the OLD secret no longer resolves", c.get("/auth/me", headers={"Authorization": f"Bearer {t0}"}).status_code == 401)
        check("I8c the NEW token resolves", c.get("/auth/me", headers={"Authorization": f"Bearer {t1}"}).status_code == 200)
        check("I8d benign reuse WITHIN the grace is rejected (401)",
              c.post(f"/auth/refresh?now={T + 5}", json={"token": t0}).status_code == 401)
        check("I8e ...but the session SURVIVES (the new token still works — no self-destruct on a double-submit)",
              c.get("/auth/me", headers={"Authorization": f"Bearer {t1}"}).status_code == 200)
        check("I8f stale reuse AFTER the grace is rejected (401)",
              c.post(f"/auth/refresh?now={T + 1000}", json={"token": t0}).status_code == 401)
        check("I8g ...and theft detection revoked the whole session (the new token is now dead)",
              c.get("/auth/me", headers={"Authorization": f"Bearer {t1}"}).status_code == 401)

        # I9 — scoped logout
        a = login(c, "alice@ex.com", PW).json()["access_token"]
        b = login(c, "alice@ex.com", PW).json()["access_token"]
        c.post("/auth/logout", headers={"Authorization": f"Bearer {a}"})
        check("I9a local logout kills THIS session", c.get("/auth/me", headers={"Authorization": f"Bearer {a}"}).status_code == 401)
        check("I9b but NOT the other session", c.get("/auth/me", headers={"Authorization": f"Bearer {b}"}).status_code == 200)
        c.post("/auth/logout?scope=global", headers={"Authorization": f"Bearer {b}"})
        check("I9c global logout kills ALL sessions", c.get("/auth/me", headers={"Authorization": f"Bearer {b}"}).status_code == 401)

        # I10 — password reset: single-use token, revokes ALL sessions, old password dies
        reg(c, "reset@ex.com", PW)
        live = login(c, "reset@ex.com", PW).json()["access_token"]
        c.post("/auth/password/reset/request", json={"email": "reset@ex.com"})
        rtok = outbox_token("reset", "reset@ex.com")
        NEWPW = "a brand new strong password"
        ok = c.post("/auth/password/reset/confirm", json={"token": rtok, "password": NEWPW})
        check("I10a reset/confirm with the delivered token -> 200", ok.status_code == 200)
        check("I10b the OLD password no longer logs in", login(c, "reset@ex.com", PW).status_code == 401)
        check("I10c the NEW password logs in", login(c, "reset@ex.com", NEWPW).status_code == 200)
        check("I10d reset revoked all PRE-EXISTING sessions",
              c.get("/auth/me", headers={"Authorization": f"Bearer {live}"}).status_code == 401)
        check("I10e the reset token is SINGLE-USE (second confirm -> 400)",
              c.post("/auth/password/reset/confirm", json={"token": rtok, "password": "yet another password"}).status_code == 400)

        # I11 — email verification: single-use token sets the bound subject verified
        reg(c, "verify@ex.com", PW)
        check("I11a a fresh account is unverified", store.get("auth_users", "verify@ex.com")["email_verified"] is False)
        vtok = outbox_token("verify", "verify@ex.com")
        check("I11b verify/confirm with the delivered token -> 200",
              c.post("/auth/verify/confirm", json={"token": vtok}).status_code == 200)
        check("I11c the subject is now verified", store.get("auth_users", "verify@ex.com")["email_verified"] is True)
        check("I11d the verify token is SINGLE-USE (second confirm -> 400)",
              c.post("/auth/verify/confirm", json={"token": vtok}).status_code == 400)

        # I12 — token->subject binding: a reset token minted for reset2 only ever acts on reset2
        reg(c, "reset2@ex.com", PW)
        c.post("/auth/password/reset/request", json={"email": "reset2@ex.com"})
        t2 = outbox_token("reset", "reset2@ex.com")
        before = store.get("auth_users", "alice@ex.com")["hash"]
        c.post("/auth/password/reset/confirm", json={"token": t2, "password": "rebinding attempt password"})
        check("I12 consuming reset2's token never alters another subject (alice's hash unchanged)",
              store.get("auth_users", "alice@ex.com")["hash"] == before)

    print(f"AUTH INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
