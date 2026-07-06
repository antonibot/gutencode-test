"""STRIPE INVARIANTS — correctness proofs for this domain's dangerous properties.
Run against the python app (cwd = <app>/python; DATABASE_PATH + APP_TEST_CLOCK set by the harness).
Credited by EXIT CODE ONLY.

Proves:  I1 no double-charge — a replayed key returns the STORED charge; no new charge id is consumed.
         I2 key-reuse guard — same key + different amount/currency is 409 and the original charge survives
            (a naive replay would charge the original for a DIFFERENT amount — that flaw is closed).
         I3 opt-in — without a key every request is a fresh charge.
         I4 the webhook accepts ONLY a correctly signed, fresh payload: valid passes; a tampered payload, a
            forged signature, a stale timestamp, a garbage header, and a missing header all reject. The webhook is
            authed by the HMAC, NOT a session — every call here is token-less (signature is the identity).
         I5 TWO PROCESSES racing the SAME key charge EXACTLY ONCE (both receive the same charge id).
         I6 strict input — bad amounts/currencies and a malformed present key are rejected.
/stripe/charges requires the authenticated caller, so every charge call carries a 'Bearer test:<subject>'
token resolved by the APP_TEST_SESSIONS=1 seam (set below; inherited by the race subprocesses). The webhook stays
token-less. require_identity does not change any of the proven idempotency/signature behavior."""
import hmac
import hashlib
import json
import os
import subprocess
import sys

os.environ["APP_TEST_SESSIONS"] = "1"  # the test-session seam: a 'test:<subject>' bearer resolves (inert in prod)
# TWO active endpoint secrets BEFORE the app import (the app reads STRIPE_WEBHOOK_SECRET at module load) — so I9 can
# prove zero-downtime rotation: a webhook signed with EITHER active secret verifies.
os.environ["STRIPE_WEBHOOK_SECRET"] = "whsec_demo_change_me,whsec_rotated_new"

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

SECRETS = [s.strip() for s in os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_demo_change_me").split(",") if s.strip()]
SECRET = SECRETS[0]   # the existing webhook tests sign with the FIRST active secret (the app accepts any active one)
AUTH = {"Authorization": "Bearer test:alice"}  # the authenticated charge caller (the webhook stays token-less)
failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def sign(ts, payload):
    return f"t={ts},v1=" + hmac.new(SECRET.encode(), f"{ts}.{payload}".encode(), hashlib.sha256).hexdigest()


RACE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
with TestClient(app, raise_server_exceptions=False) as c:
    r = c.post("/stripe/charges", json={"amount": 4242, "currency": "usd"},
               headers={"Authorization": "Bearer test:alice", "Idempotency-Key": "RACE"})
    print(r.json()["id"] if r.status_code == 201 else f"status={r.status_code}")
"""


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        def charge(amount, currency="usd", key=None):
            h = dict(AUTH)  # charges require the authenticated caller
            if key is not None:
                h["Idempotency-Key"] = key
            return c.post("/stripe/charges", json={"amount": amount, "currency": currency}, headers=h)

        # I1 — no double-charge: the replay is byte-identical and consumes no id
        first = charge(2000, key="K1")
        replay = charge(2000, key="K1")
        check("I1a first charge -> 201 succeeded", first.status_code == 201 and first.json()["status"] == "succeeded")
        check("I1b replay -> the SAME stored charge", replay.json() == first.json())
        nxt = charge(10, key="K2")
        check("I1c the replay consumed NO charge id (next id contiguous)",
              int(nxt.json()["id"].split("_")[1]) == int(first.json()["id"].split("_")[1]) + 1)

        # I2 — reuse with a different body: 409, the original survives
        check("I2a same key, different amount -> 409", charge(999, key="K1").status_code == 409)
        check("I2b same key, different currency -> 409", charge(2000, "eur", key="K1").status_code == 409)
        check("I2c the original charge survives the conflict attempts", charge(2000, key="K1").json() == first.json())

        # I3 — opt-in: keyless charges are never deduped
        a, b = charge(50), charge(50)
        check("I3 no key -> two identical requests, two charges", a.json()["id"] != b.json()["id"])

        # I4 — the webhook gate: only a correctly signed, fresh payload passes
        payload = json.dumps({"type": "payment_succeeded"}, separators=(",", ":"))
        def hook(body, sig, now=1000):
            headers = {"Content-Type": "application/json"}
            if sig is not None:
                headers["Stripe-Signature"] = sig
            return c.post(f"/stripe/webhook?now={now}", content=body, headers=headers)
        check("I4a a valid signature passes", hook(payload, sign(1000, payload)).status_code == 200)
        check("I4b a tampered payload rejects", hook(payload.replace("succeeded", "TAMPERED"),
                                                     sign(1000, payload)).status_code == 400)
        check("I4c a forged signature rejects", hook(payload, "t=1000,v1=" + "0" * 64).status_code == 400)
        check("I4d a stale timestamp rejects (replay window)", hook(payload, sign(1000, payload), now=99999).status_code == 400)
        check("I4e a garbage header rejects", hook(payload, "totally-garbage").status_code == 400)
        check("I4f a missing header rejects", hook(payload, None).status_code == 422)

        # I9 — MULTI-SECRET ROTATION + MULTI-v1: the app holds TWO active endpoint secrets (set
        # before import). A webhook signed with EITHER verifies (zero-downtime rotation); a NON-active secret rejects;
        # and a header carrying MULTIPLE v1 (Stripe sends one per active secret during a roll) verifies if ANY matches.
        def sign_with(sec, ts, body):
            return f"t={ts},v1=" + hmac.new(sec.encode(), f"{ts}.{body}".encode(), hashlib.sha256).hexdigest()
        check("I9a signed with the FIRST active secret verifies",
              hook(payload, sign_with(SECRETS[0], 1000, payload)).status_code == 200)
        check("I9b signed with the SECOND (rotated) active secret verifies",
              hook(payload, sign_with(SECRETS[1], 1000, payload)).status_code == 200)
        check("I9c signed with a NON-active secret rejects",
              hook(payload, sign_with("whsec_not_configured", 1000, payload)).status_code == 400)
        valid_v1 = sign_with(SECRETS[0], 1000, payload).split("v1=", 1)[1]
        check("I9d multiple v1 (garbage FIRST, valid second) still verifies (collect-all, not last-wins)",
              hook(payload, f"t=1000,v1={'0' * 64},v1={valid_v1}").status_code == 200)
        check("I9e a non-positive timestamp rejects (a far-future ts can't bypass the window)",
              hook(payload, sign_with(SECRETS[0], 0, payload), now=0).status_code == 400)

        # I6 — strict input (authenticated: a no-token caller is 401, see I7 — strict checks run AFTER auth)
        # incl. currency: a well-formed but NON-ISO-4217 code ("xyz") is 422 (the closed currency set, not just well-formed)
        for bad in ({"amount": 0, "currency": "usd"}, {"amount": "x", "currency": "usd"},
                    {"amount": 10, "currency": ""}, {"amount": 10}, {"amount": 10, "currency": "xyz"}):
            check(f"I6 invalid charge body {bad!r} -> 422",
                  c.post("/stripe/charges", json=bad, headers=AUTH).status_code == 422)
        check("I6 empty Idempotency-Key -> 422", charge(5, key="").status_code == 422)

        # I7 — the charge API requires the authenticated caller (anonymous = charge fabrication). Auth resolves
        # BEFORE semantic validation, so even a body that WOULD be 422 is 401 without a token (precedence: AUTH>SEMANTIC).
        check("I7a no token -> 401", c.post("/stripe/charges",
              json={"amount": 100, "currency": "usd"}).status_code == 401)
        check("I7b an invalid bearer token -> 401", c.post("/stripe/charges", json={"amount": 100, "currency": "usd"},
              headers={"Authorization": "Bearer nosuchtoken"}).status_code == 401)
        check("I7c a non-Bearer scheme -> 401", c.post("/stripe/charges", json={"amount": 100, "currency": "usd"},
              headers={"Authorization": "test:alice"}).status_code == 401)
        check("I7d no token + invalid body -> 401 (auth precedes semantic validation)",
              c.post("/stripe/charges", json={"amount": 0, "currency": "usd"}).status_code == 401)

        # I8 — CROSS-CALLER ISOLATION + collision-resistance: an Idempotency-Key is PRIVATE
        # to its caller. caller B reusing A's key gets B's OWN fresh charge — never A's stored charge, and B cannot
        # 409-grief A with a different body. The slot is scoped_key(route, subject, key); subject comes from the
        # AUTHENTICATED session (test:<sub> via APP_TEST_SESSIONS), never a client field.
        def charge_as(sub, amount, key, currency="usd"):
            return c.post("/stripe/charges", json={"amount": amount, "currency": currency},
                          headers={"Authorization": f"Bearer test:{sub}", "Idempotency-Key": key})
        alice_s = charge_as("alice", 1000, "SHARED")
        bob_s = charge_as("bob", 3000, "SHARED")     # SAME key, DIFFERENT caller, DIFFERENT amount
        check("I8a cross-caller same key -> a DIFFERENT charge (no cross-caller collision)",
              alice_s.status_code == 201 and bob_s.status_code == 201 and alice_s.json()["id"] != bob_s.json()["id"])
        check("I8b a different body under another caller's key is NOT 409 (no cross-caller grief)", bob_s.status_code == 201)
        check("I8c each caller replays only its OWN charge",
              charge_as("alice", 1000, "SHARED").json() == alice_s.json()
              and charge_as("bob", 3000, "SHARED").json() == bob_s.json())
        # I8d — COLLISION-RESISTANCE: (caller="alice:x", key="y") vs (caller="alice", key="x:y") — EQUAL under a naive
        # ':'-join — must land in DISTINCT slots. Proves digest.scoped_key's pre-hash is INJECTIVE,
        # the same property the shared digest vectors assert ×3.
        p = charge_as("alice:x", 5, "COL"); q = charge_as("alice", 6, "COL:Y")
        check("I8d the collision pair lands in DISTINCT slots (scoped_key is injective)",
              p.status_code == 201 and q.status_code == 201 and p.json()["id"] != q.json()["id"])

    # I5 — the double-charge race: two processes, one key, concurrently — exactly one charge may exist
    if os.getenv("DATABASE_PATH"):
        procs = [subprocess.Popen([sys.executable, "-c", RACE_WORKER], cwd=os.getcwd(),
                                  env={**os.environ, "LOG_LEVEL": "silent"},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for _ in range(2)]
        outs = []
        for p in procs:
            so, se = p.communicate(timeout=120)
            outs.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:120]))
        ids = [o for rc, o in outs if rc == 0]
        check("I5 two processes racing one key -> the SAME charge id (no double-charge)",
              len(ids) == 2 and ids[0] == ids[1] and ids[0].startswith("ch_"), f"got {outs}")
    else:
        print("  [FAIL] I5 double-charge race NOT RUN — DATABASE_PATH unset (the harness must provide it)")
        failures.append("I5 not run")

    print(f"STRIPE INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
