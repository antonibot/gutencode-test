"""BILLING INVARIANTS — subscription correctness scoped to the AUTHENTICATED owner (the core require_identity
seam), NOT a client-supplied field. Run against the python app (cwd=<app>/python; the app includes auth — billing
`requires` it). Credited by EXIT CODE ONLY: prints are for humans, sys.exit(0|1) is the verdict.

Proves:  I0 deny-by-default — every route is 401 without a valid bearer token (no / malformed / forged).
         I1 derived amount — the price comes from the plan catalog; a client-supplied amount is unexpressible.
         I2 deny-by-default plan — an unknown plan is rejected; no record is created for it (ids stay contiguous).
         I3 monotonic lifecycle — active -> canceled; cancel is idempotent; a canceled subscription NEVER
            returns to active (re-cancel, re-read, and even a re-subscribe leave it terminal).
         I4 cancel changes ONLY the status — the derived amount and identity fields are untouched.
         I5 records live in the durable store seam, the whole subscription as one row.
         I6 owner scoping — the owner is the TOKEN's subject: a caller cannot read OR cancel another owner's
            subscription (404, indistinguishable from missing), and a smuggled body `owner` cannot redirect a
            create to someone else."""
import os
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


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        def token_for(u):
            c.post("/auth/register", json={"email": u, "password": f"pw-{u}-1234"})
            return c.post("/auth/login", json={"email": u, "password": f"pw-{u}-1234"}).json()["access_token"]

        def H(t):
            return {"Authorization": f"Bearer {t}"}

        ta, tb = token_for("alice"), token_for("bob")

        # I0 — deny-by-default: a valid bearer token is required on every route (bodies/ids are valid, only auth fails)
        check("I0a POST no token -> 401", c.post("/billing/subscriptions", json={"plan": "pro"}).status_code == 401)
        check("I0b GET no token -> 401", c.get("/billing/subscriptions/1").status_code == 401)
        check("I0c cancel no token -> 401", c.post("/billing/subscriptions/1/cancel").status_code == 401)
        check("I0d forged token -> 401", c.post("/billing/subscriptions", json={"plan": "pro"}, headers={"Authorization": "Bearer deadbeef"}).status_code == 401)
        check("I0e malformed scheme -> 401", c.get("/billing/subscriptions/1", headers={"Authorization": ta}).status_code == 401)

        # I1 — the amount is derived, and a smuggled amount cannot win
        pro = c.post("/billing/subscriptions", json={"plan": "pro"}, headers=H(ta))
        check("I1a pro -> 201 active, amount 2000 (from the catalog), owner = the token",
              pro.status_code == 201 and pro.json()["status"] == "active"
              and pro.json()["amount"] == 2000 and pro.json()["owner"] == "alice")
        smuggle = c.post("/billing/subscriptions", json={"plan": "free", "amount": 999999}, headers=H(ta))
        check("I1b a client-supplied amount is IGNORED (free == 0, not 999999)",
              smuggle.status_code == 201 and smuggle.json()["amount"] == 0)
        ent = c.post("/billing/subscriptions", json={"plan": "enterprise"}, headers=H(ta))
        check("I1c enterprise == 10000 (derived)", ent.json()["amount"] == 10000)

        # I2 — unknown plan: rejected AND no record minted (the next create's id is contiguous)
        before_id = ent.json()["id"]
        check("I2a unknown plan -> 422", c.post("/billing/subscriptions",
                                                json={"plan": "platinum"}, headers=H(ta)).status_code == 422)
        nxt = c.post("/billing/subscriptions", json={"plan": "free"}, headers=H(ta))
        check("I2b the rejected subscribe consumed no id (ids stay contiguous)",
              nxt.json()["id"] == before_id + 1, f"{before_id} then {nxt.json()['id']}")

        # I3 — monotonic lifecycle: terminal, idempotent, never resurrects
        sid = pro.json()["id"]
        c1r = c.post(f"/billing/subscriptions/{sid}/cancel", headers=H(ta))
        check("I3a cancel -> 200 canceled", c1r.status_code == 200 and c1r.json()["status"] == "canceled")
        c2r = c.post(f"/billing/subscriptions/{sid}/cancel", headers=H(ta))
        check("I3b cancel AGAIN -> 200, still canceled (idempotent)", c2r.json()["status"] == "canceled")
        check("I3c read after cancel -> still canceled (never resurrects)",
              c.get(f"/billing/subscriptions/{sid}", headers=H(ta)).json()["status"] == "canceled")
        c.post("/billing/subscriptions", json={"plan": "pro"}, headers=H(ta))   # same owner subscribes anew
        check("I3d a NEW subscription never mutates the canceled one",
              c.get(f"/billing/subscriptions/{sid}", headers=H(ta)).json()["status"] == "canceled")

        # I4 — cancel changes only the status
        after = c.get(f"/billing/subscriptions/{sid}", headers=H(ta)).json()
        check("I4 canceled record keeps id/owner/plan/amount",
              after["id"] == sid and after["owner"] == "alice" and after["plan"] == "pro" and after["amount"] == 2000)

        # I5 — the durable seam holds the whole record
        row = store.get("billing_subs", str(sid))
        check("I5 whole record in the store seam, status canceled, owner stamped",
              row is not None and row["status"] == "canceled" and row["amount"] == 2000 and row["owner"] == "alice")

        # I6 — owner scoping: the owner is the TOKEN's subject. bob can neither read nor cancel alice's subscription,
        # and a missing id is the SAME 404 as a cross-owner one (existence does not leak).
        bobs = c.post("/billing/subscriptions", json={"plan": "pro"}, headers=H(tb))
        bob_sid = bobs.json()["id"]
        cross_read = c.get(f"/billing/subscriptions/{bob_sid}", headers=H(ta))
        missing = c.get("/billing/subscriptions/999999", headers=H(ta))
        check("I6a alice cannot read bob's subscription (404)", cross_read.status_code == 404)
        check("I6b cross-owner 404 == missing 404 (existence does not leak)", cross_read.json() == missing.json())
        check("I6c alice cannot cancel bob's subscription (404)",
              c.post(f"/billing/subscriptions/{bob_sid}/cancel", headers=H(ta)).status_code == 404)
        check("I6d bob's subscription is untouched by alice's cancel attempt — still active",
              c.get(f"/billing/subscriptions/{bob_sid}", headers=H(tb)).json()["status"] == "active")
        # a smuggled body `owner` cannot redirect the create to bob — the stamp is the token's
        sneaky = c.post("/billing/subscriptions", json={"plan": "pro", "owner": "bob"}, headers=H(ta))
        check("I6e smuggled body owner ignored — the subscription is alice's", sneaky.json()["owner"] == "alice")
        check("I6f the smuggled subscription is invisible to bob",
              c.get(f"/billing/subscriptions/{sneaky.json()['id']}", headers=H(tb)).status_code == 404)

    print(f"BILLING INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
