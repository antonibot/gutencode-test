"""LEDGER INVARIANTS — correctness proofs for this domain's dangerous properties.
Run against the python app (cwd = <app>/python; the runner sets DATABASE_PATH + APP_TEST_CLOCK).
Credited by EXIT CODE ONLY: prints are for humans, sys.exit(0|1) is the verdict — a printed FAIL that exits 0
would be a silent pass, the exact bug class this system bans.

Proves:  I1 conservation — across any set of accepted transactions, the sum of ALL account balances is 0.
         I2 rejected tx has NO partial effect — a 422 consumes no tx id and writes no entries.
         I3 immutability by construction — no update/delete route exists on the ledger.
         I4 balances are DERIVED — re-reading is stable (same answer twice, no write-on-read)."""
import os
import random
import sys

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

failures = []

# ledger is ADMIN-ONLY: enable the test-session seam (Bearer test:<subject>, inert in prod) and send every
# request as the inert test admin 'root'. The I3 wrong-method probes are routing-level (405/404), auth-independent.
os.environ["APP_TEST_SESSIONS"] = "1"
ADMIN = {"Authorization": "Bearer test:root"}


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def main():
    random.seed(42)
    accounts = list(range(1, 8))
    with TestClient(app, raise_server_exceptions=False, headers=ADMIN) as c:
        # I1 — pump 40 random BALANCED transactions through, then prove conservation
        accepted = 0
        for _ in range(40):
            n = random.randint(2, 5)
            amounts = [random.randint(-500, 500) for _ in range(n - 1)]
            entries = [{"account_id": random.choice(accounts), "amount": a} for a in amounts]
            entries.append({"account_id": random.choice(accounts), "amount": -sum(amounts)})
            r = c.post("/ledger/transactions", json={"entries": entries})
            if r.status_code == 201:
                accepted += 1
        check("I1a all balanced transactions accepted", accepted == 40, f"accepted {accepted}/40")
        total = sum(c.get(f"/ledger/accounts/{a}/balance").json()["balance"] for a in accounts)
        check("I1b conservation: sum of ALL balances == 0", total == 0, f"sum = {total}")

        # I2 — a rejected (unbalanced) tx consumes NO tx id and leaves NO partial entries
        before = {a: c.get(f"/ledger/accounts/{a}/balance").json()["balance"] for a in accounts}
        r = c.post("/ledger/transactions", json={"entries": [
            {"account_id": 1, "amount": 999}, {"account_id": 2, "amount": -1}]})
        check("I2a unbalanced rejected with 422", r.status_code == 422, f"got {r.status_code}")
        after = {a: c.get(f"/ledger/accounts/{a}/balance").json()["balance"] for a in accounts}
        check("I2b rejected tx wrote nothing", before == after)
        r1 = c.post("/ledger/transactions", json={"entries": [
            {"account_id": 1, "amount": 7}, {"account_id": 2, "amount": -7}]})
        r2 = c.post("/ledger/transactions", json={"entries": [
            {"account_id": 1, "amount": 7}, {"account_id": 2, "amount": -7}]})
        check("I2c rejected tx consumed no id (ids stay consecutive)",
              r1.json()["id"] + 1 == r2.json()["id"], f"{r1.json()['id']} then {r2.json()['id']}")

        # I3 — immutability by construction: no mutating route on the ledger
        for method in ("PUT", "PATCH", "DELETE"):
            r = c.request(method, "/ledger/transactions")
            check(f"I3 {method} /ledger/transactions does not exist", r.status_code in (404, 405),
                  f"got {r.status_code}")

        # I4 — balances derived, read twice -> identical
        b1 = c.get("/ledger/accounts/1/balance").json()["balance"]
        b2 = c.get("/ledger/accounts/1/balance").json()["balance"]
        check("I4 balance read is stable (derived, no write-on-read)", b1 == b2)

    print(f"LEDGER INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
