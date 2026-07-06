"""ADMIN INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the python app (cwd =
<app>/python). Credited by EXIT CODE ONLY.

Proves:  I1 GUARD ON EVERY ROUTE — record/list/get all reject a missing token, a wrong token, and a wrong
            scheme with the same 401 (non-enumerable), and only the exact admin token is accepted.
         I2 UNAUTHORIZED LEAVES NO TRACE — a 401'd record attempt writes nothing (the log length is unchanged,
            white-box and via the authorized list).
         I3 APPEND-ONLY — there is no update or delete route; ids are monotonic; an authorized record persists.
         I4 the read is guarded too — list/get need the token (the trail is admin-only).
         I5 strict input (with a valid token, a malformed body/ id is 422).
         I6 BOUNDED LIST — the admin-only list returns {results, next_cursor}; a small limit bounds the page to
            that size and hands back a cursor that round-trips to the next page (eventually next_cursor null), and a
            malformed cursor/limit is 422 — all WHILE the admin guard still holds."""
import os
import sys

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.core import store  # noqa: E402
from app_pkg.app import app  # noqa: E402

TOKEN = os.getenv("ADMIN_TOKEN", "admin_dev_token_change_me")
AUTH = {"Authorization": f"Bearer {TOKEN}"}
failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        body = {"action": "deactivate_user", "target": "alice"}

        # I1 — the guard rejects every bad credential the same way
        denials = [
            ("no header", c.post("/admin/actions", json=body)),
            ("wrong token", c.post("/admin/actions", json=body, headers={"Authorization": "Bearer nope"})),
            ("wrong scheme", c.post("/admin/actions", json=body, headers={"Authorization": TOKEN})),
            ("empty bearer", c.post("/admin/actions", json=body, headers={"Authorization": "Bearer "})),
        ]
        for label, r in denials:
            check(f"I1 {label} -> 401", r.status_code == 401)
        check("I1b all denials are the same body (non-enumerable)",
              len({r.json()["detail"] for _, r in denials}) == 1)

        # I2 — unauthorized leaves NO trace
        check("I2a the store is empty after the denied attempts", store.values("admin_actions") == [])
        ok = c.post("/admin/actions", json=body, headers=AUTH)
        check("I2b an authorized record -> 201", ok.status_code == 201 and ok.json()["id"] == 1)
        c.post("/admin/actions", json=body, headers={"Authorization": "Bearer nope"})  # denied
        check("I2c a later denied attempt added nothing",
              len(c.get("/admin/actions", headers=AUTH).json()["results"]) == 1)   # list is {results, next_cursor}

        # I3 — append-only + monotonic
        second = c.post("/admin/actions", json={"action": "archive_org", "target": "acme"}, headers=AUTH)
        check("I3a ids are monotonic", second.json()["id"] == 2)
        for method in ("PUT", "PATCH", "DELETE"):
            r = c.request(method, "/admin/actions/1", headers=AUTH)
            check(f"I3b {method} on an action does not exist (append-only)", r.status_code in (404, 405))

        # I4 — reads are guarded
        check("I4a list without token -> 401", c.get("/admin/actions").status_code == 401)
        check("I4b get without token -> 401", c.get("/admin/actions/1").status_code == 401)
        check("I4c get with token -> the action", c.get("/admin/actions/1", headers=AUTH).json()["target"] == "alice")

        # I5 — strict input (authorized)
        check("I5a unknown action id -> 404", c.get("/admin/actions/999", headers=AUTH).status_code == 404)
        check("I5b non-numeric id -> 422", c.get("/admin/actions/abc", headers=AUTH).status_code == 422)
        for bad in ({"target": "y"}, {"action": "", "target": "y"}, {"action": "x", "target": 7}):
            check(f"I5c invalid record {bad!r} -> 422",
                  c.post("/admin/actions", json=bad, headers=AUTH).status_code == 422)

        # I6 — BOUNDED LIST: the trail (ids 1, 2) is {results, next_cursor}; a small limit bounds the page
        # and the cursor round-trips to the next page (eventually next_cursor null), all while the guard still holds.
        full = c.get("/admin/actions", headers=AUTH).json()
        check("I6a list is the bounded shape {results, next_cursor}",
              isinstance(full, dict) and set(full) == {"results", "next_cursor"})
        check("I6b the full list is the whole trail in id order, no next page",
              [a["id"] for a in full["results"]] == [1, 2] and full["next_cursor"] is None)
        first = c.get("/admin/actions?limit=1", headers=AUTH).json()
        check("I6c limit=1 BOUNDS the page to one record (the first) + a non-null cursor",
              len(first["results"]) == 1 and first["results"][0]["id"] == 1 and first["next_cursor"] is not None)
        nxt = c.get(f"/admin/actions?limit=1&cursor={first['next_cursor']}", headers=AUTH).json()
        check("I6d the cursor ROUND-TRIPS to the next record, then next_cursor is null (end reached)",
              len(nxt["results"]) == 1 and nxt["results"][0]["id"] == 2 and nxt["next_cursor"] is None)
        check("I6e a malformed cursor -> 422", c.get("/admin/actions?cursor=!!!", headers=AUTH).status_code == 422)
        check("I6f a malformed limit -> 422", c.get("/admin/actions?limit=0", headers=AUTH).status_code == 422)
        check("I6g the bounded list is STILL admin-guarded (no token -> 401)",
              c.get("/admin/actions?limit=1").status_code == 401)

    print(f"ADMIN INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
