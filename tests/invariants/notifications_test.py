"""NOTIFICATIONS INVARIANTS — correctness proofs for this domain's dangerous properties, now keyed to the
AUTHENTICATED identity (the core require_identity seam), NOT a caller-supplied param. Run against the python
app (cwd = <app>/python; the app includes auth — notifications `requires` it). Credited by EXIT CODE ONLY.

Proves:  I0 sender is the AUTHENTICATED caller — `from` is stamped from the sender's REAL token; sending without a
            valid bearer is 401; a body `from` is OVERRIDDEN by the token subject (the sender cannot be forged).
         I1 identity scoping — a user's list contains EXACTLY their rows, keyed by their REAL bearer token
            (a register->login flow), in id order.
         I2 cross-identity isolation — another user's REAL token cannot read or mark your notification: 404,
            byte-identical to missing, the body never leaks your message, and the 404 path is side-effect-free.
         I3 monotonic read-state — unread -> read; idempotent; nothing returns it to unread.
         I4 deny-by-default — no token / malformed scheme / forged token is 401 on every scoped route (send too).
         I5 the spoof vector is CLOSED — a ?recipient= query param is IGNORED; identity comes ONLY from the token.
         I6 strict input — bad send bodies (with a valid token) are rejected 422.
         I7 BOUNDED list — the owner-scoped list rides the shared paginate seam: a page is capped to `limit`,
            the opaque cursor round-trips to the next (still owner-scoped) page, and a malformed cursor/limit -> 422."""
import os
import sys

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402
from app_pkg.core import store  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        def token_for(user):
            # a REAL bearer token via the auth domain (register -> login) — not the test seam
            c.post("/auth/register", json={"email": user, "password": f"pw-{user}-1234"})
            return c.post("/auth/login", json={"email": user, "password": f"pw-{user}-1234"}).json()["access_token"]

        def auth(t):
            return {"Authorization": f"Bearer {t}"}

        def send(token, to, message, **extra):
            # sending is AUTHENTICATED; `extra` lets a test plant a hostile body `from` to prove it's ignored
            return c.post("/notifications", json={"to": to, "message": message, **extra}, headers=auth(token))

        def listing(t, **params):
            return c.get("/notifications", headers=auth(t), params=params)

        def mark(nid, t):
            return c.post(f"/notifications/{nid}/read", headers=auth(t))

        ta, tb = token_for("alice"), token_for("bob")

        # I0 — the SENDER is the authenticated caller, never a body field
        check("I0a no token cannot send -> 401",
              c.post("/notifications", json={"to": "alice", "message": "anon"}).status_code == 401)
        check("I0b forged/unknown token cannot send -> 401",
              c.post("/notifications", json={"to": "alice", "message": "x"},
                     headers={"Authorization": "Bearer deadbeefdeadbeef"}).status_code == 401)
        # (route these to 'carol' so they don't pollute alice's/bob's lists asserted exactly below)
        stamped = send(ta, "carol", "from-alice").json()
        check("I0c `from` is stamped from the sender's token (alice)", stamped.get("from") == "alice")
        forged = send(tb, "carol", "spoofed", **{"from": "admin"}).json()
        check("I0d a body `from` is OVERRIDDEN by the token subject (sender un-forgeable)",
              forged.get("from") == "bob")
        check("I0e the stored row records the TOKEN subject as `from`, not the body value",
              store.get("notifications_items", str(forged["id"]))["from"] == "bob")

        a1 = send(ta, "alice", "alpha-secret-one").json()
        a2 = send(ta, "alice", "alpha-two").json()
        b1 = send(tb, "bob", "bravo-one").json()

        # I1 — identity scoping by REAL token (the list is now a bounded {results, next_cursor} page)
        la, lb = listing(ta).json()["results"], listing(tb).json()["results"]
        check("I1a alice's token lists exactly her 2 rows, id order",
              [n["id"] for n in la] == [a1["id"], a2["id"]] and all(n["to"] == "alice" for n in la))
        check("I1b bob's token lists exactly his row", [n["id"] for n in lb] == [b1["id"]])

        # I2 — cross-identity isolation: bob's REAL token cannot touch alice's note
        cross = mark(a1["id"], tb)
        missing = mark(999999, tb)
        check("I2a bob's token marking alice's note is 404", cross.status_code == 404)
        check("I2b cross-identity 404 == missing 404 (no existence leak)", cross.json() == missing.json())
        check("I2c the 404 never carries alice's message", b"alpha-secret-one" not in cross.content)
        check("I2d the cross-identity attempt left it UNREAD (side-effect-free)",
              store.get("notifications_items", str(a1["id"]))["status"] == "unread")

        # I3 — monotonic read-state (alice's own token)
        r1 = mark(a1["id"], ta)
        check("I3a mark read -> 200 read", r1.status_code == 200 and r1.json()["status"] == "read")
        r2 = mark(a1["id"], ta)
        check("I3b marking again is idempotent (still read)", r2.json() == r1.json())
        mark(a1["id"], tb)   # a hostile re-probe after the read
        check("I3c nothing returns it to unread",
              store.get("notifications_items", str(a1["id"]))["status"] == "read")

        # I4 — deny-by-default: a valid bearer token is REQUIRED on every scoped route (list AND send)
        check("I4a no token -> 401", c.get("/notifications").status_code == 401)
        check("I4b malformed scheme (no 'Bearer ') -> 401",
              c.get("/notifications", headers={"Authorization": ta}).status_code == 401)
        check("I4c forged/unknown token -> 401",
              c.get("/notifications", headers={"Authorization": "Bearer deadbeefdeadbeef"}).status_code == 401)
        check("I4d no token cannot SEND -> 401 (auth precedes body validation: a CLEAN body still 401s)",
              c.post("/notifications", json={"to": "alice", "message": "hi"}).status_code == 401)

        # I5 — the spoof vector is CLOSED: a ?recipient= param cannot override the token identity
        spoof = listing(ta, recipient="bob").json()["results"]
        check("I5 a ?recipient=bob param is IGNORED — alice's token still lists ONLY alice's rows",
              [n["id"] for n in spoof] == [a1["id"], a2["id"]])

        # I7 — BOUNDED list: the owner-scoped list rides the shared paginate seam — a page is
        # capped to `limit`, the opaque cursor round-trips to the next page (still owner-scoped), and a malformed
        # cursor/limit is a clean 422. (alice's a1, a2 from I1; the page never leaks across the owner scope.)
        p1 = listing(ta, limit=1).json()
        check("I7a a page is bounded to limit + carries a forward cursor",
              [n["id"] for n in p1["results"]] == [a1["id"]] and bool(p1["next_cursor"]))
        p2 = listing(ta, limit=1, cursor=p1["next_cursor"]).json()
        check("I7b the opaque cursor round-trips to the next owner-scoped page",
              [n["id"] for n in p2["results"]] == [a2["id"]] and p2["next_cursor"] is None)
        check("I7c a malformed cursor -> 422", listing(ta, cursor="MDU").status_code == 422)
        check("I7d a limit < 1 -> 422", listing(ta, limit=0).status_code == 422)
        check("I7e an over-large limit CLAMPS (bounded, not an error)", listing(ta, limit=9999).status_code == 200)
        check("I7f the bounded page stays owner-scoped (only alice's rows, never bob's)",
              all(n["to"] == "alice" for n in p1["results"] + p2["results"]))

        # I6 — strict send input (WITH a valid token — auth comes first, so these must reach the 422 validator)
        for bad in ({"to": "x"}, {"to": 7, "message": "m"}, {"to": "", "message": "m"},
                    {"to": "x", "message": ""}, {"to": "x", "message": True}):
            check(f"I6 invalid send body {bad!r} -> 422",
                  c.post("/notifications", json=bad, headers=auth(ta)).status_code == 422)

    print(f"NOTIFICATIONS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
