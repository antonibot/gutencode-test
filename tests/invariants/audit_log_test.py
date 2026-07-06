"""AUDIT_LOG INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the python app (cwd = <app>/python; DATABASE_PATH set by the harness). Credited by
EXIT CODE ONLY.

Proves:  I1 chain integrity — every event links to its predecessor over the COMPLETE record (id·at·actor·action);
            /verify confirms the derived chain.
         I2 immutability by construction — no update/delete route exists on the log.
         I3 TAMPER-EVIDENCE (action) — editing a past action (white-box, through the store) makes /verify report
            invalid, naming the broken link; restoring the original makes it valid again.
         I4 HOLE-EVIDENCE — a missing event (crash damage, white-box delete) is reported invalid, named.
         I5 fork-resistance — TWO PROCESSES appending concurrently produce sequential ids on ONE valid chain
            (the atomic head claim cannot build twice on the same predecessor).
         I6 strict input — a non-string / empty / control-character actor OR action is rejected (both fields).
         I7 WRITES ARE SERVICE-ONLY, THE DISCLOSING READ ADMIN-ONLY, /verify STAYS OPEN — append (POST
            /events) is gated by core.require_service (no/wrong token 401; an admin session is a user, not a
            service, so also 401); list (GET /events) needs the admin role (no token 401, non-admin 403); /verify
            works with NO token (the integrity probe leaks only {valid, count, detail}, no event contents).
         I8 BOUNDED LIST — the admin event list is paginated through the shared paginate part: the response is
            {results, next_cursor} (never a bare unbounded array); a ?limit page is bounded to that size and hands
            back an opaque next_cursor; feeding that cursor back returns the NEXT page (round-trip), and the union of
            the pages is the whole chain in order; a malformed cursor/limit is 422 (auth precedence is preserved —
            a non-admin is still 403 BEFORE any pagination is attempted).
         I9 BACKDATE-EVIDENCE (at) — editing a past event's `at` timestamp (white-box) makes /verify report invalid:
            the WHEN is covered by the hash, so a backdated/forward-dated record breaks its link. Restoring heals.
         I10 ACTOR-FORGE-EVIDENCE (actor) — editing a past event's `actor` (white-box) makes /verify report invalid:
            the WHO is covered by the hash, so a forged subject breaks its link. Restoring heals.
         I12 PREIMAGE UNAMBIGUITY (colon-injectivity) — an event with actor "a:b"/action "c" and the swap
            actor "a"/action "b:c" — which a naive ':'-join would hash IDENTICALLY (the delimiter-collision class) — are
            distinguished: tampering a stored row to the colliding pair (keeping its hash) is CAUGHT by /verify,
            because actor and action are PRE-HASHED before the join. A naive join would miss the forgery.
         (I11 — a signed chain head, defending against a full-rewrite by an operator who holds the store — is a
            DELIBERATELY DEFERRED v2 capability: the `signing` part is HMAC-only/symmetric, so a same-process signed
            head is false security; the real close is an external witness/WORM/KMS-held key.)"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.getcwd())

# audit_log APPENDS are SERVICE-only, the disclosing LIST is ADMIN-only. The test-session seam (Bearer
# test:<subject>, inert in prod) gives an inert admin 'root' for the list; the append carries the SERVICE_TOKEN (the
# env-overridable dev default). /verify is open. I7 below proves all three walls via a separate tokenless client.
os.environ["APP_TEST_SESSIONS"] = "1"

from starlette.testclient import TestClient  # noqa: E402

from app_pkg.core import store  # noqa: E402
from app_pkg.app import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test:root"}                       # the inert test admin — for the disclosing LIST
SERVICE = {"Authorization": "Bearer " + os.getenv("SERVICE_TOKEN", "service_dev_token_change_me")}  # for the APPEND

failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


# The race worker appends as the trusted SERVICE (service-gated append must stay authed across processes — the
# fork-resistance proof still exercises the real atomic head claim).
RACE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
svc = {"Authorization": "Bearer " + os.environ.get("SERVICE_TOKEN", "service_dev_token_change_me")}
with TestClient(app, raise_server_exceptions=False) as c:
    r = c.post("/audit_log/events", json={"actor": "racer", "action": "race_event"}, headers=svc)
    print(r.json()["id"] if r.status_code == 201 else f"status={r.status_code}")
"""


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        # I1 — build a chain, verify it end to end (appends carry the SERVICE token; /verify is open)
        e1 = c.post("/audit_log/events", json={"actor": "alice", "action": "alpha"}, headers=SERVICE).json()
        e2 = c.post("/audit_log/events", json={"actor": "bob", "action": "beta"}, headers=SERVICE).json()
        check("I1a events link (e2.prev == e1.hash)", e2["prev"] == e1["hash"])
        v = c.get("/audit_log/verify").json()
        check("I1b /verify confirms the chain", v["valid"] is True and v["count"] == 2)

        # I2 — immutability by construction
        for method in ("PUT", "PATCH", "DELETE"):
            r = c.request(method, "/audit_log/events/1")
            check(f"I2 {method} on an event does not exist", r.status_code in (404, 405), f"got {r.status_code}")

        # I3 — tamper-evidence: edit a past action through the store; /verify must name the damage
        original = store.get("audit_log_events", "1")
        store.put("audit_log_events", "1", {**original, "action": "FORGED"})
        v = c.get("/audit_log/verify").json()
        check("I3a a tampered action is DETECTED", v["valid"] is False and "1" in v["detail"], f"got {v}")
        store.put("audit_log_events", "1", original)
        check("I3b restoring the original heals the chain", c.get("/audit_log/verify").json()["valid"] is True)

        # I4 — hole-evidence: a missing event (the crash-damage class) is reported, never smoothed over
        store.delete_("audit_log_events", "2")
        v = c.get("/audit_log/verify").json()
        check("I4a a hole in the chain is DETECTED and named", v["valid"] is False and "2" in v["detail"], f"got {v}")
        store.put("audit_log_events", "2", e2)
        check("I4b restoring the event heals the chain", c.get("/audit_log/verify").json()["valid"] is True)

        # I9 — backdate-evidence: the WHEN is in the hash (event 1's `original` from I3 is current again).
        store.put("audit_log_events", "1", {**original, "at": original["at"] + 9999})
        v = c.get("/audit_log/verify").json()
        check("I9a a backdated/forward-dated `at` is DETECTED", v["valid"] is False and "1" in v["detail"], f"got {v}")
        store.put("audit_log_events", "1", original)
        check("I9b restoring the timestamp heals the chain", c.get("/audit_log/verify").json()["valid"] is True)

        # I10 — actor-forge-evidence: the WHO is in the hash. Edit a past event's `actor`; /verify must name the break.
        store.put("audit_log_events", "1", {**original, "actor": "FORGED_ACTOR"})
        v = c.get("/audit_log/verify").json()
        check("I10a a forged actor is DETECTED", v["valid"] is False and "1" in v["detail"], f"got {v}")
        store.put("audit_log_events", "1", original)
        check("I10b restoring the actor heals the chain", c.get("/audit_log/verify").json()["valid"] is True)

        # I12 — PREIMAGE UNAMBIGUITY: actor "a:b"/action "c" and the swap actor "a"/action "b:c" hash IDENTICALLY
        # under a naive ':'-join (the delimiter-collision class). Pre-hashing each field defeats it. Append the first pair,
        # then tamper the STORED row to the colliding swap (keeping the original hash) — /verify MUST catch it; a
        # naive-join implementation would report "valid" and miss the forgery.
        ec = c.post("/audit_log/events", json={"actor": "a:b", "action": "c"}, headers=SERVICE).json()
        cid = str(ec["id"])
        stored = store.get("audit_log_events", cid)
        store.put("audit_log_events", cid, {**stored, "actor": "a", "action": "b:c"})  # naive-join-colliding swap
        v = c.get("/audit_log/verify").json()
        check("I12a the colon-swap forgery is DETECTED (pre-hash makes the join injective)",
              v["valid"] is False and cid in v["detail"], f"got {v}")
        store.put("audit_log_events", cid, stored)
        check("I12b restoring the original record heals the chain", c.get("/audit_log/verify").json()["valid"] is True)

        # I6 — strict input on BOTH fields (authed as the service, so the 422 is the SEMANTIC check, not the auth wall)
        for bad in ({}, {"action": "x"}, {"actor": "x"},                         # missing actor and/or action
                    {"actor": "a", "action": 7}, {"actor": "a", "action": ""}, {"actor": "a", "action": True},
                    {"actor": 7, "action": "a"}, {"actor": "", "action": "a"}, {"actor": True, "action": "a"}):
            check(f"I6 invalid body {bad!r} -> 422",
                  c.post("/audit_log/events", json=bad, headers=SERVICE).status_code == 422)

    # I5 — fork-resistance: two processes append concurrently against the shared DATABASE_PATH. The atomic head
    # claim means sequential DISTINCT ids and a chain that still verifies — never two events on one predecessor.
    if os.getenv("DATABASE_PATH"):
        procs = [subprocess.Popen([sys.executable, "-c", RACE_WORKER], cwd=os.getcwd(),
                                  env={**os.environ, "APP_TEST_SESSIONS": "1", "LOG_LEVEL": "silent"},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for _ in range(2)]
        outs = []
        for p in procs:
            so, se = p.communicate(timeout=120)
            outs.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:120]))
        ids = sorted(int(o) for rc, o in outs if rc == 0 and str(o).isdigit())
        check("I5a two racing appends -> two DISTINCT sequential ids", len(ids) == 2 and ids[1] == ids[0] + 1,
              f"got {outs}")
        with TestClient(app, raise_server_exceptions=False) as c:
            v = c.get("/audit_log/verify").json()
            check("I5b the chain still verifies after the race (no fork)", v["valid"] is True, f"got {v}")
    else:
        print("  [FAIL] I5 cross-process race NOT RUN — DATABASE_PATH unset (the harness must provide it)")
        failures.append("I5 not run")

    # I7 — APPEND is SERVICE-only, the disclosing LIST is ADMIN-only, /verify stays open. A fresh client probes each wall.
    with TestClient(app, raise_server_exceptions=False) as anon:
        # APPEND (service): no token / any user session (non-admin OR admin) is 401 — service auth is binary, no 403
        check("I7a anonymous append -> 401", anon.post("/audit_log/events", json={"action": "anon"}).status_code == 401)
        check("I7b a user session is not a service -> 401",
              anon.post("/audit_log/events", json={"action": "anon"},
                        headers={"Authorization": "Bearer test:alice"}).status_code == 401)
        check("I7c an ADMIN session is still a user, not a service -> 401",
              anon.post("/audit_log/events", json={"action": "anon"}, headers=ADMIN).status_code == 401)
        check("I7d anonymous bad-body append still 401 (auth before validation)",
              anon.post("/audit_log/events", json={"action": 7}).status_code == 401)
        # LIST (admin): discloses every subject's events -> no token 401, a non-admin 403, an admin 200
        check("I7e anonymous list -> 401", anon.get("/audit_log/events").status_code == 401)
        check("I7f non-admin list -> 403",
              anon.get("/audit_log/events", headers={"Authorization": "Bearer test:alice"}).status_code == 403)
        rg = anon.get("/audit_log/events", headers=ADMIN)
        body = rg.json()
        check("I7g admin list -> 200 with the {results, next_cursor} envelope (not a bare array)",
              rg.status_code == 200 and isinstance(body, dict) and "results" in body and "next_cursor" in body,
              f"got {rg.status_code} {body}")
        # /verify: the integrity probe MUST work with NO token (leaks only {valid, count, detail})
        check("I7h anonymous verify stays OPEN -> 200", anon.get("/audit_log/verify").status_code == 200)

        # I8 — BOUNDED LIST: the admin event list is paginated through the shared paginate part.
        full = anon.get("/audit_log/events", headers=ADMIN).json()["results"]   # the whole chain, in id order
        check("I8a there are >= 2 events to page over", len(full) >= 2, f"got {len(full)}")
        # a ?limit=1 page is bounded to ONE row and hands back an opaque forward cursor (more remain)
        p1 = anon.get("/audit_log/events?limit=1", headers=ADMIN).json()
        check("I8b ?limit=1 returns exactly one bounded result + a next_cursor",
              len(p1["results"]) == 1 and p1["results"][0] == full[0] and p1["next_cursor"], f"got {p1}")
        # cursor ROUND-TRIP: feeding next_cursor back returns the NEXT page (the 2nd row), proving the offset codec
        p2 = anon.get(f"/audit_log/events?limit=1&cursor={p1['next_cursor']}", headers=ADMIN).json()
        check("I8c the next_cursor round-trips to the following row", p2["results"][0] == full[1], f"got {p2}")
        # walking the chain one page at a time reconstructs EXACTLY the whole list, in order (no loss, no overlap)
        walked, cursor, guard = [], "", 0
        while True:
            pg = anon.get(f"/audit_log/events?limit=1&cursor={cursor}", headers=ADMIN).json()
            walked += pg["results"]
            cursor = pg["next_cursor"]
            guard += 1
            if not cursor or guard > len(full) + 2:
                break
        check("I8d paging through with the cursor reconstructs the whole chain in order", walked == full, f"got {walked}")
        # a malformed cursor / limit is 422 (the bound is enforced, never silently ignored)
        check("I8e a non-canonical cursor -> 422",
              anon.get("/audit_log/events?cursor=MQ==", headers=ADMIN).status_code == 422)
        check("I8f limit=0 -> 422", anon.get("/audit_log/events?limit=0", headers=ADMIN).status_code == 422)
        check("I8g limit=abc -> 422", anon.get("/audit_log/events?limit=abc", headers=ADMIN).status_code == 422)
        # AUTH PRECEDENCE preserved: a non-admin is 403 BEFORE pagination is even attempted (not 422 on a bad limit)
        check("I8h non-admin is 403 even with a malformed limit (auth before pagination)",
              anon.get("/audit_log/events?limit=0",
                       headers={"Authorization": "Bearer test:alice"}).status_code == 403)

    print(f"AUDIT_LOG INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
