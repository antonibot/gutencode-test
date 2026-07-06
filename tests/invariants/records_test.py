"""RECORDS INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the python app
(cwd = <app>/python). Credited by EXIT CODE ONLY.

The named property: a record is reachable ONLY by its owner, and ONLY its declared fields are ever writable.
Tokens use the core test-session seam ('test:<subject>') under APP_TEST_SESSIONS=1 (inert in production), exactly as
the manifest tests do. The id is the response's derived id (no recomputation in the probe — we test the SHIPPED path).

Proves:  I0 deny-by-default — create/list/get/update/delete are 401 without a valid bearer token.
         I-OWN — a record is reachable ONLY by its owner: bob's get/update/delete of alice's id is 404 (never 403,
            never 200), byte-identical to a missing id; alice's record is UNTOUCHED by bob's failed attempts.
         I-MASS — NO mass-assignment: a smuggled owner/id/type (top-level, inside fields, OR a case-variant
            Owner/OWNER, OR a nested object) has NO effect — the stored owner is the token's, the id is derived, and
            the stored fields hold ONLY the declared keys (allowlist-read proves it by construction).
         I-PATCH-IMMUT — update never re-homes a record: owner/id/created_at are unchanged by a PATCH that tries to set them.
         I-SCHEMA — typed validation: a wrong-typed field is 422 + the field set is allow-listed (an undeclared key is
            stripped, not stored); a select outside its options, a non-ISO datetime, and an over-2^53 number are 422.
         I-ONCE — exactly-once create: a repeat key returns the SAME record (same id, same fields — the first write
            wins; the second's fields are ignored), and the store holds exactly ONE row for that (owner, key).
         I-DEL-PATCH — no resurrection: after a delete, get/update/re-delete of that id are all 404.
         I-WELLFORMED — the key is a well-formed identifier: a control character (the \\x1f composite separator) is 422.
         I-LIST — the owner-scoped list is a SEMANTIC cross-owner proof: two owners each see ONLY their own rows
            (walked cursor-to-exhaustion), a stranger gets an empty page (never 403), the envelope is bounded.
         I-ORG — the OPTIONAL ?org=<slug> selector shares a record across an org's members (the INVERSE of I-OWN's
            per-subject isolation): an org record is created org-owned (owner==slug, scope=="org") by an active member;
            TWO DISTINCT members both read it (200); an outsider is 404 byte-identical to a missing org record (existence
            never leaks); an outsider CANNOT create (404, no row minted); the org owner is server-set from the verified
            selector, never a client body field; and the USER path (no ?org=) is wholly UNAFFECTED (no scope key, its own
            partition). Membership is resolved via the core org_role seam (the transfer-demotion recipe gives 2 active
            members without the accept-token flow) — records imports NOTHING from orgs.
(The FORCED concurrent interleavings — two creates racing the same key, two PATCHes racing one record — need a
cross-process barrier harness; this suite proves the atomic-seam contract they rest on.)"""
import os
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # the 'test:' bearer resolves only under this seam (inert in production)
os.environ["APP_TEST_CLOCK"] = "1"      # ?now= honored, so created_at is deterministic

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402
from app_pkg.core import store  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def H(subject):
    return {"Authorization": f"Bearer test:{subject}"}


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        # I0 — deny-by-default on every route
        check("I0a create no token -> 401", c.post("/records", json={"key": "k", "fields": {"title": "x"}}).status_code == 401)
        check("I0b list no token -> 401", c.get("/records").status_code == 401)
        check("I0c get no token -> 401", c.get("/records/anyid").status_code == 401)
        check("I0d update no token -> 401", c.patch("/records/anyid", json={"fields": {}}).status_code == 401)
        check("I0e delete no token -> 401", c.delete("/records/anyid").status_code == 401)
        check("I0f forged token -> 401", c.get("/records", headers={"Authorization": "Bearer deadbeef"}).status_code == 401)
        check("I0g malformed scheme -> 401", c.get("/records", headers={"Authorization": "test:alice"}).status_code == 401)

        a = c.post("/records?now=1700000000", json={"key": "doc-1", "fields": {"title": "alpha", "count": 2}}, headers=H("alice")).json()
        aid = a["id"]

        # I-OWN — only the owner reaches the record; bob is 404 everywhere; alice's row is untouched
        miss = c.get("/records/deadbeefdeadbeef", headers=H("bob"))
        x_get = c.get(f"/records/{aid}", headers=H("bob"))
        x_patch = c.patch(f"/records/{aid}", json={"fields": {"count": 99}}, headers=H("bob"))
        x_del = c.delete(f"/records/{aid}", headers=H("bob"))
        check("I-OWN a cross-owner GET is 404 (never 403/200)", x_get.status_code == 404)
        check("I-OWN b cross-owner PATCH is 404", x_patch.status_code == 404)
        check("I-OWN c cross-owner DELETE is 404", x_del.status_code == 404)
        check("I-OWN d cross-owner 404 == missing 404 (existence does not leak)", x_get.json() == miss.json())
        check("I-OWN e the 404 body never carries alice's record (title/owner absent)",
              b"alpha" not in x_get.content and b"alice" not in x_get.content)
        owned = c.get(f"/records/{aid}", headers=H("alice")).json()
        check("I-OWN f alice's record is UNTOUCHED after bob's failed writes (count still 2)",
              owned["fields"] == {"title": "alpha", "count": 2})

        # I-MASS — a smuggled owner/id/type cannot win; the stored fields are allow-listed
        m = c.post("/records?now=1700000000",
                   json={"key": "mass", "fields": {"title": "x", "owner": "bob", "id": "forged", "Owner": "bob", "OWNER": "bob", "nested": {"x": 1}},
                         "owner": "bob", "id": "forged", "type": "evil"},
                   headers=H("alice"))
        mj = m.json()
        check("I-MASS a create succeeds, owner is the TOKEN's (alice), not the smuggled body owner", m.status_code == 201 and mj["owner"] == "alice")
        rec = store.get("records_rows", f"alice\x1f{mj['id']}")
        check("I-MASS b the STORE record's owner is alice", rec is not None and rec["owner"] == "alice")
        check("I-MASS c the stored fields hold ONLY the declared 'title' (owner/id/case-variants/nested STRIPPED)",
              rec["fields"] == {"title": "x"}, f"got {rec['fields']}")
        check("I-MASS d bob cannot read the smuggled-owner record", c.get(f"/records/{mj['id']}", headers=H("bob")).status_code == 404)

        # I-PATCH-IMMUT — owner/id/created_at survive a hostile PATCH
        before = c.get(f"/records/{aid}", headers=H("alice")).json()
        p = c.patch(f"/records/{aid}?now=1700009999",
                    json={"fields": {"count": 7}, "owner": "bob", "id": "forged", "created_at": 0}, headers=H("alice")).json()
        check("I-PATCH-IMMUT a owner unchanged", p["owner"] == "alice")
        check("I-PATCH-IMMUT b id unchanged", p["id"] == aid)
        check("I-PATCH-IMMUT c created_at unchanged", p["created_at"] == before["created_at"])
        check("I-PATCH-IMMUT d updated_at advanced + count merged (title preserved)",
              p["updated_at"] == 1700009999 and p["fields"] == {"title": "alpha", "count": 7})

        # I-SCHEMA — typed validation + allow-list strip
        check("I-SCHEMA a number 'NaN' (string) -> 422", c.post("/records", json={"key": "s1", "fields": {"title": "x", "count": "NaN"}}, headers=H("alice")).status_code == 422)
        check("I-SCHEMA b required title missing -> 422", c.post("/records", json={"key": "s2", "fields": {"count": 1}}, headers=H("alice")).status_code == 422)
        check("I-SCHEMA c select outside options -> 422", c.post("/records", json={"key": "s3", "fields": {"title": "x", "status": "nope"}}, headers=H("alice")).status_code == 422)
        check("I-SCHEMA d non-ISO datetime -> 422", c.post("/records", json={"key": "s4", "fields": {"title": "x", "due": "yesterday"}}, headers=H("alice")).status_code == 422)
        check("I-SCHEMA e boolean from a string -> 422", c.post("/records", json={"key": "s5", "fields": {"title": "x", "done": "true"}}, headers=H("alice")).status_code == 422)
        check("I-SCHEMA f integer beyond 2^53 -> 422", c.post("/records", json={"key": "s6", "fields": {"title": "x", "count": 9007199254740993}}, headers=H("alice")).status_code == 422)
        ok = c.post("/records?now=1700000000", json={"key": "s7", "fields": {"title": "x", "extra": "drop", "count": 4}}, headers=H("alice")).json()
        check("I-SCHEMA g an undeclared field is STRIPPED, not rejected", ok["fields"] == {"title": "x", "count": 4})
        check("I-SCHEMA h all valid types accepted",
              c.post("/records?now=1700000000", json={"key": "s8", "fields": {"title": "t", "count": 3, "done": True, "due": "2126-06-28T10:30:00Z", "status": "closed", "meta": {"a": 1}}}, headers=H("alice")).status_code == 201)

        # I-JSON — the opaque json field is ×3-SAFE (Pillar-1 found a HIGH: a lone surrogate crashed python + poisoned
        # the list). A lone surrogate must be sent as a RAW body (json.dumps cannot encode it) — exactly how a
        # malformed client payload arrives on the wire.
        raw = '{"key": "js1", "fields": {"title": "ok", "meta": {"note": "a\\ud800b"}}}'
        sj = c.post("/records?now=1700000000", content=raw, headers={**H("alice"), "content-type": "application/json"})
        check("I-JSON a a lone surrogate in a json value -> 201, NOT a 5xx", sj.status_code == 201, f"got {sj.status_code}")
        check("I-JSON b the surrogate is normalized to U+FFFD in the stored+returned value",
              sj.status_code == 201 and sj.json()["fields"]["meta"]["note"] == "a�b")
        check("I-JSON c the owner's LIST is NOT poisoned (still 200 after a surrogate write)",
              c.get("/records", headers=H("alice")).status_code == 200)
        check("I-JSON d an integer >2^53 anywhere in a json value -> 422 (no silent ×3 precision drift)",
              c.post("/records", json={"key": "js2", "fields": {"title": "x", "meta": {"n": 9007199254740993}}}, headers=H("alice")).status_code == 422)

        # I-DATE — the `date` type (distinct from datetime) is exercised end-to-end: strict ISO format + ranges
        check("I-DATE a a valid date -> 201",
              c.post("/records?now=1700000000", json={"key": "dt1", "fields": {"title": "x", "day": "2126-03-15"}}, headers=H("alice")).status_code == 201)
        check("I-DATE b a bad-range date -> 422",
              c.post("/records", json={"key": "dt2", "fields": {"title": "x", "day": "2126-13-45"}}, headers=H("alice")).status_code == 422)
        check("I-DATE c a non-ISO date -> 422",
              c.post("/records", json={"key": "dt3", "fields": {"title": "x", "day": "15/03/2126"}}, headers=H("alice")).status_code == 422)

        # I-ONCE — exactly-once create: a repeat key returns the SAME record; the second's fields are ignored
        o1 = c.post("/records?now=1700000000", json={"key": "once", "fields": {"title": "first"}}, headers=H("alice")).json()
        o2 = c.post("/records?now=1700000050", json={"key": "once", "fields": {"title": "SECOND", "count": 9}}, headers=H("alice")).json()
        check("I-ONCE a a repeat key returns the SAME id", o1["id"] == o2["id"])
        check("I-ONCE b the first write WINS (the second's fields are ignored)", o2["fields"] == {"title": "first"} and o2["created_at"] == o1["created_at"])
        mine = [r for r in store.values("records_rows") if r["owner"] == "alice" and r["id"] == o1["id"]]
        check("I-ONCE c the store holds exactly ONE row for that key", len(mine) == 1)

        # I-DEL-PATCH — no resurrection after delete
        d = c.post("/records?now=1700000000", json={"key": "del", "fields": {"title": "bye"}}, headers=H("alice")).json()
        did = d["id"]
        check("I-DEL-PATCH a delete -> 204", c.delete(f"/records/{did}", headers=H("alice")).status_code == 204)
        check("I-DEL-PATCH b get after delete -> 404", c.get(f"/records/{did}", headers=H("alice")).status_code == 404)
        check("I-DEL-PATCH c PATCH after delete -> 404 (no resurrection)", c.patch(f"/records/{did}", json={"fields": {"title": "back"}}, headers=H("alice")).status_code == 404)
        check("I-DEL-PATCH d re-delete -> 404 (idempotent)", c.delete(f"/records/{did}", headers=H("alice")).status_code == 404)

        # I-WELLFORMED — the key cannot carry the composite separator / control chars
        check("I-WELLFORMED a a \\x1f in the key -> 422", c.post("/records", json={"key": "a\x1fb", "fields": {"title": "x"}}, headers=H("alice")).status_code == 422)
        check("I-WELLFORMED b an empty key -> 422", c.post("/records", json={"key": "", "fields": {"title": "x"}}, headers=H("alice")).status_code == 422)

        # I-LIST — owner-scoped list, a SEMANTIC cross-owner proof (the correctness backstop)
        def list_all(subject):
            out, cursor, guard = [], "", 0
            while True:
                pg = c.get(f"/records?limit=1&cursor={cursor}", headers=H(subject)).json()
                out += pg["results"]
                cursor = pg["next_cursor"]
                guard += 1
                if not cursor or guard > 100:
                    break
            return out

        c.post("/records?now=1700000000", json={"key": "bobdoc", "fields": {"title": "bobs"}}, headers=H("bob"))
        a_list, b_list = list_all("alice"), list_all("bob")
        a_owners = {r["owner"] for r in a_list}
        b_owners = {r["owner"] for r in b_list}
        check("I-LIST a alice's list holds ONLY alice's rows", a_owners == {"alice"} and len(a_list) > 0, f"got {a_owners}")
        check("I-LIST b bob's list holds ONLY bob's rows (alice's never leak)", b_owners == {"bob"} and len(b_list) > 0, f"got {b_owners}")
        check("I-LIST c a caller with no rows gets an empty page, never 403",
              c.get("/records", headers=H("zelda")).json() == {"results": [], "next_cursor": None})
        check("I-LIST d anonymous list -> 401", c.get("/records").status_code == 401)
        check("I-LIST e the list is the bounded {results, next_cursor} envelope, never a bare array",
              isinstance(c.get("/records", headers=H("alice")).json().get("results"), list))

        # I-ORG — the OPTIONAL ?org=<slug> selector shares a record across an org's ACTIVE members (the INVERSE of
        # I-OWN). Set up 2 active members WITHOUT the accept-token flow via the transfer-demotion recipe (as the manifest
        # does): alice creates recshare, transfers to bob -> bob=owner, alice=active admin. records reaches membership
        # ONLY through the core org_role seam; it imports nothing from orgs.
        c.post("/orgs", json={"slug": "recshare"}, headers=H("alice"))
        tr = c.post("/orgs/recshare/transfer", json={"owner": "bob"}, headers=H("alice"))
        check("I-ORG setup transfer demotes alice to an ACTIVE admin (2 members: bob=owner, alice=admin)",
              tr.status_code == 200 and tr.json().get("owner") == "bob")

        # I-ORG a — an org create by an active member is ORG-OWNED (owner==slug, scope=='org'); the store row confirms it
        oc = c.post("/records?org=recshare&now=1700000000", json={"key": "deal-1", "fields": {"title": "lead"}}, headers=H("alice"))
        ocj = oc.json()
        oid = ocj.get("id")
        check("I-ORG a create -> 201, owner is the ORG slug (not the caller), scope=='org'",
              oc.status_code == 201 and ocj["owner"] == "recshare" and ocj.get("scope") == "org")
        stored = store.get("records_org_rows", f"recshare\x1f{oid}")
        check("I-ORG a2 the STORE row is in the org partition with owner==recshare",
              stored is not None and stored["owner"] == "recshare")

        # I-ORG b — CROSS-MEMBER VISIBILITY: two DISTINCT members both read the SAME org record (200)
        g_alice = c.get(f"/records/{oid}?org=recshare", headers=H("alice"))
        g_bob = c.get(f"/records/{oid}?org=recshare", headers=H("bob"))
        check("I-ORG b member 1 (alice) reads the org record -> 200", g_alice.status_code == 200 and g_alice.json()["owner"] == "recshare")
        check("I-ORG b2 member 2 (bob) reads the SAME org record -> 200 (>=2 distinct members)", g_bob.status_code == 200 and g_bob.json()["owner"] == "recshare")

        # I-ORG c — OUTSIDER ISOLATION: carol (non-member) is 404, byte-identical to a missing org rid (existence never leaks)
        g_carol = c.get(f"/records/{oid}?org=recshare", headers=H("carol"))
        miss_org = c.get("/records/deadbeefdeadbeef?org=recshare", headers=H("carol"))
        check("I-ORG c an outsider GET is 404 (never 200/403)", g_carol.status_code == 404)
        check("I-ORG c2 outsider 404 == missing-rid 404 (existence does not leak: cannot even confirm the org)",
              g_carol.json() == miss_org.json())
        check("I-ORG c3 the outsider 404 body never carries the org record (title/owner absent)",
              b"lead" not in g_carol.content and b"recshare" not in g_carol.content)

        # I-ORG d — NON-MEMBER CREATE REFUSED: carol cannot mint an org record; the store gains no row
        before = len([r for r in store.values("records_org_rows") if r.get("owner") == "recshare"])
        dc = c.post("/records?org=recshare", json={"key": "carol-attempt", "fields": {"title": "x"}}, headers=H("carol"))
        after = len([r for r in store.values("records_org_rows") if r.get("owner") == "recshare"])
        check("I-ORG d a non-member create is 404 (not 201/403)", dc.status_code == 404)
        check("I-ORG d2 the store gained NO row for the refused create", after == before)

        # I-ORG e — OWNER UN-FORGEABLE: a smuggled body owner is discarded; the server sets owner from the verified slug
        se = c.post("/records?org=recshare&now=1700000000", json={"key": "deal-2", "fields": {"title": "lead2"}, "owner": "bob", "id": "forged"}, headers=H("bob"))
        sej = se.json()
        check("I-ORG e a smuggled body owner is IGNORED — response owner is the org slug", se.status_code == 201 and sej["owner"] == "recshare")
        stored_e = store.get("records_org_rows", f"recshare\x1f{sej['id']}")
        check("I-ORG e2 the STORE row's owner is recshare (never the smuggled 'bob')", stored_e is not None and stored_e["owner"] == "recshare")

        # I-ORG f — USER PATH INERT: a plain user record (no ?org=) is created/read/listed exactly as before; an org
        # write never touches it; the user view carries NO scope key and lives in its own partition.
        ur = c.post("/records?now=1700000000", json={"key": "inert-user-1", "fields": {"title": "mine"}}, headers=H("alice"))
        urj = ur.json()
        check("I-ORG f a user record is unchanged: 201, owner==caller, NO scope key",
              ur.status_code == 201 and urj["owner"] == "alice" and "scope" not in urj)
        ug = c.get(f"/records/{urj['id']}", headers=H("alice"))
        check("I-ORG f2 the user record reads on the user path (no ?org=) -> 200, still no scope",
              ug.status_code == 200 and "scope" not in ug.json())
        u_list = list_all("alice")
        check("I-ORG f3 the user LIST (walked to exhaustion) holds ONLY alice's user rows, none carry scope",
              all(r["owner"] == "alice" and "scope" not in r for r in u_list) and any(r["id"] == urj["id"] for r in u_list))
        check("I-ORG f4 the user record is NOT in the org partition (the partitions are disjoint)",
              store.get("records_org_rows", f"alice\x1f{urj['id']}") is None)

    print(f"RECORDS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
