"""RBAC INVARIANTS — access control governed by the AUTHENTICATED identity (the core require_identity seam),
NOT caller-supplied input. Run against the python app (cwd=<app>/python; the app includes auth — rbac `requires`
it). The test seam (APP_TEST_SESSIONS) is enabled HERE so the fixed test admin 'root' is recognized (inert in
prod); production bootstrap is OUT-OF-BAND (operator seeds the store) — proven in I12. Credited by EXIT CODE ONLY.

Proves:  I0 deny-by-default — every route is 401 without a valid bearer token (no / malformed / forged).
         I1 admin-gate (ARBAC) — mutations (/roles, /relations) require an rbac admin: a non-admin caller is 403.
         I2 ESCALATION CLOSED — a non-admin cannot grant THEMSELVES a role; the refusal leaves their access empty.
         I3 caller-scoped /can — the permission decision is about the CALLER's roles only (alice's grant never
            shows up for bob).
         I4 caller-scoped /check — the tuple decision is about the CALLER; (u1,owner,doc1) is true for u1 and
            FALSE for u2 (no enumeration of another subject's tuples).
         I5 admin via ROLE (dogfood) — the bootstrap admin can grant the 'admin' role; that grantee can then
            administer (rbac governs rbac).
         I6 ARBAC separation — the test-seam admin (root) can ADMINISTER but holds no resource permissions itself
            (root can assign yet root /can?delete is false), and an unknown role grants NOTHING (201 allowed:false).
         I7 key-forgery resistance — a relation/object carrying the \x1f delimiter is rejected (422).
         I8 durable — roles + tuples persist in the store seam."""
import os
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # test seam: the fixed test admin 'root' is recognized (inert in prod); real tokens used below
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
        def token_for(u):
            c.post("/auth/register", json={"email": u, "password": f"pw-{u}-1234"})
            return c.post("/auth/login", json={"email": u, "password": f"pw-{u}-1234"}).json()["access_token"]

        def H(t):
            return {"Authorization": f"Bearer {t}"}

        troot, talice, tbob, tu1, tu2 = (token_for(u) for u in ("root", "alice", "bob", "u1", "u2"))

        # I0 — deny-by-default: a valid bearer token is required on every route (bodies/params valid, only auth fails)
        check("I0a POST roles no token -> 401", c.post("/rbac/roles", json={"subject": "alice", "role": "viewer"}).status_code == 401)
        check("I0b GET can no token -> 401", c.get("/rbac/can?permission=read").status_code == 401)
        check("I0c POST relations no token -> 401", c.post("/rbac/relations", json={"subject": "u1", "relation": "owner", "object": "d1"}).status_code == 401)
        check("I0d GET check no token -> 401", c.get("/rbac/check?relation=owner&object=d1").status_code == 401)
        check("I0e forged token -> 401", c.get("/rbac/can?permission=read", headers={"Authorization": "Bearer deadbeef"}).status_code == 401)
        check("I0f malformed scheme -> 401", c.get("/rbac/can?permission=read", headers={"Authorization": troot}).status_code == 401)

        # I1 — admin-gate (ARBAC): root (env-seed) may assign; a non-admin may not
        check("I1a env-seed admin can assign", c.post("/rbac/roles", json={"subject": "alice", "role": "viewer"}, headers=H(troot)).status_code == 201)
        check("I1b non-admin assign -> 403", c.post("/rbac/roles", json={"subject": "bob", "role": "viewer"}, headers=H(tbob)).status_code == 403)
        check("I1c non-admin relation -> 403", c.post("/rbac/relations", json={"subject": "u1", "relation": "owner", "object": "d1"}, headers=H(tu1)).status_code == 403)

        # I2 — ESCALATION CLOSED: alice (a viewer) cannot grant herself admin; her access is unchanged
        esc = c.post("/rbac/roles", json={"subject": "alice", "role": "admin"}, headers=H(talice))
        check("I2a alice self-grant admin -> 403", esc.status_code == 403)
        check("I2b alice still cannot delete (no escalation)", c.get("/rbac/can?permission=delete", headers=H(talice)).json()["allowed"] is False)

        # I3 — caller-scoped /can: alice has viewer (read), bob has nothing; neither sees the other's
        check("I3a alice can read (her viewer role)", c.get("/rbac/can?permission=read", headers=H(talice)).json()["allowed"] is True)
        check("I3b alice cannot write (viewer only)", c.get("/rbac/can?permission=write", headers=H(talice)).json()["allowed"] is False)
        check("I3c bob (no roles) cannot read — alice's grant is not bob's", c.get("/rbac/can?permission=read", headers=H(tbob)).json()["allowed"] is False)

        # I4 — caller-scoped /check: the tuple (u1, owner, doc1) is u1's, invisible to u2
        c.post("/rbac/relations", json={"subject": "u1", "relation": "owner", "object": "doc1"}, headers=H(troot))
        check("I4a u1 sees its own tuple", c.get("/rbac/check?relation=owner&object=doc1", headers=H(tu1)).json()["allowed"] is True)
        check("I4b u2 does NOT see u1's tuple (caller-scoped, no enumeration)", c.get("/rbac/check?relation=owner&object=doc1", headers=H(tu2)).json()["allowed"] is False)
        check("I4c wrong object -> false", c.get("/rbac/check?relation=owner&object=doc2", headers=H(tu1)).json()["allowed"] is False)
        check("I4d wrong relation -> false", c.get("/rbac/check?relation=editor&object=doc1", headers=H(tu1)).json()["allowed"] is False)

        # I5 — admin via ROLE (dogfood): root grants bob the 'admin' role; bob can now administer
        check("I5a root grants bob admin role", c.post("/rbac/roles", json={"subject": "bob", "role": "admin"}, headers=H(troot)).status_code == 201)
        check("I5b bob (now admin by role) can assign", c.post("/rbac/roles", json={"subject": "alice", "role": "editor"}, headers=H(tbob)).status_code == 201)
        check("I5c the grant landed: alice can now write", c.get("/rbac/can?permission=write", headers=H(talice)).json()["allowed"] is True)

        # I6 — ARBAC separation + unknown role: root ADMINISTERS but holds no resource perms; unknown role grants nothing
        check("I6a the test-seam bootstrap admin has admin CAPABILITY but no resource role (root /can delete is false)",
              c.get("/rbac/can?permission=delete", headers=H(troot)).json()["allowed"] is False)
        unk = c.post("/rbac/roles", json={"subject": "mallory", "role": "superuser"}, headers=H(troot))
        check("I6b unknown role -> 201 allowed:false (loud deny, admin caller)", unk.status_code == 201 and unk.json()["allowed"] is False)
        check("I6c the unknown role granted NOTHING", c.get("/rbac/can?permission=read", headers=H(token_for("mallory"))).json()["allowed"] is False)

        # I7 — key-forgery resistance: a relation/object carrying the unit separator is rejected
        check("I7a forged relation (%1F -> \\x1f) -> 422", c.get("/rbac/check?relation=p%1Fq&object=s", headers=H(tu1)).status_code == 422)
        check("I7b forged object in a grant -> 422", c.post("/rbac/relations", json={"subject": "u1", "relation": "owner", "object": "a\x1fb"}, headers=H(troot)).status_code == 422)

        # I8 — durable seam: roles + tuples are stored
        check("I8a roles persisted", "viewer" in (store.get("rbac_roles", "alice") or []))
        check("I8b tuple persisted under the exact composite key (self-describing value)",
              store.get("rbac_rel", "u1\x1fowner\x1fdoc1") == {"subject": "u1", "relation": "owner", "object": "doc1"})

        # I9 — REVOCATION: revoke removes access; idempotent; admin-gated; deny-by-default. (alice has editor from I5b.)
        rev = c.request("DELETE", "/rbac/roles", json={"subject": "alice", "role": "editor"}, headers=H(troot))
        check("I9a revoke role -> 200 removed:true", rev.status_code == 200 and rev.json()["removed"] is True)
        check("I9b after revoke, alice can no longer write", c.get("/rbac/can?permission=write", headers=H(talice)).json()["allowed"] is False)
        check("I9c alice keeps her other role (viewer -> read still allowed)", c.get("/rbac/can?permission=read", headers=H(talice)).json()["allowed"] is True)
        again = c.request("DELETE", "/rbac/roles", json={"subject": "alice", "role": "editor"}, headers=H(troot))
        check("I9d revoke again -> 200 removed:false (idempotent)", again.status_code == 200 and again.json()["removed"] is False)
        c.post("/rbac/relations", json={"subject": "u1", "relation": "owner", "object": "docZ"}, headers=H(troot))
        rr = c.request("DELETE", "/rbac/relations", json={"subject": "u1", "relation": "owner", "object": "docZ"}, headers=H(troot))
        check("I9e revoke tuple -> removed:true", rr.json()["removed"] is True)
        check("I9f after revoke, check denies", c.get("/rbac/check?relation=owner&object=docZ", headers=H(tu1)).json()["allowed"] is False)
        check("I9g revoke tuple again -> removed:false (idempotent)",
              c.request("DELETE", "/rbac/relations", json={"subject": "u1", "relation": "owner", "object": "docZ"}, headers=H(troot)).json()["removed"] is False)
        check("I9h non-admin revoke -> 403", c.request("DELETE", "/rbac/roles", json={"subject": "alice", "role": "viewer"}, headers=H(talice)).status_code == 403)
        check("I9i no-token revoke -> 401", c.request("DELETE", "/rbac/roles", json={"subject": "alice", "role": "viewer"}).status_code == 401)
        check("I9j revoke is durable (editor gone from the store seam)", "editor" not in (store.get("rbac_roles", "alice") or []))

        # I10 — LISTING + pagination. carol gets 2 (non-admin) roles so she is NOT an rbac admin.
        for role in ("viewer", "editor"):
            c.post("/rbac/roles", json={"subject": "carol", "role": role}, headers=H(troot))
        tcarol = token_for("carol")
        check("I10a caller lists own roles", c.get("/rbac/roles", headers=H(tcarol)).json()["results"] == ["viewer", "editor"])
        check("I10b admin lists another's roles", c.get("/rbac/roles?subject=carol", headers=H(troot)).json()["results"] == ["viewer", "editor"])
        check("I10c non-admin listing another -> 403", c.get("/rbac/roles?subject=carol", headers=H(talice)).status_code == 403)
        check("I10d listing no token -> 401", c.get("/rbac/roles?subject=carol").status_code == 401)
        p1 = c.get("/rbac/roles?subject=carol&limit=1", headers=H(troot)).json()
        check("I10e page 1 bounded to limit + has a cursor", p1["results"] == ["viewer"] and bool(p1["next_cursor"]))
        p2 = c.get(f"/rbac/roles?subject=carol&limit=1&cursor={p1['next_cursor']}", headers=H(troot)).json()
        check("I10f cursor round-trips to the next page", p2["results"] == ["editor"] and p2["next_cursor"] is None)
        check("I10g bad cursor -> 422", c.get("/rbac/roles?subject=carol&cursor=MDU", headers=H(troot)).status_code == 422)
        check("I10h limit < 1 -> 422", c.get("/rbac/roles?subject=carol&limit=0", headers=H(troot)).status_code == 422)
        check("I10i limit clamps to max (bounded, not an error)", c.get("/rbac/roles?subject=carol&limit=9999", headers=H(troot)).status_code == 200)
        c.post("/rbac/relations", json={"subject": "carol", "relation": "owner", "object": "docA"}, headers=H(troot))
        c.post("/rbac/relations", json={"subject": "carol", "relation": "viewer", "object": "docB"}, headers=H(troot))
        fwd = c.get("/rbac/relations?subject=carol", headers=H(tcarol)).json()
        check("I10j caller lists own forward tuples",
              {(t["relation"], t["object"]) for t in fwd["results"]} == {("owner", "docA"), ("viewer", "docB")})
        check("I10k admin inverse lookup (who can access docA)",
              [t["subject"] for t in c.get("/rbac/relations?object=docA", headers=H(troot)).json()["results"]] == ["carol"])
        check("I10l non-admin inverse -> 403", c.get("/rbac/relations?object=docA", headers=H(tcarol)).status_code == 403)
        check("I10m unfiltered list -> 422 (no full dump)", c.get("/rbac/relations", headers=H(troot)).status_code == 422)

        # I11 — DECISION-AUDIT (Path 2, domain-local). Modes via APP_RBAC_AUDIT; the log is admin-only.
        teve = token_for("eve")                                    # a non-admin with no roles
        os.environ["APP_RBAC_AUDIT"] = "deny"
        c.get("/rbac/can?permission=delete", headers=H(teve))      # eve has nothing -> deny -> logged
        evelog = c.get("/rbac/decisions?subject=eve", headers=H(troot)).json()["results"]
        check("I11a a denied decision is recorded (deny mode)",
              any(d["result"] == "deny" and d["action"] == "delete" and d["kind"] == "can" for d in evelog))
        check("I11b the record carries the security fields",
              bool(evelog) and all(k in evelog[0] for k in ("id", "subject", "kind", "action", "object", "result", "reason", "ts")))
        before = len(c.get("/rbac/decisions?subject=carol", headers=H(troot)).json()["results"])
        c.get("/rbac/can?permission=read", headers=H(tcarol))      # carol viewer -> allow -> NOT logged in deny mode
        after = len(c.get("/rbac/decisions?subject=carol", headers=H(troot)).json()["results"])
        check("I11c an allow is NOT logged in deny mode", after == before)
        os.environ["APP_RBAC_AUDIT"] = "all"
        c.get("/rbac/can?permission=read", headers=H(tcarol))      # allow -> logged in all mode
        check("I11d an allow IS logged in all mode",
              any(d["result"] == "allow" and d["action"] == "read"
                  for d in c.get("/rbac/decisions?subject=carol", headers=H(troot)).json()["results"]))
        os.environ["APP_RBAC_AUDIT"] = "off"
        b2 = len(c.get("/rbac/decisions?subject=eve", headers=H(troot)).json()["results"])
        c.get("/rbac/can?permission=write", headers=H(teve))       # deny, but audit off -> nothing recorded
        check("I11e off mode records nothing",
              len(c.get("/rbac/decisions?subject=eve", headers=H(troot)).json()["results"]) == b2)
        os.environ["APP_RBAC_AUDIT"] = "deny"
        check("I11f the decision log is admin-only (non-admin -> 403)", c.get("/rbac/decisions", headers=H(tcarol)).status_code == 403)
        check("I11g decision log no token -> 401", c.get("/rbac/decisions").status_code == 401)
        os.environ["APP_RBAC_AUDIT"] = "DENY"   # a typo (wrong case) must fail SAFE to deny, not open to "all"
        bct = len(c.get("/rbac/decisions?subject=carol", headers=H(troot)).json()["results"])
        c.get("/rbac/can?permission=read", headers=H(tcarol))   # an ALLOW under the garbage mode
        check("I11h garbage/typo audit mode fails SAFE to deny (the allow is NOT logged)",
              len(c.get("/rbac/decisions?subject=carol", headers=H(troot)).json()["results"]) == bct)
        os.environ["APP_RBAC_AUDIT"] = "deny"

        # I12 — ESCALATION REGRESSION (closed): in PRODUCTION (no test seam) there is NO claimable-name admin;
        # the ONLY bootstrap is OUT-OF-BAND (operator seeds the store). Deny-by-default is the point.
        os.environ.pop("APP_TEST_SESSIONS", None)            # simulate production: test seam OFF
        tprod = token_for("prod_user")                       # a real registered user, real token (login needs no seam)
        check("I12a prod: a fresh authenticated user is NOT admin (no env-name seed to claim)",
              c.post("/rbac/roles", json={"subject": "x", "role": "viewer"}, headers=H(tprod)).status_code == 403)
        check("I12b prod: even registering the old seed name 'root' grants nothing",
              c.post("/rbac/roles", json={"subject": "x", "role": "viewer"}, headers=H(token_for("root2"))).status_code == 403)
        store.do("rbac_roles", "prod_user", lambda cur: ((cur or []) + ["admin"], None))   # OUT-OF-BAND operator seed
        check("I12c out-of-band store seed is the supported prod bootstrap (now prod_user can administer)",
              c.post("/rbac/roles", json={"subject": "y", "role": "viewer"}, headers=H(tprod)).status_code == 201)
        os.environ["APP_TEST_SESSIONS"] = "1"                # restore the test seam

        # I13 — MUTATION AUDIT: a DENIED mutation attempt is the ASVS L2 "log failures" MUST; a successful
        # grant is the admin-event trail (surfaced in "all" mode). (alice is a non-admin viewer from earlier.)
        os.environ["APP_RBAC_AUDIT"] = "deny"
        c.post("/rbac/roles", json={"subject": "z", "role": "viewer"}, headers=H(talice))   # non-admin -> 403
        alog = c.get("/rbac/decisions?subject=alice", headers=H(troot)).json()["results"]
        check("I13a a DENIED mutation attempt is recorded (deny mode, ASVS L2)",
              any(d["kind"] == "assign" and d["result"] == "deny" and d["reason"] == "not-admin" for d in alog))
        os.environ["APP_RBAC_AUDIT"] = "all"
        c.post("/rbac/roles", json={"subject": "auditgrantee", "role": "editor"}, headers=H(troot))   # admin grant
        glog = c.get("/rbac/decisions?subject=root", headers=H(troot)).json()["results"]
        check("I13b a successful grant is recorded in all mode (who granted what to whom)",
              any(d["kind"] == "assign" and d["result"] == "grant" and d["action"] == "editor" and d["object"] == "auditgrantee" for d in glog))
        os.environ["APP_RBAC_AUDIT"] = "deny"

        # I14 — precedence authn -> authz -> validation (the conformance suite proves this identical ×3):
        check("I14a non-admin + bad body -> 403 (authz BEFORE validation, not 422)",
              c.post("/rbac/roles", json={"subject": "x"}, headers=H(talice)).status_code == 403)
        check("I14b no token + bad body -> 401 (authn first, not 422)",
              c.post("/rbac/roles", json={}).status_code == 401)

    print(f"RBAC INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
