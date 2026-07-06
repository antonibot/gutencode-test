"""TEAMS INVARIANTS — teams authorized AGAINST ORG MEMBERSHIP via the core org_role seam (the authz subject is
the bearer token, the scope is the team's org), NOT caller-supplied input. Run against the python app (cwd=<app>/
python; the app includes auth + orgs — teams `requires` them). The test seam (APP_TEST_SESSIONS) resolves a
'test:<handle>' token to <handle> (inert in prod). Credited by EXIT CODE ONLY.

Proves:  I0 deny-by-default — every mutation is 401 without a valid bearer token.
         I1 ORG-SCOPED CREATE — only an owner|admin of the org may create a team under it; a non-member is 403;
            creating under a non-existent org is 403 (no membership).
         I2 ORG-SCOPED MEMBER MANAGEMENT — only the team's-org owner|admin may add/remove members; a non-member of
            that org is 403.
         I3 CROSS-ORG ISOLATION — an owner|admin of org A cannot manage org B's teams (403).
         I4 SET membership — a handle appears AT MOST ONCE; re-adding UPDATES the role in place (upsert).
         I5 deterministic order — the member list is always sorted by handle regardless of insertion order.
         I6 org binding immutable — the org set at creation is unchanged by any membership op.
         I7 idempotent removal — removing twice / removing a non-member is a stable 200.
         I8 AUTHZ BEFORE VALIDATION — a non-member with an otherwise-invalid body is 403 (not 422); no-token is 401.
         I9 honest 404s + strict input. I10 durable — teams persist in the store seam.
         I11 READ-SCOPING — the read is org-membership-gated: ANY member role of the team's org can
            read the team (200), a NON-member is 404 (not-yours == not-found, never 403 — an enumerable id leaks no
            existence across orgs), and no token is 401 (authn before the not-found). Cross-org: an owner of org B
            cannot read org A's team, and an admin of org A cannot read org B's team (both 404)."""
import os
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # the 'test:<handle>' token resolves to <handle> (inert in prod)
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.core import store  # noqa: E402  (to drain the orgs invite outbox — membership is pending-until-accepted)
from app_pkg.app import app  # noqa: E402

failures = []


def accept_org(c, slug, handle):
    # orgs membership is PENDING until the invitee ACCEPTs the single-use token the invite delivered to orgs_outbox
    # (the "email worker"). teams authorizes against ACTIVE org membership, so an invited manager must accept first.
    rec = store.get("orgs_outbox", f"{slug}\x1f{handle}")   # \x1f-joined, parity with orgs _deliver_invite
    return c.post(f"/orgs/{slug}/members/accept", json={"token": rec["token"]},
                  headers={"Authorization": f"Bearer test:{handle}"}) if rec else None


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def H(handle):
    return {"Authorization": f"Bearer test:{handle}"}


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        # set up org membership through the orgs surface: alice owns acme, bob is an acme admin, carol is a non-member.
        # (orgs membership is PENDING until accepted — bob must accept the invite to become an ACTIVE admin teams trusts.)
        c.post("/orgs", json={"slug": "acme"}, headers=H("alice"))            # alice = owner of acme
        c.post("/orgs/acme/members", json={"handle": "bob", "role": "admin"}, headers=H("alice"))  # bob = INVITED admin
        _bob_accept = accept_org(c, "acme", "bob")
        check("setup: bob accepts the acme admin invite -> ACTIVE", _bob_accept is not None and _bob_accept.status_code == 200)
        # a SECOND org for cross-org isolation: dave owns globex (and is NOT in acme)
        c.post("/orgs", json={"slug": "globex"}, headers=H("dave"))           # dave = owner of globex

        # I0 — deny-by-default (clean bodies so the failure is purely auth, identical ×3)
        check("I0a create no token -> 401", c.post("/teams", json={"org": "acme", "name": "t"}).status_code == 401)
        # (member-route no-token checks need a team; created below in I1, re-checked in I2)

        # I1 — org-scoped create
        owner_team = c.post("/teams", json={"org": "acme", "name": "platform"}, headers=H("alice"))
        check("I1a an org OWNER can create a team under it", owner_team.status_code == 201)
        admin_team = c.post("/teams", json={"org": "acme", "name": "growth"}, headers=H("bob"))
        check("I1b an org ADMIN can create a team under it", admin_team.status_code == 201)
        check("I1c a NON-member cannot create a team under the org (-> 403)",
              c.post("/teams", json={"org": "acme", "name": "x"}, headers=H("carol")).status_code == 403)
        check("I1d creating under a NON-EXISTENT org is 403 (no membership)",
              c.post("/teams", json={"org": "ghostorg", "name": "x"}, headers=H("alice")).status_code == 403)
        tid = owner_team.json()["id"]

        # I0 (member routes, now that a team exists) — no token -> 401
        check("I0b add-member no token -> 401", c.post(f"/teams/{tid}/members", json={"handle": "x", "role": "member"}).status_code == 401)
        check("I0c remove-member no token -> 401", c.delete(f"/teams/{tid}/members/x").status_code == 401)

        # I2 — org-scoped member management
        check("I2a the org owner can add a member", c.post(f"/teams/{tid}/members", json={"handle": "u1", "role": "lead"}, headers=H("alice")).status_code == 200)
        check("I2b the org admin can add a member", c.post(f"/teams/{tid}/members", json={"handle": "u2", "role": "member"}, headers=H("bob")).status_code == 200)
        check("I2c a NON-member of the org cannot add a member (-> 403)",
              c.post(f"/teams/{tid}/members", json={"handle": "u3", "role": "member"}, headers=H("carol")).status_code == 403)
        check("I2d the org owner can remove a member", c.delete(f"/teams/{tid}/members/u2", headers=H("alice")).status_code == 200)
        check("I2e a NON-member of the org cannot remove a member (-> 403)",
              c.delete(f"/teams/{tid}/members/u1", headers=H("carol")).status_code == 403)

        # I3 — CROSS-ORG ISOLATION: dave (owner of globex) cannot manage acme's team; bob (acme admin) cannot manage globex's team
        globex_team = c.post("/teams", json={"org": "globex", "name": "ops"}, headers=H("dave"))
        gtid = globex_team.json()["id"]
        check("I3a an owner of org B cannot add to org A's team (-> 403)",
              c.post(f"/teams/{tid}/members", json={"handle": "x", "role": "member"}, headers=H("dave")).status_code == 403)
        check("I3b an admin of org A cannot add to org B's team (-> 403)",
              c.post(f"/teams/{gtid}/members", json={"handle": "x", "role": "member"}, headers=H("bob")).status_code == 403)
        check("I3c an admin of org A cannot remove from org B's team (-> 403)",
              c.delete(f"/teams/{gtid}/members/x", headers=H("bob")).status_code == 403)

        # I4 — SET + upsert (alice is the acme owner; u1 currently on the team)
        c.post(f"/teams/{tid}/members", json={"handle": "u1", "role": "member"}, headers=H("alice"))
        t = c.post(f"/teams/{tid}/members", json={"handle": "u1", "role": "owner"}, headers=H("alice")).json()
        u1s = [m for m in t["members"] if m["handle"] == "u1"]
        check("I4a a handle appears at most once", len(u1s) == 1, f"got {u1s}")
        check("I4b re-adding UPDATES the role in place", u1s[0]["role"] == "owner")

        # I5 — deterministic order (insert out of alphabetical order); reads need a member token (I11 read-scoping)
        c.post(f"/teams/{tid}/members", json={"handle": "zoe", "role": "member"}, headers=H("bob"))
        c.post(f"/teams/{tid}/members", json={"handle": "amy", "role": "member"}, headers=H("bob"))
        handles = [m["handle"] for m in c.get(f"/teams/{tid}", headers=H("alice")).json()["members"]]
        check("I5 members are sorted by handle", handles == sorted(handles), f"got {handles}")

        # I6 — org binding immutable across all the mutations above
        check("I6 the org is unchanged by membership ops", c.get(f"/teams/{tid}", headers=H("alice")).json()["org"] == "acme")

        # I7 — idempotent removal (by the org owner)
        r1 = c.delete(f"/teams/{tid}/members/zoe", headers=H("alice"))
        r2 = c.delete(f"/teams/{tid}/members/zoe", headers=H("alice"))        # already gone
        r3 = c.delete(f"/teams/{tid}/members/never", headers=H("alice"))      # never a member
        check("I7 removing twice / a non-member is a stable 200",
              r1.status_code == r2.status_code == r3.status_code == 200 and r1.json() == r2.json() == r3.json())
        check("I7b zoe is actually gone", "zoe" not in [m["handle"] for m in r3.json()["members"]])

        # I8 — authz BEFORE validation (the rbac precedence, identical ×3)
        check("I8a non-member + invalid body -> 403 (authz before validation, not 422)",
              c.post(f"/teams/{tid}/members", json={"handle": ""}, headers=H("carol")).status_code == 403)
        check("I8b no token + invalid body -> 401 (authn first, not 422)",
              c.post(f"/teams/{tid}/members", json={"handle": ""}).status_code == 401)

        # I9 — honest 404s + strict input (with a valid manager token)
        check("I9a missing team add/remove -> 404 (load before authz)",
              c.post("/teams/999999/members", json={"handle": "x", "role": "y"}, headers=H("alice")).status_code == 404
              and c.delete("/teams/999999/members/x", headers=H("alice")).status_code == 404)
        check("I9b missing team read (member token) -> 404", c.get("/teams/999999", headers=H("alice")).status_code == 404)
        check("I9c non-numeric team id -> 422", c.get("/teams/abc", headers=H("alice")).status_code == 422
              and c.post("/teams/abc/members", json={"handle": "x", "role": "y"}, headers=H("alice")).status_code == 422)
        for bad in ({"name": "x"}, {"org": "acme"}, {"org": "", "name": "x"}, {"org": "acme", "name": ""}):
            check(f"I9d invalid create {bad!r} -> 422", c.post("/teams", json=bad, headers=H("alice")).status_code == 422)
        for bad in ({"handle": "x"}, {"role": "y"}, {"handle": "", "role": "y"}):
            check(f"I9e invalid member {bad!r} (manager token) -> 422",
                  c.post(f"/teams/{tid}/members", json=bad, headers=H("alice")).status_code == 422)
        check("I9f forged handle (%1F) delete by a manager -> 422",
              c.delete(f"/teams/{tid}/members/p%1Fq", headers=H("alice")).status_code == 422)

        # I10 — durable seam: the team (with its org + members) is stored
        from app_pkg.core import store
        stored = store.get("teams_records", str(tid))
        check("I10 team persisted with its org + members", stored is not None and stored["org"] == "acme")

        # I11 — READ-SCOPING: the read is gated on org MEMBERSHIP, not the manager roles. carol is made
        # a plain 'member' of acme to prove ANY role can read; eve is a registered non-member; dave owns globex only.
        c.post("/orgs/acme/members", json={"handle": "carol", "role": "member"}, headers=H("alice"))  # carol = INVITED member
        _carol_accept = accept_org(c, "acme", "carol")  # carol accepts -> ACTIVE plain member (pending grants no access)
        check("I11-setup carol accepts the acme member invite -> ACTIVE", _carol_accept is not None and _carol_accept.status_code == 200)
        check("I11a the org OWNER can read the team (200)", c.get(f"/teams/{tid}", headers=H("alice")).status_code == 200)
        check("I11b the org ADMIN can read the team (200)", c.get(f"/teams/{tid}", headers=H("bob")).status_code == 200)
        check("I11c a plain MEMBER (any role) can read the team (200)", c.get(f"/teams/{tid}", headers=H("carol")).status_code == 200)
        check("I11d a NON-member of the team's org cannot read it (-> 404, not 403)",
              c.get(f"/teams/{tid}", headers=H("eve")).status_code == 404)
        check("I11e a read with NO token is 401 (authn before the not-found)", c.get(f"/teams/{tid}").status_code == 401)
        # cross-org read isolation (the read-side mirror of I3): dave owns globex (gtid), bob is an acme admin
        check("I11f an owner of org B cannot read org A's team (-> 404)", c.get(f"/teams/{tid}", headers=H("dave")).status_code == 404)
        check("I11g an admin of org A cannot read org B's team (-> 404)", c.get(f"/teams/{gtid}", headers=H("bob")).status_code == 404)
        check("I11h a member of org B CAN read org B's own team (-> 200)", c.get(f"/teams/{gtid}", headers=H("dave")).status_code == 200)

    print(f"TEAMS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
