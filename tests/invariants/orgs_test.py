"""ORGS INVARIANTS — multi-member orgs governed by the AUTHENTICATED identity (the core require_identity +
org_role seams), NOT caller-supplied input. Run against the python app (cwd=<app>/python; the app includes auth —
orgs `requires` it). The test seam (APP_TEST_SESSIONS) is enabled so a 'test:<handle>' token resolves to <handle>
(inert in prod). Credited by EXIT CODE ONLY.

Proves:  I0 deny-by-default — every mutation is 401 without a valid bearer token (no / malformed scheme).
         I1 slug uniqueness — a duplicate create is 409, the original org (owner intact) survives.
         I2 THE SLUG RACE — two processes create the same slug concurrently: exactly one org (one 201, one 409).
         I3 OWNER STAMPED FROM THE TOKEN — create ignores any body 'owner'; the owner is the caller; the owner is
            DERIVED from orgs_records.owner (SINGLE-SOURCE — NOT a membership row), proven by I3c/I3d.
         I4 NEVER OWNERLESS / EXACTLY ONE OWNER — transfer moves ownership (new owner becomes the sole 'owner',
            the old owner is demoted to 'admin'); the owner can never be removed (403) or demoted via add-member;
            a transfer to a blank/garbage owner is 422 and ownership is unchanged.
         I5 ROLE-GATED MANAGEMENT + PENDING-UNTIL-ACCEPTED — owner|active-admin may add/remove members + archive;
            transfer is owner-only; a non-member is 403; a member can NEVER escalate itself; add_member INVITES (the
            invitee is PENDING and has NO role) and the role is granted ONLY once the invitee ACCEPTs the token.
         I6 AUTHZ BEFORE VALIDATION — a non-member with an otherwise-invalid body is 403 (not 422); no-token is 401.
         I7 monotonic archival — idempotent, terminal; an archived org keeps its owner.
         I8 honest 404s (a valid-token op on a missing org is 404, load before authz) + strict input.
         I9 durable — records + memberships (as {role,status} records) persist in the store seam.
        I10 MEMBER-SCOPED READ — GET /orgs/{slug} requires identity (401 without a token)
            and is gated by ACTIVE org membership: a non-member (incl. a PENDING invitee) read is 404, BYTE-IDENTICAL
            to a missing slug; the owner + every ACCEPTED member (admin|member) get 200.
        I15 THE CLOSURE PROOF — the member-identity privilege escalation REFUTES: a manager planting
            add_member{victim, admin} leaves victim PENDING with org_role None (no role, denied manage/read); only the
            invitee, ACCEPTing with the single-use token the email worker delivered to the outbox, gains the role; a
            wrong/replayed token or a DIFFERENT caller activates nothing.
        I16 LISTING — three paginated reads through the bounded paginate seam: list-members is
            MEMBER-SCOPED (a member sees the roster = the DERIVED owner + every ACTIVE member; a PENDING invite is NOT
            listed; a non-member is 404 byte-identical to a missing slug); list-invitations is MANAGER-only (owner|
            admin) and lists the PENDING invites WITHOUT the secret/token; list-my-orgs returns the caller's own orgs
            (owned OR an active member of), authenticated, and a pending-only invitee is excluded.
        I17 SELF-LEAVE — the authenticated caller leaves (org_role -> None afterwards); the OWNER cannot leave
            (409, never ownerless); a non-member leave is MEMBER-SCOPED -> 404 byte-identical to a missing slug (no
            existence leak, no no-op audit firehose); the successful leave is audited.
        I18 TRANSFER-DEMOTION ‖ REMOVE(old owner) — the demotion + remove_member are SOFT writes through
            the do() seam on the ONE member key, so they SERIALIZE: the old owner converges to ONE deterministic state
            (active 'admin' XOR a 'removed' tombstone, org_role agreeing), no confirmed-removed member is resurrected,
            and ownership is unaffected (the atomic owner-swap is independent).
        I19 DENY-AUDIT THROTTLE (deny-audit flood + cross-org isolation) — a caller hammering a deny path can NOT grow
            orgs_decisions unbounded: the deny-audit WRITE is throttled per (org, subject) (first N per window record),
            every attempt is STILL refused 403, success audits are never throttled, and noise on a decoy org can't
            blind a victim org's first-denial trail (I19e).
        I20 OUTBOX KEY — the invite-delivery key is <slug>\x1f<handle> (un-forgeable, not <slug>:<handle>): two
            colon-crafted invites across different orgs keep DISTINCT delivery rows (no cross-tenant clobber).
        I21 NO-OWNER-ROW DEFENSE-IN-DEPTH — the org_role seam REFUSES a membership row that claims role 'owner': a
            hostile ACTIVE orgs_members row {role:'owner'} injected DIRECTLY into the store (bypassing every handler)
            confers org_role None, NOT 'owner' (single-source: ownership is orgs_records.owner alone), while the real
            records-owner still derives 'owner'. Locks the seam's `role if role != 'owner' else None` guard ×3
            BEHAVIORALLY — a regression that silently drops it is caught even though no writer emits such a row (I11b/
            I18b only cover handler-PRODUCED rows; this injects one no API path can)."""
import os
import subprocess
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # the 'test:<handle>' token resolves to <handle> (inert in prod)
os.environ.setdefault("ORGS_DENY_AUDIT_LIMIT", "5")   # a small per-subject deny-audit cap so I19 is crisp + fast (the
os.environ.setdefault("ORGS_DENY_AUDIT_WINDOW", "3600")  # deny-audit throttle; the first 5 denials per subject record)
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.core import store  # noqa: E402
from app_pkg.core.errors import org_role  # noqa: E402  (single-source: prove the owner is DERIVED, not a membership row)
from app_pkg.app import app  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def H(handle):
    return {"Authorization": f"Bearer test:{handle}"}


RACE_WORKER = """
import os, sys
os.environ["APP_TEST_SESSIONS"] = "1"
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
with TestClient(app, raise_server_exceptions=False) as c:
    r = c.post("/orgs", json={"slug": "raced"}, headers={"Authorization": "Bearer test:founder"})
    print(r.status_code)
"""


TRANSFER_WORKER = """
import os, sys
os.environ["APP_TEST_SESSIONS"] = "1"
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
with TestClient(app, raise_server_exceptions=False) as c:
    r = c.post(f"/orgs/{sys.argv[1]}/transfer", json={"owner": sys.argv[2]},
               headers={"Authorization": f"Bearer test:{sys.argv[3]}"})
    print(r.status_code)
"""


ARCHIVE_WORKER = """
import os, sys
os.environ["APP_TEST_SESSIONS"] = "1"
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
with TestClient(app, raise_server_exceptions=False) as c:
    r = c.post(f"/orgs/{sys.argv[1]}/archive", headers={"Authorization": f"Bearer test:{sys.argv[2]}"})
    print(r.status_code)
"""


REMOVE_WORKER = """
import os, sys
os.environ["APP_TEST_SESSIONS"] = "1"
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
with TestClient(app, raise_server_exceptions=False) as c:
    r = c.delete(f"/orgs/{sys.argv[1]}/members/{sys.argv[2]}",
                 headers={"Authorization": f"Bearer test:{sys.argv[3]}"})
    print(r.status_code)
"""


def mkey(slug, handle):
    return f"{slug}\x1f{handle}"


def member_rec(slug, handle):
    return store.get("orgs_members", mkey(slug, handle))   # {org, handle, role, status, ...} or None


def member_status(slug, handle):
    rec = member_rec(slug, handle)
    return rec.get("status") if rec else None


def member_role(slug, handle):
    rec = member_rec(slug, handle)
    return rec.get("role") if rec else None


def invite_token(slug, handle):
    # drain the orgs_outbox the way the "email worker" would (mirrors auth's outbox_token in its invariant): this is
    # the ONLY way to obtain the single-use accept secret — it is delivered to the INVITEE, never returned to the inviter.
    rec = store.get("orgs_outbox", f"{slug}\x1f{handle}")   # \x1f-joined, parity with _deliver_invite (F2 collision-free)
    return rec.get("token") if rec else None


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        # I0 — deny-by-default (clean bodies so the failure is purely auth, identical ×3)
        check("I0a create no token -> 401", c.post("/orgs", json={"slug": "anon"}).status_code == 401)
        check("I0b transfer no token -> 401", c.post("/orgs/acme/transfer", json={"owner": "x"}).status_code == 401)
        check("I0c archive no token -> 401", c.post("/orgs/acme/archive", json={}).status_code == 401)
        check("I0d add-member no token -> 401", c.post("/orgs/acme/members", json={"handle": "x", "role": "member"}).status_code == 401)
        check("I0e remove-member no token -> 401", c.delete("/orgs/acme/members/x").status_code == 401)
        check("I0f malformed scheme -> 401", c.post("/orgs", json={"slug": "anon"}, headers={"Authorization": "test:alice"}).status_code == 401)

        # I3 — owner stamped from the token; a body 'owner' is IGNORED; the owner is DERIVED from orgs_records.owner
        # (SINGLE-SOURCE), NOT a membership row (proven by I3c/I3d)
        created = c.post("/orgs", json={"slug": "acme", "owner": "mallory"}, headers=H("alice")).json()
        check("I3a owner is the authenticated caller, not the body field", created["owner"] == "alice")
        check("I3b orgs_records carries the owner handle", store.get("orgs_records", "acme")["owner"] == "alice")
        check("I3c SINGLE-SOURCE: the owner is NOT a membership row — it is DERIVED from orgs_records.owner",
              store.get("orgs_members", mkey("acme", "alice")) is None and org_role("acme", "alice") == "owner")
        check("I3d mallory (the forged body owner) is NOT a member and has no role",
              store.get("orgs_members", mkey("acme", "mallory")) is None and org_role("acme", "mallory") is None)

        # I1 — slug uniqueness
        check("I1a duplicate slug -> 409", c.post("/orgs", json={"slug": "acme"}, headers=H("bob")).status_code == 409)
        check("I1b the original org survives intact (owner still alice)", c.get("/orgs/acme", headers=H("alice")).json()["owner"] == "alice")

        # I5 — role-gated management + MEMBERSHIP PENDING UNTIL ACCEPTED. add_member is an INVITE: the invitee is
        # PENDING and has NO role until they ACCEPT with the single-use token (the member-identity escalation fix).
        add_bob = c.post("/orgs/acme/members", json={"handle": "bob", "role": "admin"}, headers=H("alice"))
        check("I5a owner invites an admin -> 201, status PENDING (not yet granted)",
              add_bob.status_code == 201 and add_bob.json().get("status") == "pending")
        check("I5a2 the PENDING invitee has NO role yet (org_role None) and is NOT yet an admin",
              org_role("acme", "bob") is None and member_status("acme", "bob") == "pending")
        check("I5a3 a PENDING invitee CANNOT manage (add -> 403): the unaccepted invite grants nothing",
              c.post("/orgs/acme/members", json={"handle": "carol", "role": "member"}, headers=H("bob")).status_code == 403)
        # bob ACCEPTS with the token the "email worker" delivered to the outbox (the ONLY way to obtain it)
        btok = invite_token("acme", "bob")
        acc = c.post("/orgs/acme/members/accept", json={"token": btok}, headers=H("bob"))
        check("I5a4 bob ACCEPTs with the delivered token -> 200, now ACTIVE admin (org_role == admin)",
              acc.status_code == 200 and acc.json().get("status") == "active" and org_role("acme", "bob") == "admin")
        check("I5a5 the accept CLEARED the single-use secret (no lingering secret_hash)",
              (member_rec("acme", "bob") or {}).get("secret_hash", "") == "")
        check("I5b that NOW-ACTIVE admin can manage (invites a member)",
              c.post("/orgs/acme/members", json={"handle": "carol", "role": "member"}, headers=H("bob")).status_code == 201)
        check("I5c a PENDING member cannot manage (add -> 403)",
              c.post("/orgs/acme/members", json={"handle": "dave", "role": "member"}, headers=H("carol")).status_code == 403)
        check("I5d a member cannot escalate ITSELF to admin (-> 403)",
              c.post("/orgs/acme/members", json={"handle": "carol", "role": "admin"}, headers=H("carol")).status_code == 403)
        check("I5e a NON-member cannot manage (-> 403)",
              c.post("/orgs/acme/members", json={"handle": "x", "role": "member"}, headers=H("stranger")).status_code == 403)
        check("I5f a manager cannot mint a second OWNER via add-member (role 'owner' -> 403)",
              c.post("/orgs/acme/members", json={"handle": "x", "role": "owner"}, headers=H("alice")).status_code == 403)
        check("I5g transfer is OWNER-only: an admin cannot transfer (-> 403)",
              c.post("/orgs/acme/transfer", json={"owner": "carol"}, headers=H("bob")).status_code == 403)

        # I4 — never ownerless / exactly one owner. SINGLE-SOURCE: the owner is orgs_records.owner (DERIVED), NOT a
        # membership row — so "exactly one owner" is STRUCTURAL (one field can hold one value), and owner_of reads it.
        def owner_of(slug):
            rec = store.get("orgs_records", slug)
            return rec["owner"] if rec else None
        check("I4a exactly one owner before transfer", owner_of("acme") == "alice", f"got {owner_of('acme')}")
        t = c.post("/orgs/acme/transfer", json={"owner": "bob"}, headers=H("alice"))
        check("I4b owner transfers ownership -> 200, new owner recorded", t.status_code == 200 and t.json()["owner"] == "bob")
        check("I4c the new owner is the sole owner (orgs_records.owner)", owner_of("acme") == "bob", f"got {owner_of('acme')}")
        check("I4d the OLD owner is demoted to an ACTIVE 'admin' (kept, not evicted; an existing owner is already proven)",
              member_role("acme", "alice") == "admin" and member_status("acme", "alice") == "active")
        check("I4e the owner cannot be REMOVED (-> 403, never ownerless)",
              c.delete("/orgs/acme/members/bob", headers=H("bob")).status_code == 403)
        check("I4f the owner is still present after the rejected removal (derived from orgs_records.owner)", owner_of("acme") == "bob")
        bad = c.post("/orgs/acme/transfer", json={"owner": ""}, headers=H("bob"))
        check("I4g transfer to a blank owner -> 422", bad.status_code == 422)
        check("I4h ownership unchanged after the rejected transfer", c.get("/orgs/acme", headers=H("bob")).json()["owner"] == "bob")
        # a self-transfer keeps the caller as the sole owner (no demotion-to-admin of itself). SINGLE-SOURCE: the owner
        # is DERIVED (org_role == "owner") and holds NO ACTIVE membership row — any leftover row is an inert SOFT-delete
        # tombstone (status != active), which org_role ignores. (Under the soft-delete, the transfer tombstones
        # the new owner's prior row instead of hard-deleting it; the tombstone grants nothing — the derived owner stands.)
        st = c.post("/orgs/acme/transfer", json={"owner": "bob"}, headers=H("bob"))
        check("I4i a self-transfer leaves the caller as the sole DERIVED owner (org_role owner; no ACTIVE membership row)",
              st.status_code == 200 and owner_of("acme") == "bob" and org_role("acme", "bob") == "owner"
              and member_status("acme", "bob") != "active")

        # I6 — authz BEFORE validation (the rbac precedence, identical ×3)
        check("I6a non-member + invalid body -> 403 (authz before validation, not 422)",
              c.post("/orgs/acme/members", json={"handle": ""}, headers=H("stranger")).status_code == 403)
        check("I6b no token + invalid body -> 401 (authn first, not 422)",
              c.post("/orgs/acme/members", json={"handle": ""}).status_code == 401)

        # I7 — monotonic archival (bob is owner; alice is admin -> both may archive)
        c.post("/orgs/acme/archive", headers=H("alice"))           # admin archives
        again = c.post("/orgs/acme/archive", headers=H("bob"))     # idempotent + terminal
        check("I7a archive idempotent + terminal", again.json()["status"] == "archived")
        check("I7b an archived org keeps its owner", c.get("/orgs/acme", headers=H("bob")).json()["owner"] == "bob")

        # I8 — honest 404s (valid token, missing org -> 404: load before authz) + strict input
        check("I8a a valid-token op on a missing org is 404 (not 403)",
              c.post("/orgs/ghost/transfer", json={"owner": "x"}, headers=H("alice")).status_code == 404
              and c.post("/orgs/ghost/archive", headers=H("alice")).status_code == 404
              and c.post("/orgs/ghost/members", json={"handle": "x", "role": "member"}, headers=H("alice")).status_code == 404
              and c.delete("/orgs/ghost/members/x", headers=H("alice")).status_code == 404)
        check("I8b missing org read -> 404 (valid token; load before the membership check)", c.get("/orgs/ghost", headers=H("alice")).status_code == 404)
        for bad_body in ({}, {"slug": ""}, {"slug": 7}):
            check(f"I8c invalid create {bad_body!r} -> 422", c.post("/orgs", json=bad_body, headers=H("alice")).status_code == 422)
        # forged slug is a 422 at load — but authn runs FIRST, so it needs a valid token
        # (a no-token read of any slug is 401, asserted in I10d); identical ×3 with the mutation 422 precedence.
        check("I8d forged slug (%1F) read -> 422", c.get("/orgs/p%1Fq", headers=H("alice")).status_code == 422)

        # I9 — durable seam: records + memberships are stored under the exact keys the core seam reads
        check("I9a org record persisted", store.get("orgs_records", "acme")["status"] == "archived")
        check("I9b membership persisted under '<slug>\\x1f<handle>' as a self-describing record {role, status}",
              member_role("acme", "alice") == "admin" and member_status("acme", "alice") == "active")

        # I10 — MEMBER-SCOPED READ: the read is gated by org membership, and a non-member is
        # 404 BYTE-IDENTICAL to a missing slug (existence never leaks). Fresh org so the assertions are unambiguous.
        c.post("/orgs", json={"slug": "scoped"}, headers=H("ollie"))            # ollie owns it
        c.post("/orgs/scoped/members", json={"handle": "mary", "role": "member"}, headers=H("ollie"))   # mary: INVITED (pending)
        check("I10a the OWNER can read its own org (200)",
              c.get("/orgs/scoped", headers=H("ollie")).status_code == 200)
        check("I10b0 a PENDING invitee is NOT yet a member: her read is 404 (the invite confers no access until accepted)",
              c.get("/orgs/scoped", headers=H("mary")).status_code == 404)
        c.post("/orgs/scoped/members/accept", json={"token": invite_token("scoped", "mary")}, headers=H("mary"))  # mary accepts
        check("I10b an ACTIVE member can read the org (200)",
              c.get("/orgs/scoped", headers=H("mary")).status_code == 200)
        check("I10c a NON-member read is 404 (not 200, not 403 — existence never leaks)",
              c.get("/orgs/scoped", headers=H("stranger")).status_code == 404)
        check("I10d a no-token read is 401 (authn before the membership 404)",
              c.get("/orgs/scoped").status_code == 401)
        # the leak this closes: a non-member read of a REAL org must be INDISTINGUISHABLE from a read of a missing one
        non_member = c.get("/orgs/scoped", headers=H("stranger"))
        missing = c.get("/orgs/ghost", headers=H("stranger"))
        check("I10e non-member 404 is BYTE-IDENTICAL to a missing-slug 404 (status + body)",
              non_member.status_code == missing.status_code == 404 and non_member.text == missing.text,
              f"non_member={non_member.status_code}:{non_member.text!r} missing={missing.status_code}:{missing.text!r}")
        scoped_rec = store.get("orgs_records", "scoped")
        check("I10f the org is unchanged by the rejected non-member read (still owned by ollie, active)",
              scoped_rec["owner"] == "ollie" and scoped_rec["status"] == "active")

        # I13 — PRIVILEGED-MUTATION + DENIAL AUDIT (ASVS 7.1.3/7.2.2): the default mode records
        # every authz DENIAL and every successful ownership/membership MUTATION to the orgs_decisions trail. (A fresh
        # org so the trail is unambiguous; APP_ORGS_AUDIT unset -> the 'deny' default is active.)
        c.post("/orgs", json={"slug": "audited"}, headers=H("auer"))                                # create (success)
        c.post("/orgs/audited/members", json={"handle": "x", "role": "owner"}, headers=H("auer"))    # 403 -> deny audit
        c.post("/orgs/audited/members", json={"handle": "amy", "role": "admin"}, headers=H("auer"))  # INVITE amy (pending)
        c.post("/orgs/audited/members/accept", json={"token": invite_token("audited", "amy")}, headers=H("amy"))  # accept
        c.post("/orgs/audited/transfer", json={"owner": "amy"}, headers=H("auer"))                   # transfer (success)
        trail = [d for d in store.values("orgs_decisions") if d.get("org") == "audited"]
        results = {d["result"] for d in trail}
        kinds = {d["kind"] for d in trail}
        check("I13a a denied mutation (role-not-assignable) is audited 'deny' BEFORE refusing (the denial-audit gate)",
              "deny" in results, f"results={results}")
        check("I13b every privileged event is recorded by default (create + invite + accept + transfer)",
              {"create", "transfer", "accept"} <= results and "invite" in kinds, f"results={results} kinds={kinds}")
        check("I13c every record carries the subject + a monotonic id + the org (the ASVS trail fields)",
              len(trail) >= 5 and all(set(d) >= {"id", "subject", "kind", "org", "result", "ts"} for d in trail),
              f"n={len(trail)}")

        # I14 — IDEMPOTENT membership writes (SCIM §3.5.2 / openfga on_duplicate=ignore): re-INVITING a still-pending
        # member is a no-duplicate upsert (one row); re-setting an ALREADY-ACTIVE member updates the role IN PLACE with
        # NO new token (they are already proven); removing an absent member is a 200 no-op. (amy is now owner of 'audited'
        # after the I13 transfer, so amy manages.) SoD is proven by I5f (owner-role add -> 403) + I5g (transfer owner-only).
        r1 = c.post("/orgs/audited/members", json={"handle": "ida", "role": "member"}, headers=H("amy"))
        r2 = c.post("/orgs/audited/members", json={"handle": "ida", "role": "member"}, headers=H("amy"))  # re-invite same
        check("I14a re-inviting the SAME pending member is an idempotent upsert (one PENDING row, role unchanged)",
              r1.status_code == 201 and r2.status_code == 201
              and member_role("audited", "ida") == "member" and member_status("audited", "ida") == "pending")
        c.post("/orgs/audited/members/accept", json={"token": invite_token("audited", "ida")}, headers=H("ida"))  # ida accepts
        check("I14a2 ida is now an ACTIVE member (org_role member)", org_role("audited", "ida") == "member")
        r3 = c.post("/orgs/audited/members", json={"handle": "ida", "role": "admin"}, headers=H("amy"))    # re-set role
        check("I14b re-setting an ALREADY-ACTIVE member's role UPDATES it in place as ACTIVE, no token, no re-pending",
              r3.status_code == 201 and r3.json().get("status") == "active"
              and member_role("audited", "ida") == "admin" and member_status("audited", "ida") == "active"
              and org_role("audited", "ida") == "admin"
              and (member_rec("audited", "ida") or {}).get("secret_hash", "") == "")
        d1 = c.delete("/orgs/audited/members/ghosty", headers=H("amy"))   # remove an ABSENT member
        check("I14c removing an absent member is a 200 no-op (idempotent; no row created)",
              d1.status_code == 200 and d1.json()["removed"] is True and store.get("orgs_members", mkey("audited", "ghosty")) is None)

        # I15 — THE CLOSURE PROOF: the member-identity privilege escalation is REFUTED. A
        # manager pre-names a raw handle (victim) an attacker could later self-register; before the fix that handle got
        # the role immediately (escalation). Now it is PENDING and grants NOTHING until the INVITED party ACCEPTs with
        # the single-use token — which only the real recipient (here, the test "email worker" reading the outbox) holds.
        c.post("/orgs", json={"slug": "vorg"}, headers=H("vowner"))                                   # vowner owns vorg
        plant = c.post("/orgs/vorg/members", json={"handle": "victim", "role": "admin"}, headers=H("vowner"))
        check("I15a the manager's add_member is an INVITE: victim is PENDING (status pending), role NOT granted",
              plant.status_code == 201 and plant.json().get("status") == "pending"
              and member_status("vorg", "victim") == "pending")
        check("I15b ESCALATION REFUTED at the seam: org_role('vorg','victim') is None (a pending invite grants nothing)",
              org_role("vorg", "victim") is None)
        check("I15b2 ESCALATION REFUTED at the surface: the unaccepted 'victim' (the attacker who registered that handle) "
              "is DENIED a manage op (403) and cannot read the org (404)",
              c.post("/orgs/vorg/members", json={"handle": "x", "role": "member"}, headers=H("victim")).status_code == 403
              and c.get("/orgs/vorg", headers=H("victim")).status_code == 404)
        # a WRONG token does NOT activate (and does not consume the pending invite) -> 403, victim still has no role
        wrong = c.post("/orgs/vorg/members/accept", json={"token": "deadbeef.deadbeef"}, headers=H("victim"))
        check("I15c accept with a WRONG token -> 403; victim is still PENDING with no role (the invite is not consumed)",
              wrong.status_code == 403 and member_status("vorg", "victim") == "pending" and org_role("vorg", "victim") is None)
        # a DIFFERENT caller than the invited handle cannot activate victim's invite: the membership is keyed on the
        # CALLER, so even WITH the real token an attacker authenticated as someone else only ever touches THEIR OWN
        # (absent) row -> 404, and victim's pending invite is untouched.
        vtok = invite_token("vorg", "victim")
        other = c.post("/orgs/vorg/members/accept", json={"token": vtok}, headers=H("impostor"))
        check("I15d a DIFFERENT caller (impostor) presenting victim's token activates NOTHING (keyed on the caller) -> 404; "
              "victim still pending; impostor gains no role",
              other.status_code == 404 and member_status("vorg", "victim") == "pending"
              and org_role("vorg", "victim") is None and org_role("vorg", "impostor") is None)
        # the LEGITIMATE accept: the real recipient (the email worker delivered the token to victim) accepts -> NOW active
        good = c.post("/orgs/vorg/members/accept", json={"token": vtok}, headers=H("victim"))
        check("I15e the INVITED party accepts with the delivered token -> 200 ACTIVE admin; org_role now 'admin' and "
              "victim CAN manage (the grant happens ONLY through accept)",
              good.status_code == 200 and org_role("vorg", "victim") == "admin"
              and c.post("/orgs/vorg/members", json={"handle": "y", "role": "member"}, headers=H("victim")).status_code == 201)
        # single-use: replaying the same token after a successful accept does not re-trigger anything (already active -> 404)
        replay = c.post("/orgs/vorg/members/accept", json={"token": vtok}, headers=H("victim"))
        check("I15f the accept token is SINGLE-USE: replaying it after activation is 404 (no pending invite remains)",
              replay.status_code == 404 and org_role("vorg", "victim") == "admin")

        # I16 — LISTING: three paginated reads, each routed through the bounded paginate seam.
        # Build a fresh org so the rosters are unambiguous: lister owns 'lorg'; mem1 is an ACCEPTED member; inv1 is a
        # PENDING invite. The DERIVED owner (no membership row) MUST appear in the roster; a PENDING invite must NOT.
        c.post("/orgs", json={"slug": "lorg"}, headers=H("lister"))
        c.post("/orgs/lorg/members", json={"handle": "mem1", "role": "member"}, headers=H("lister"))
        c.post("/orgs/lorg/members/accept", json={"token": invite_token("lorg", "mem1")}, headers=H("mem1"))  # mem1 ACTIVE
        c.post("/orgs/lorg/members", json={"handle": "inv1", "role": "admin"}, headers=H("lister"))           # inv1 PENDING
        # I16a list-members: a member sees the roster = the DERIVED owner + every ACTIVE member; pending NOT listed.
        lm = c.get("/orgs/lorg/members", headers=H("mem1"))
        roster = {(x["handle"], x["role"]) for x in lm.json()["results"]} if lm.status_code == 200 else set()
        check("I16a a member sees the roster incl. the DERIVED owner (owner + active member); pending NOT listed; {results,next_cursor}",
              lm.status_code == 200 and ("lister", "owner") in roster and ("mem1", "member") in roster
              and ("inv1", "admin") not in roster and len(roster) == 2 and lm.json()["next_cursor"] is None,
              f"got {lm.status_code}:{lm.json() if lm.status_code == 200 else lm.text}")
        # I16b a NON-member (incl. the pending invitee) listing members is 404, BYTE-IDENTICAL to a missing slug.
        nm_members = c.get("/orgs/lorg/members", headers=H("stranger"))
        miss_members = c.get("/orgs/ghost/members", headers=H("stranger"))
        check("I16b a non-member list-members is 404 BYTE-IDENTICAL to a missing slug; the pending invitee is also 404; no token -> 401",
              nm_members.status_code == miss_members.status_code == 404 and nm_members.text == miss_members.text
              and c.get("/orgs/lorg/members", headers=H("inv1")).status_code == 404
              and c.get("/orgs/lorg/members").status_code == 401,
              f"nonmember={nm_members.status_code}:{nm_members.text!r} missing={miss_members.status_code}:{miss_members.text!r}")
        # I16c list-invitations is MANAGER-only: it lists the PENDING invite (handle, role, invite_exp) and NEVER the secret.
        li = c.get("/orgs/lorg/invitations", headers=H("lister"))
        inv_rows = li.json()["results"] if li.status_code == 200 else []
        check("I16c the owner|admin lists PENDING invites (inv1) with NO secret/token leaked; an active member CAN list (it is owner|admin-gated only — mem1 is a plain member -> 403); a non-member -> 403",
              li.status_code == 200 and len(inv_rows) == 1 and inv_rows[0]["handle"] == "inv1"
              and inv_rows[0]["role"] == "admin" and "invite_exp" in inv_rows[0]
              and not any(k in inv_rows[0] for k in ("secret_hash", "token", "secret"))
              and c.get("/orgs/lorg/invitations", headers=H("mem1")).status_code == 403
              and c.get("/orgs/lorg/invitations", headers=H("stranger")).status_code == 403,
              f"got {li.status_code}:{inv_rows}")
        # I16d list-my-orgs returns the caller's orgs (owned OR an active member of), authenticated, paginated.
        owned = {r["slug"] for r in c.get("/orgs", headers=H("lister")).json()["results"]}
        member_of = {r["slug"] for r in c.get("/orgs", headers=H("mem1")).json()["results"]}
        check("I16d list-my-orgs returns the caller's orgs — the OWNER sees 'lorg'; an ACTIVE member sees 'lorg'; "
              "a no-token read is 401; a caller in no org sees an empty page",
              "lorg" in owned and "lorg" in member_of
              and c.get("/orgs").status_code == 401
              and c.get("/orgs", headers=H("hermit")).json()["results"] == [],
              f"owned={owned} member_of={member_of}")
        # I16e a pending-only invitee does NOT see the org in list-my-orgs (the invite confers no membership yet).
        check("I16e a PENDING-only invitee does NOT see the org in list-my-orgs (no membership until accepted)",
              "lorg" not in {r["slug"] for r in c.get("/orgs", headers=H("inv1")).json()["results"]})

        # I17 — SELF-LEAVE: the authenticated caller deletes THEIR OWN membership row; the OWNER cannot leave
        # (409, never ownerless); a non-member leave is MEMBER-SCOPED -> 404 BYTE-IDENTICAL to a missing slug (existence
        # never leaks via leave's status, and a non-member can't pump no-op 'leave' audit rows); the real leave is audited.
        check("I17a a member leaves -> 200; afterwards org_role is None (the role is gone)",
              c.post("/orgs/lorg/leave", headers=H("mem1")).status_code == 200 and org_role("lorg", "mem1") is None
              and member_rec("lorg", "mem1") is None)
        check("I17b the OWNER cannot leave -> 409 (transfer ownership first); the owner is unchanged",
              c.post("/orgs/lorg/leave", headers=H("lister")).status_code == 409
              and (store.get("orgs_records", "lorg") or {}).get("owner") == "lister" and org_role("lorg", "lister") == "owner")
        # a non-member leave is MEMBER-SCOPED: 404 BYTE-IDENTICAL to a missing slug (mirrors the read posture I10e) — so
        # existence never leaks via leave's 200/404, and a non-member also can't pump no-op 'leave' rows.
        nm_leave = c.post("/orgs/lorg/leave", headers=H("stranger"))
        miss_leave = c.post("/orgs/ghost/leave", headers=H("stranger"))
        check("I17c a non-member leave is 404 BYTE-IDENTICAL to a missing slug (no existence leak, no no-op audit); no row "
              "created; a no-token leave is 401; a valid-token missing org is 404",
              nm_leave.status_code == miss_leave.status_code == 404 and nm_leave.text == miss_leave.text
              and member_rec("lorg", "stranger") is None
              and c.post("/orgs/lorg/leave").status_code == 401
              and c.post("/orgs/ghost/leave", headers=H("lister")).status_code == 404,
              f"nonmember={nm_leave.status_code}:{nm_leave.text!r} missing={miss_leave.status_code}:{miss_leave.text!r}")
        leave_trail = [d for d in store.values("orgs_decisions") if d.get("org") == "lorg" and d.get("kind") == "leave"]
        check("I17d the successful leave is AUDITED (a 'leave'/'ok' decision recorded) and the owner-denial is audited 'deny'",
              any(d["result"] == "leave" for d in leave_trail) and any(d["result"] == "deny" for d in leave_trail),
              f"leave_trail={leave_trail}")
        # I17e: the non-member leaves above wrote NO 'leave' decision rows — a non-member can no
        # longer pump the decision log through leave's success-path (only a REAL member's leave is audited).
        stranger_leave_rows = [d for d in store.values("orgs_decisions") if d.get("subject") == "stranger" and d.get("kind") == "leave"]
        check("I17e a non-member's leave writes NO 'leave' audit row (the success-path firehose is closed)",
              len(stranger_leave_rows) == 0, f"stranger leave rows={len(stranger_leave_rows)}")

        # I19 — DENY-AUDIT THROTTLE: a non-member hammering a deny path can NOT grow orgs_decisions
        # unbounded. With the per-(org,subject) cap (ORGS_DENY_AUDIT_LIMIT=5 here), 'pumper' hammers add_member on a fresh
        # org 20x — every call is still a real 403 (the deny is NEVER suppressed), the FIRST denial IS recorded (a
        # normal denial is still audited, so the denial-audit gate stays honest), but the deny-ROWS for that subject
        # are bounded by the cap (the storage-amplification firehose is closed). Success-mutation audits aren't throttled.
        cap = int(os.environ["ORGS_DENY_AUDIT_LIMIT"])
        c.post("/orgs", json={"slug": "pumporg"}, headers=H("powner"))   # powner owns it; pumper is a non-member
        hammered = [c.post("/orgs/pumporg/members", json={"handle": "x", "role": "member"}, headers=H("pumper")).status_code
                    for _ in range(20)]
        pumper_rows = [d for d in store.values("orgs_decisions") if d.get("subject") == "pumper" and d.get("result") == "deny"]
        check("I19a every hammered add_member is STILL refused 403 (the throttle suppresses only the WRITE, never the denial)",
              all(s == 403 for s in hammered), f"statuses={set(hammered)}")
        check("I19b a normal denial IS recorded (>=1 deny row for the subject) so the denial-audit gate stays honest",
              len(pumper_rows) >= 1, f"rows={len(pumper_rows)}")
        check("I19c the deny-audit rows for the hammering subject are BOUNDED by the cap (20 attempts -> <= cap rows; "
              "orgs_decisions does NOT grow unbounded)",
              len(pumper_rows) <= cap, f"rows={len(pumper_rows)} cap={cap}")
        # a SUCCESS-mutation audit is NEVER throttled (low-volume, high-value): powner creating many orgs all record.
        for n in range(8):
            c.post("/orgs", json={"slug": f"pwn{n}"}, headers=H("powner"))
        success_rows = [d for d in store.values("orgs_decisions")
                        if d.get("subject") == "powner" and d.get("result") == "create"]
        check("I19d success-mutation audits are NOT throttled (every create by the same subject is recorded)",
              len(success_rows) >= 9, f"create_rows={len(success_rows)}")   # pumporg + pwn0..pwn7 = 9
        # I19e: the deny-budget is keyed per (ORG, subject), so a caller that EXHAUSTED its budget
        # on one org STILL records its FIRST denial on a DIFFERENT victim org — noise on a decoy org can't blind another
        # org's forensic trail. (pumper exhausted its budget on 'pumporg' above; victimorg is fresh.)
        c.post("/orgs", json={"slug": "victimorg"}, headers=H("vowner2"))   # vowner2 owns it; pumper is a non-member
        v_before = len([d for d in store.values("orgs_decisions") if d.get("subject") == "pumper" and d.get("org") == "victimorg"])
        c.post("/orgs/victimorg/members", json={"handle": "z", "role": "member"}, headers=H("pumper"))   # pumper's FIRST denial on victimorg
        v_rows = [d for d in store.values("orgs_decisions")
                  if d.get("subject") == "pumper" and d.get("org") == "victimorg" and d.get("result") == "deny"]
        check("I19e cross-org: a subject that exhausted its deny-budget on a DECOY org STILL records its first denial on "
              "a VICTIM org (the throttle is keyed per (org, subject); noise elsewhere can't blind a victim org's trail)",
              v_before == 0 and len(v_rows) >= 1, f"before={v_before} victim_rows={len(v_rows)}")

        # I20 — OUTBOX KEY COLLISION: the invite-delivery key is <slug>\x1f<handle> (un-forgeable, like the member
        # key), NOT <slug>:<handle>. ':' is well_formed, so under the OLD ':' key a crafted "<victim-slug>:<x>" slug
        # owner could clobber another org's delivery row. Org "a:b" (owner abo) invites "x"; org "a" (owner ao) invites
        # "b:x" — under ':' BOTH mapped to "a:b:x" (collision); under '\x1f' the two keys are DISTINCT.
        c.post("/orgs", json={"slug": "a:b"}, headers=H("abo"))
        c.post("/orgs", json={"slug": "a"}, headers=H("ao"))
        c.post("/orgs/a:b/members", json={"handle": "x", "role": "member"}, headers=H("abo"))
        c.post("/orgs/a/members", json={"handle": "b:x", "role": "member"}, headers=H("ao"))
        tok_ab, tok_a = invite_token("a:b", "x"), invite_token("a", "b:x")
        check("I20 the orgs_outbox key is \\x1f-joined (F2): two colon-crafted invites across different orgs keep "
              "DISTINCT delivery rows (no cross-tenant clobber) — each invitee gets their own token",
              bool(tok_ab) and bool(tok_a) and tok_ab != tok_a, f"tok_ab={bool(tok_ab)} tok_a={bool(tok_a)}")

        # I21 — NO-OWNER-ROW DEFENSE-IN-DEPTH: lock the org_role seam guard `role if role != 'owner' else None`. Ownership
        # is SINGLE-SOURCED in orgs_records.owner; an "owner" membership row must NEVER confer ownership. No handler emits
        # one (I11b/I18b prove the API never produces it), so we INJECT a hostile ACTIVE {role:'owner'} row DIRECTLY into
        # the store — a state no route can reach — and assert the seam refuses it (org_role -> None), while the real
        # records-owner still derives 'owner'. WITHOUT the guard the seam would read status=='active' + role=='owner' and
        # return 'owner' (a single dropped clause = a forged second owner); this catches that regression behaviorally.
        c.post("/orgs", json={"slug": "diorg"}, headers=H("downer"))         # downer is the real, single-source owner
        check("I21-pre the real records-owner derives 'owner' before the injection", org_role("diorg", "downer") == "owner")
        store.put("orgs_members", mkey("diorg", "mallory"),                  # a row NO handler can write: an ACTIVE owner row
                  {"org": "diorg", "handle": "mallory", "role": "owner", "status": "active"})
        check("I21a the org_role seam REFUSES an injected ACTIVE 'owner' membership row -> None (no forged second owner; "
              "the `role if role != 'owner' else None` defense-in-depth holds)",
              org_role("diorg", "mallory") is None, f"got {org_role('diorg', 'mallory')!r}")
        check("I21b the real records-owner STILL derives 'owner' (single-source orgs_records.owner is untouched)",
              org_role("diorg", "downer") == "owner")
        # a NON-owner active role on that same injected-row path is unaffected (the guard only refuses 'owner') — proves
        # the guard is surgical, not a blanket reject of injected rows.
        store.put("orgs_members", mkey("diorg", "mvalid"),
                  {"org": "diorg", "handle": "mvalid", "role": "admin", "status": "active"})
        check("I21c the guard is surgical: an injected ACTIVE 'admin' row still grants 'admin' (only 'owner' is refused)",
              org_role("diorg", "mvalid") == "admin", f"got {org_role('diorg', 'mvalid')!r}")

    # I2 — the slug race
    if os.getenv("DATABASE_PATH"):
        procs = [subprocess.Popen([sys.executable, "-c", RACE_WORKER], cwd=os.getcwd(),
                                  env={**os.environ, "LOG_LEVEL": "silent"},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for _ in range(2)]
        outs = []
        for p in procs:
            so, se = p.communicate(timeout=120)
            outs.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:200]))
        statuses = sorted(int(o) for rc, o in outs if rc == 0 and str(o).isdigit())
        check("I2 two processes racing one slug -> exactly one 201 and one 409", statuses == [201, 409], f"got {outs}")

        # I11 — THE TRANSFER RACE (the single-source-owner design): two processes, BOTH the current owner, transfer
        # concurrently to DIFFERENT new owners. The single-key atomic do() on orgs_records + the in-lock owner
        # re-check SERIALIZE them -> exactly one wins (200), the other's re-check fails (409). The OLD bare-put code
        # wrote BOTH 'owner' membership rows -> two owners (the F1 bug this proves closed).
        with TestClient(app, raise_server_exceptions=False) as c:
            c.post("/orgs", json={"slug": "raceorg"}, headers=H("racer"))    # racer owns raceorg
        tprocs = [subprocess.Popen([sys.executable, "-c", TRANSFER_WORKER, "raceorg", tgt, "racer"], cwd=os.getcwd(),
                                   env={**os.environ, "LOG_LEVEL": "silent"},
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                  for tgt in ("rbob", "rcarol")]
        touts = []
        for p in tprocs:
            so, se = p.communicate(timeout=120)
            touts.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:200]))
        tstatuses = sorted(int(o) for rc, o in touts if rc == 0 and str(o).isdigit())
        race_owner = (store.get("orgs_records", "raceorg") or {}).get("owner")
        # the rejection code is TIMING-DEPENDENT (both are correct): 409 = the loser passed authz then hit the in-lock
        # owner re-check; 403 = under load the winner finished first (demoting the old owner) so the loser fails the
        # orgsManager owner-check. The DETERMINISTIC invariant is "exactly ONE succeeds + exactly one owner" (I11b).
        check("I11 two concurrent transfers from one owner -> exactly ONE succeeds (200); the other is rejected (403/409)",
              len(tstatuses) == 2 and tstatuses[0] == 200 and tstatuses[1] in (403, 409), f"got {touts}")
        check("I11b EXACTLY ONE owner survives (orgs_records.owner is one target; the loser never became an owner — no "
              "membership row carries role 'owner')",
              race_owner in ("rbob", "rcarol")
              and member_role("raceorg", "rbob") != "owner"
              and member_role("raceorg", "rcarol") != "owner", f"owner={race_owner!r}")

        # I12 — transfer ‖ archive: archive must NOT clobber the owner (it reads the CURRENT record IN the lock).
        # The archiver is a STABLE admin (guard2), NOT the transferring owner. During a transfer the OUTGOING owner is
        # transiently roleless — ownership leaves orgs_records (do #1) BEFORE the old-owner admin row is written (do #3),
        # and two stores can't be one atomic do(): an OWNED, benign LOW (no escalation; the NEW owner holds full authority
        # throughout; the org is never ownerless). Archiving AS that outgoing owner would race its OWN demotion window (a
        # legitimate, load-sensitive transient 403) — which is NOT what I12 tests. A stable admin has org_role==admin
        # throughout, so its archive ALWAYS executes concurrently with the transfer's write: the real I12 property is that
        # the owner change is PRESERVED (owner=rbob2) AND the archive lands (archived) — neither in-lock do() clobbers the
        # other's field. (guard2 is untouched by the transfer, which only demotes racer2 + tombstones rbob2's prior row.)
        with TestClient(app, raise_server_exceptions=False) as c:
            c.post("/orgs", json={"slug": "raceorg2"}, headers=H("racer2"))
            c.post("/orgs/raceorg2/members", json={"handle": "guard2", "role": "admin"}, headers=H("racer2"))
            c.post("/orgs/raceorg2/members/accept", json={"token": invite_token("raceorg2", "guard2")}, headers=H("guard2"))
        mprocs = [
            subprocess.Popen([sys.executable, "-c", TRANSFER_WORKER, "raceorg2", "rbob2", "racer2"], cwd=os.getcwd(),
                             env={**os.environ, "LOG_LEVEL": "silent"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True),
            subprocess.Popen([sys.executable, "-c", ARCHIVE_WORKER, "raceorg2", "guard2"], cwd=os.getcwd(),
                             env={**os.environ, "LOG_LEVEL": "silent"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True),
        ]
        mouts = []
        for p in mprocs:
            so, se = p.communicate(timeout=120)
            mouts.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:200]))
        rec2 = store.get("orgs_records", "raceorg2") or {}
        archive_status = mouts[1][1] if len(mouts) > 1 else "?"
        check("I12 transfer || archive (stable-admin archiver): the owner change is PRESERVED (owner=rbob2) AND the "
              "concurrent archive lands (status archived, worker 200) — neither in-lock do() clobbers the other's field",
              rec2.get("owner") == "rbob2" and rec2.get("status") == "archived" and archive_status == "200",
              f"got {rec2} archive_worker={archive_status}")

        # I18 — TRANSFER-DEMOTION ‖ REMOVE(old owner). dman transfers drace -> dnew while an admin
        # (dadm) concurrently removes the OLD owner dman. Pre-fix, remove returned 200 "removed" (hard delete_) and the
        # demotion's bare put RE-CREATED dman as an active admin — a confirmed-removed member RESURRECTED. With BOTH
        # writes routed through the do() seam on the ONE member key, they SERIALIZE: the final state is a DETERMINISTIC
        # last-writer-wins (dman ends EITHER active 'admin' OR a 'removed' tombstone — never a torn/half-written row),
        # org_role agrees with that single row, and ownership is dnew regardless (the atomic swap is independent).
        with TestClient(app, raise_server_exceptions=False) as c:
            c.post("/orgs", json={"slug": "drace"}, headers=H("dman"))            # dman owns drace
            inv = c.post("/orgs/drace/members", json={"handle": "dadm", "role": "admin"}, headers=H("dman"))
            c.post("/orgs/drace/members/accept", json={"token": invite_token("drace", "dadm")}, headers=H("dadm"))
            check("I18-pre dadm is an ACTIVE admin who may remove members", org_role("drace", "dadm") == "admin")
        dprocs = [
            subprocess.Popen([sys.executable, "-c", TRANSFER_WORKER, "drace", "dnew", "dman"], cwd=os.getcwd(),
                             env={**os.environ, "LOG_LEVEL": "silent"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True),
            subprocess.Popen([sys.executable, "-c", REMOVE_WORKER, "drace", "dman", "dadm"], cwd=os.getcwd(),
                             env={**os.environ, "LOG_LEVEL": "silent"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True),
        ]
        douts = []
        for p in dprocs:
            so, se = p.communicate(timeout=120)
            douts.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:200]))
        drec = store.get("orgs_records", "drace") or {}
        dman_rec = member_rec("drace", "dman")
        dman_status = (dman_rec or {}).get("status")
        dman_role = org_role("drace", "dman")
        # CONVERGENCE: dman is EITHER an active admin (demotion last) OR a removed tombstone (remove last) — and
        # org_role is EXACTLY consistent with that one row (admin iff active, None iff removed/absent). No third state.
        converged = (
            (dman_status == "active" and dman_role == "admin")
            or (dman_status in ("removed", None) and dman_role is None))
        check("I18a transfer-demotion || remove(old owner) CONVERGES to ONE deterministic state "
              "(dman active-admin XOR removed-tombstone; org_role agrees; no resurrected/torn row)",
              converged, f"status={dman_status!r} role={dman_role!r} workers={douts}")
        check("I18b ownership is UNAFFECTED by the demotion race — the new owner is dnew, single-source, "
              "and no membership row ever carries role 'owner'",
              drec.get("owner") == "dnew" and member_role("drace", "dnew") != "owner"
              and member_role("drace", "dman") != "owner", f"owner={drec.get('owner')!r}")
    else:
        print("  [FAIL] I2 slug race NOT RUN — DATABASE_PATH unset")
        failures.append("I2 not run")

    print(f"ORGS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
