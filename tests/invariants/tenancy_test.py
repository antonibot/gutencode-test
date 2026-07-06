"""TENANCY INVARIANTS — tenant isolation keyed to the AUTHENTICATED identity (the core require_identity seam),
NOT a client-supplied header. Run against the python app (cwd=<app>/python; the app includes auth — tenancy
`requires` it). Credited by EXIT CODE ONLY.

Proves:  I1 deny-by-default — every route is 401 without a valid bearer token (no / malformed / forged).
         I2 point-read isolation — a cross-tenant read (another user's REAL token) is 404, byte-identical to a
            missing row; the body never carries the other tenant's content.
         I3 list isolation — a tenant's list is EXACTLY its own rows, keyed by its real token.
         I4 the tenant stamp is the TOKEN's — a smuggled `tenant` in the request body cannot override it.
         I5 the spoof vector is CLOSED — an X-Tenant-Id header is IGNORED; the tenant comes only from the token.
         I6 durable — rows persist carrying their tenant.
         I7 the list is BOUNDED — pagination caps the page within the caller's OWN tenant; the opaque cursor
            round-trips to the next page and stays owner-scoped; a malformed cursor/limit is 422 (never a full
            unbounded dump, never another tenant's rows).
         I8 tenant IMMUTABILITY — a row's tenant is stamped ONCE at create and can never be re-homed: no UPDATE/DELETE
            surface exists, and no client write reaches a stored row's tenant after create (the lifecycle extension of
            I4; the references' TenantIsImmutable / @TenantId-read-only convergence; ASVS 4.2.1)."""
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
        def token_for(u):
            c.post("/auth/register", json={"email": u, "password": f"pw-{u}-1234"})
            return c.post("/auth/login", json={"email": u, "password": f"pw-{u}-1234"}).json()["access_token"]

        def H(t):
            return {"Authorization": f"Bearer {t}"}

        ta, tb = token_for("alice"), token_for("bob")

        # I1 — deny-by-default: a valid bearer token is required on every route
        check("I1a POST no token -> 401", c.post("/tenancy/notes", json={"body": "x"}).status_code == 401)
        check("I1b GET list no token -> 401", c.get("/tenancy/notes").status_code == 401)
        check("I1c forged token -> 401", c.get("/tenancy/notes", headers={"Authorization": "Bearer deadbeef"}).status_code == 401)
        check("I1d malformed scheme -> 401", c.get("/tenancy/notes", headers={"Authorization": ta}).status_code == 401)

        # rows under two tenants, keyed by REAL tokens
        r1 = c.post("/tenancy/notes", json={"body": "alpha-secret"}, headers=H(ta))
        r2 = c.post("/tenancy/notes", json={"body": "beta"}, headers=H(tb))
        check("setup: both 201 + stamped to the token's identity",
              r1.status_code == 201 and r1.json()["tenant"] == "alice" and r2.json()["tenant"] == "bob")
        id1, id2 = r1.json()["id"], r2.json()["id"]

        # I2 — point-read isolation
        own = c.get(f"/tenancy/notes/{id1}", headers=H(ta))
        cross = c.get(f"/tenancy/notes/{id1}", headers=H(tb))
        missing = c.get("/tenancy/notes/999999", headers=H(tb))
        check("I2a own row reads 200", own.status_code == 200)
        check("I2b cross-tenant read is 404 (never 403, never the row)", cross.status_code == 404)
        check("I2c cross-tenant 404 == missing 404 (same body, existence does not leak)", cross.json() == missing.json())
        check("I2d the 404 never carries the other tenant's content", b"alpha-secret" not in cross.content)
        check("I2e symmetric: alice cannot read bob's row", c.get(f"/tenancy/notes/{id2}", headers=H(ta)).status_code == 404)

        # I3 — list isolation: exactly your rows (the page is the {results, next_cursor} envelope)
        c.post("/tenancy/notes", json={"body": "alpha-two"}, headers=H(ta))
        l1 = c.get("/tenancy/notes", headers=H(ta)).json()["results"]
        l2 = c.get("/tenancy/notes", headers=H(tb)).json()["results"]
        check("I3a alice's list is exactly her 2 rows", len(l1) == 2 and all(r["tenant"] == "alice" for r in l1))
        check("I3b bob's list is exactly his 1 row", len(l2) == 1 and all(r["tenant"] == "bob" for r in l2))
        check("I3c no row appears in both lists", not ({r["id"] for r in l1} & {r["id"] for r in l2}))

        # I4 — the stamp is the TOKEN's: a smuggled body tenant must NOT win
        smug = c.post("/tenancy/notes", json={"body": "spoof", "tenant": "bob"}, headers=H(ta))
        if smug.status_code == 201:
            check("I4 smuggled body tenant ignored (stamp is the token's)", smug.json()["tenant"] == "alice")
            check("I4b the spoofed row is invisible to bob",
                  not any(r["body"] == "spoof" for r in c.get("/tenancy/notes", headers=H(tb)).json()["results"]))
        else:
            check("I4 smuggled tenant rejected outright", smug.status_code == 422)

        # I5 — the spoof vector is CLOSED: an X-Tenant-Id header cannot override the token identity. The list is
        # IDENTICAL with or without the bogus header (it is simply ignored), and every row is still alice's.
        with_hdr = c.get("/tenancy/notes", headers={**H(ta), "X-Tenant-Id": "bob"}).json()["results"]
        without = c.get("/tenancy/notes", headers=H(ta)).json()["results"]
        check("I5 X-Tenant-Id is IGNORED — alice's list is identical with/without it, and all rows are hers",
              with_hdr == without and all(r["tenant"] == "alice" for r in with_hdr))

        # I6 — durable seam, the tenant on the stored row itself
        stored = store.get("tenancy_notes", str(id1))
        check("I6 row persisted in the store seam, carrying its tenant", stored is not None and stored["tenant"] == "alice")

        # I7 — BOUNDED list + owner-scoped pagination. Add rows so alice has >=3, then prove the page walk is bounded,
        # owner-scoped, and the opaque cursor round-trips: paging with limit=1 reconstructs EXACTLY alice's own list
        # in the same stable order (no dup/skip) and terminates (next_cursor null) — and never reaches bob's row.
        for body in ("alpha-three", "alpha-four"):
            c.post("/tenancy/notes", json={"body": body}, headers=H(ta))
        full = c.get("/tenancy/notes?limit=200", headers=H(ta)).json()   # ground truth: alice's whole owner-scoped list
        check("I7a the full owner-scoped page is alice-only and >=3 rows",
              len(full["results"]) >= 3 and all(r["tenant"] == "alice" for r in full["results"]))
        page1 = c.get("/tenancy/notes?limit=1", headers=H(ta)).json()
        check("I7b page 1 is bounded to the limit (1) + carries a forward cursor, still owner-scoped",
              len(page1["results"]) == 1 and bool(page1["next_cursor"]) and page1["results"][0]["tenant"] == "alice")
        walked, cursor, guard = [], "", 0
        while True:
            j = c.get(f"/tenancy/notes?limit=1&cursor={cursor}" if cursor else "/tenancy/notes?limit=1", headers=H(ta)).json()
            assert all(r["tenant"] == "alice" for r in j["results"]), "a page leaked across the tenant boundary"
            walked.extend(j["results"])
            if not j["next_cursor"]:
                break
            cursor, guard = j["next_cursor"], guard + 1
            assert guard < 1000, "cursor walk did not terminate"
        check("I7c the cursor walk reconstructs EXACTLY alice's list in stable order (no dup/skip, terminates)",
              walked == full["results"])
        bob_ids = {r["id"] for r in c.get("/tenancy/notes", headers=H(tb)).json()["results"]}
        check("I7d no page ever leaks across the tenant boundary (bob's row unreachable from alice's cursor)",
              not ({r["id"] for r in walked} & bob_ids))
        check("I7e a malformed cursor -> 422 (not a silent full dump)",
              c.get("/tenancy/notes?cursor=MDU", headers=H(ta)).status_code == 422)
        check("I7f limit < 1 -> 422", c.get("/tenancy/notes?limit=0", headers=H(ta)).status_code == 422)
        check("I7g limit clamps to max (bounded, not an error)",
              c.get("/tenancy/notes?limit=9999", headers=H(ta)).status_code == 200)

        # I8 — tenant IMMUTABILITY (the lifecycle extension of I4). A row's tenant is stamped ONCE at create from the
        # token and can NEVER be re-homed: there is no UPDATE/DELETE surface to change it, and no client input reaches
        # a stored row's tenant after create. Grounded in the convergent references (acts_as_tenant TenantIsImmutable,
        # django-multitenant NotSupportedError, Hibernate @TenantId read-only) + Postgres UPDATE USING+WITH CHECK +
        # ASVS 4.2.1. When an UPDATE/DELETE route is added it MUST re-prove this (UPDATE with a WITH-CHECK-style tenant
        # assertion, DELETE owner-scoped) — see docs/build/domains/tenancy/INTEROP.md.
        iid = c.post("/tenancy/notes", json={"body": "immutable-me"}, headers=H(ta)).json()["id"]
        check("I8a the row is stamped with the create-time token's tenant",
              store.get("tenancy_notes", str(iid))["tenant"] == "alice")
        notes_verbs = set()
        for rt in app.routes:
            if getattr(rt, "path", "").startswith("/tenancy/notes"):
                notes_verbs |= (getattr(rt, "methods", None) or set())
        check("I8b no UPDATE/DELETE route exists on the resource — there is no re-home surface",
              not (notes_verbs & {"PUT", "PATCH", "DELETE"}), f"found mutating verbs: {sorted(notes_verbs)}")
        c.post("/tenancy/notes", json={"body": "steal", "tenant": "alice"}, headers=H(tb))   # bob's smuggled-tenant write
        check("I8c another caller cannot re-home alice's row (still alice's after bob's smuggled-tenant write)",
              store.get("tenancy_notes", str(iid))["tenant"] == "alice")

    print(f"TENANCY INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
