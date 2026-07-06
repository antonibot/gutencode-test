"""API_KEYS INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the python app (cwd =
<app>/python). Credited by EXIT CODE ONLY. The secret is shown once, so the issue->verify flow lives here.

OWNERSHIP — a key is USER-SCOPED: it belongs to the caller who created it. create/get/rotate/revoke require the core
identity seam and stamp/scope on the authenticated OWNER; /verify stays PUBLIC (the `ak_<id>_<secret>` key IS the
credential, checked before any session). Tokens come from the real session seam (register+login) under
APP_TEST_SESSIONS=1, exactly as tenancy proves its isolation.

Proves:  I0 deny-by-default — create/get/rotate/revoke are 401 without a valid bearer token; /verify is PUBLIC.
         I1 NO PLAINTEXT AT REST — the stored record holds a secret_hash and never the secret; no public
            response (create/get/rotate/revoke) leaks the hash OR the owner.
         I2 verify works for a freshly issued key and returns its scopes; a wrong secret for a REAL id is
            {valid:false} (non-enumerable: same shape as an unknown id). /verify needs NO token.
         I3 ROTATION invalidates the old secret — the pre-rotation key verifies false, the new one true, the
            scopes are preserved.
         I4 REVOCATION is monotonic — a revoked key verifies false forever; re-revoking is stable.
         I5 unknown id, wrong secret, and garbage key are all the same {valid:false, scopes:[]}.
         I6 strict input.
         I7 USER-SCOPED / CROSS-OWNER-404 — a second caller (real token) cannot get/rotate/revoke another owner's
            key id: each is 404, byte-identical to a missing id (existence never leaks over the enumerable id), and
            the owner's key is UNTOUCHED (still verifies, never rotated/revoked by the stranger). The owner-stamp is
            the TOKEN's: a smuggled `owner` in the create body cannot override it.
         I8 OWNER-SCOPED LIST (the new read surface) — a SEMANTIC cross-owner proof: with TWO owners that each hold
            keys, GET /api_keys returns ONLY the caller's keys (walked cursor-to-EXHAUSTION, never page-1-only),
            never the secret_hash/owner; a caller with no keys gets an empty page (never 403); anonymous is 401; the
            response is the bounded {results, next_cursor} envelope (never an unbounded bare array).
         I9 created_at — every key carries created_at (seconds, from the core clock seam), identical across the
            create / get / list views (rotation re-mints the secret but PRESERVES the birth time)."""
import os
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # the `test:` bearer + real register/login resolve only under this seam

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

        def verify(key):  # /verify is PUBLIC — no token
            return c.post("/api_keys/verify", json={"key": key}).json()

        ta, tb = token_for("alice"), token_for("bob")

        # I0 — deny-by-default on the management ops; /verify is PUBLIC
        check("I0a create no token -> 401", c.post("/api_keys", json={"name": "x", "scopes": ["r"]}).status_code == 401)
        check("I0b get no token -> 401", c.get("/api_keys/1").status_code == 401)
        check("I0c rotate no token -> 401", c.post("/api_keys/1/rotate", json={}).status_code == 401)
        check("I0d revoke no token -> 401", c.post("/api_keys/1/revoke", json={}).status_code == 401)
        check("I0e forged token -> 401", c.get("/api_keys/1", headers={"Authorization": "Bearer deadbeef"}).status_code == 401)
        check("I0f malformed scheme -> 401", c.get("/api_keys/1", headers={"Authorization": ta}).status_code == 401)
        check("I0g /verify is PUBLIC (200 without any token)",
              c.post("/api_keys/verify", json={"key": "garbage"}).status_code == 200)

        issued = c.post("/api_keys", json={"name": "ci", "scopes": ["read", "write"]}, headers=H(ta)).json()
        key = issued["key"]

        # I1 — no plaintext at rest; the public views leak neither the hash NOR the owner
        rec = store.get("api_keys_records", str(issued["id"]))
        # the key is `ak_<id>_<secret>`; token_urlsafe secrets CAN contain '_', so split from the LEFT (maxsplit=2)
        # to recover the WHOLE secret. rsplit("_",1) would yield only the tail after the last '_', and a short tail
        # can coincidentally appear in str(rec.values()) (the hex secret_hash or a field like 'active') — a ~2%/run
        # false failure. The full 32-char secret can never be a substring of any stored value.
        secret = key.split("_", 2)[2]
        check("I1a the store holds a secret_hash, not the secret",
              "secret_hash" in rec and "secret" not in rec and secret not in str(rec.values()))
        check("I1b the store record carries the owner (the authenticated subject)", rec.get("owner") == "alice")
        got = c.get(f"/api_keys/{issued['id']}", headers=H(ta)).json()
        check("I1c create/get responses never leak the hash or the owner",
              "secret_hash" not in issued and "owner" not in issued
              and "secret_hash" not in got and "owner" not in got)

        # I2 — verify the real key; a wrong secret on the SAME id is false
        v = verify(key)
        check("I2a a freshly issued key verifies with its scopes",
              v == {"valid": True, "scopes": ["read", "write"]})
        check("I2b a wrong secret for a real id -> {valid:false}",
              verify(f"ak_{issued['id']}_wrongsecret") == {"valid": False, "scopes": []})

        # I3 — rotation invalidates the old secret
        rotated = c.post(f"/api_keys/{issued['id']}/rotate", json={}, headers=H(ta)).json()
        check("I3a rotation returns a NEW key", rotated["key"] != key)
        check("I3b the OLD key no longer verifies", verify(key)["valid"] is False)
        check("I3c the NEW key verifies with the SAME scopes",
              verify(rotated["key"]) == {"valid": True, "scopes": ["read", "write"]})

        # I4 — revocation is monotonic
        c.post(f"/api_keys/{issued['id']}/revoke", json={}, headers=H(ta))
        check("I4a a revoked key verifies false", verify(rotated["key"])["valid"] is False)
        re = c.post(f"/api_keys/{issued['id']}/revoke", json={}, headers=H(ta))
        check("I4b re-revoking is stable", re.status_code == 200 and re.json()["status"] == "revoked")
        check("I4c still false after re-revoke", verify(rotated["key"])["valid"] is False)

        # I5 — non-enumeration: unknown id, wrong secret, garbage all identical (PUBLIC verify)
        outcomes = [verify("ak_999999_x"), verify("ak_1_definitelywrong"), verify("garbage"),
                    verify("ak_only_two")]
        check("I5 unknown id / wrong secret / garbage are all the same denial",
              all(o == {"valid": False, "scopes": []} for o in outcomes), f"got {outcomes}")

        # I6 — strict input (owner-scoped routes; alice's token)
        check("I6a non-numeric id -> 422", c.get("/api_keys/abc", headers=H(ta)).status_code == 422)
        for bad in ({"scopes": ["r"]}, {"name": "", "scopes": ["r"]}, {"name": "x"}, {"name": "x", "scopes": "r"},
                    {"name": "x", "scopes": [7]}, {"name": "x", "scopes": [""]}):
            check(f"I6b invalid create {bad!r} -> 422", c.post("/api_keys", json=bad, headers=H(ta)).status_code == 422)
        for bad in ({}, {"key": ""}):
            check(f"I6c invalid verify {bad!r} -> 422", c.post("/api_keys/verify", json=bad).status_code == 422)

        # I7 — USER-SCOPED / cross-owner-404: bob cannot touch alice's key, and alice's key survives intact.
        a_key = c.post("/api_keys", json={"name": "secret-svc", "scopes": ["read"]}, headers=H(ta)).json()
        a_id = a_key["id"]
        hash_before = store.get("api_keys_records", str(a_id))["secret_hash"]   # snapshot BEFORE bob's attempts
        missing = c.post("/api_keys/999999/rotate", json={}, headers=H(tb))
        x_get = c.get(f"/api_keys/{a_id}", headers=H(tb))
        x_rot = c.post(f"/api_keys/{a_id}/rotate", json={}, headers=H(tb))
        x_rev = c.post(f"/api_keys/{a_id}/revoke", json={}, headers=H(tb))
        check("I7a cross-owner GET is 404 (never 403, never the record)", x_get.status_code == 404)
        check("I7b cross-owner ROTATE is 404", x_rot.status_code == 404)
        check("I7c cross-owner REVOKE is 404", x_rev.status_code == 404)
        check("I7d cross-owner 404 == missing 404 (existence does not leak over the enumerable id)",
              x_rot.json() == missing.json())
        check("I7e the 404 never carries the owner's record (name/prefix/owner absent from the body)",
              b"secret-svc" not in x_get.content and a_key["prefix"].encode() not in x_get.content
              and b"alice" not in x_get.content)
        check("I7f alice's key is UNTOUCHED — still verifies after bob's failed rotate/revoke",
              verify(a_key["key"]) == {"valid": True, "scopes": ["read"]})
        rec_after = store.get("api_keys_records", str(a_id))
        check("I7g bob never rotated/revoked alice's key (secret_hash + status unchanged)",
              rec_after["secret_hash"] == hash_before and rec_after["status"] == "active")
        # the owner-stamp is the TOKEN's: a smuggled body owner cannot win
        smug = c.post("/api_keys", json={"name": "spoof", "scopes": ["r"], "owner": "bob"}, headers=H(ta))
        if smug.status_code == 201:
            srec = store.get("api_keys_records", str(smug.json()["id"]))
            check("I7h smuggled body owner ignored (stamp is the token's)", srec["owner"] == "alice")
            check("I7i bob cannot read the smuggled-owner row", c.get(f"/api_keys/{smug.json()['id']}", headers=H(tb)).status_code == 404)
        else:
            check("I7h smuggled owner rejected outright", smug.status_code == 422)

        # I8 — OWNER-SCOPED LIST, a SEMANTIC cross-owner proof (a presence-level filter check is a heuristic; this
        # invariant is the correctness backstop). TWO owners each hold keys;
        # each LIST returns ONLY that owner's keys, walked cursor-to-EXHAUSTION (not page-1-only).
        def list_all(token):
            out, cursor, guard = [], "", 0
            while True:
                pg = c.get(f"/api_keys?limit=1&cursor={cursor}", headers=H(token)).json()
                out += pg["results"]
                cursor = pg["next_cursor"]
                guard += 1
                if not cursor or guard > 50:
                    break
            return out

        b_key = c.post("/api_keys", json={"name": "bob-key", "scopes": ["read"]}, headers=H(tb)).json()
        a_list, b_list = list_all(ta), list_all(tb)
        a_ids, b_ids = {k["id"] for k in a_list}, {k["id"] for k in b_list}
        check("I8a alice's LIST holds alice's keys", {issued["id"], a_id} <= a_ids, f"got {a_ids}")
        check("I8b bob's LIST holds ONLY bob's key — alice's ids ABSENT (cross-owner isolation, walked to exhaustion)",
              b_ids == {b_key["id"]} and not (a_ids & b_ids), f"got a={a_ids} b={b_ids}")
        check("I8c the LIST body NEVER carries the secret_hash OR owner",
              all("secret_hash" not in k and "owner" not in k for k in a_list + b_list))
        tc = token_for("carol")  # a fresh caller with NO keys -> an empty page, never 403/404 (non-enumerable)
        check("I8d a caller with no keys gets an empty page, never 403",
              c.get("/api_keys", headers=H(tc)).json() == {"results": [], "next_cursor": None})
        check("I8e anonymous LIST -> 401 (deny-by-default)", c.get("/api_keys").status_code == 401)
        check("I8f the LIST is BOUNDED — the {results, next_cursor} envelope, never a bare array",
              isinstance(c.get("/api_keys", headers=H(ta)).json().get("results"), list))

        # I9 — created_at: every key carries it (seconds), identical across the create / get / list views
        k9 = c.post("/api_keys", json={"name": "stamp", "scopes": ["read"]}, headers=H(ta)).json()
        check("I9a create returns created_at as an int (seconds)", isinstance(k9.get("created_at"), int), f"got {k9}")
        g9 = c.get(f"/api_keys/{k9['id']}", headers=H(ta)).json()
        check("I9b get returns the SAME created_at", g9.get("created_at") == k9["created_at"])
        l9 = [x for x in list_all(ta) if x["id"] == k9["id"]]
        check("I9c the LIST carries the SAME created_at", len(l9) == 1 and l9[0]["created_at"] == k9["created_at"])
        r9 = c.post(f"/api_keys/{k9['id']}/rotate", json={}, headers=H(ta)).json()
        check("I9d rotation PRESERVES created_at — re-mints the secret, NOT the birth time",
              r9["created_at"] == k9["created_at"] and r9["key"] != k9["key"], f"got {r9}")

    print(f"API_KEYS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
