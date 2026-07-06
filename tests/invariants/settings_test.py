"""SETTINGS INVARIANTS — owner scoping keyed to the AUTHENTICATED identity (the core require_identity seam),
NOT a path param or a caller-supplied owner. Run against the python app (cwd=<app>/python; the app includes auth —
settings `requires` it). Credited by EXIT CODE ONLY.

Proves:  I1 deny-by-default — every route is 401 without a valid bearer token (no / malformed / forged).
         I2 TYPE SAFETY — for every key, every WRONG-typed value (cross-type, plus the classic traps: '20'
            string for int, true for int, 1 for bool, 50.0 float for int) is 422 and the stored value is UNCHANGED.
         I3 COMPLETENESS — a fresh owner reads EVERY known key at its declared default; after a valid set, the
            list reflects the override while other keys stay at default.
         I4 owner scoping — one owner's overrides never appear for another owner, keyed by REAL tokens (alice's
            'dark' theme is invisible to bob, who still sees the default).
         I5 deny-by-default keys — an unknown key is 422 on PUT and 404 on GET.
         I6 the owner stamp is the TOKEN's — there is no owner path param, and a smuggled `owner` in the request
            body cannot redirect a write to another identity (it lands under the caller, the token's subject)."""
import os
import sys

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402
from app_pkg.core import store  # noqa: E402

failures = []

DEFAULTS = {"notifications_enabled": True, "items_per_page": 20, "theme": "light"}


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

        def put(t, key, value, extra=None):
            return c.put(f"/settings/{key}", json={"value": value, **(extra or {})}, headers=H(t))

        def getone(t, key):
            return c.get(f"/settings/{key}", headers=H(t)).json()["value"]

        ta, tb = token_for("alice"), token_for("bob")

        # I1 — deny-by-default: a valid bearer token is required on every route
        check("I1a GET list no token -> 401", c.get("/settings").status_code == 401)
        check("I1b GET one no token -> 401", c.get("/settings/theme").status_code == 401)
        check("I1c PUT no token -> 401", c.put("/settings/theme", json={"value": "dark"}).status_code == 401)
        check("I1d forged token -> 401", c.get("/settings", headers={"Authorization": "Bearer deadbeef"}).status_code == 401)
        check("I1e malformed scheme -> 401", c.get("/settings", headers={"Authorization": ta}).status_code == 401)

        # I3 — completeness at defaults (fresh owner)
        check("I3a fresh owner reads all defaults", c.get("/settings", headers=H(ta)).json() == DEFAULTS)

        # I2 — type safety: the wrong-type matrix, each must 422 AND leave the value unchanged
        wrong = {
            "items_per_page": ["20", 1.5, 50.0, True, "x", [1]],   # int rejects string/float/bool/list
            "notifications_enabled": ["yes", 1, 0, "true"],        # bool rejects string/int
            "theme": [7, True, 1.5, ["x"]],                        # string rejects number/bool/list
        }
        for key, bads in wrong.items():
            before = getone(ta, key)
            for bad in bads:
                check(f"I2 {key} rejects {bad!r} (422)", put(ta, key, bad).status_code == 422)
            check(f"I2 {key} value unchanged after rejected writes", getone(ta, key) == before)

        # valid writes of each type land for alice
        check("I2b valid int lands", put(ta, "items_per_page", 50).json()["value"] == 50)
        check("I2c valid bool lands", put(ta, "notifications_enabled", False).json()["value"] is False)
        check("I2d valid string lands", put(ta, "theme", "dark").json()["value"] == "dark")
        check("I3b list reflects overrides over defaults",
              c.get("/settings", headers=H(ta)).json() == {"notifications_enabled": False, "items_per_page": 50, "theme": "dark"})

        # I4 — owner scoping by REAL token: alice's overrides are invisible to bob
        check("I4a a different owner still sees all defaults", c.get("/settings", headers=H(tb)).json() == DEFAULTS)
        check("I4b bob's point read is the default, never alice's override", getone(tb, "theme") == "light")
        check("I4c alice still sees her own override (no cross-contamination)", getone(ta, "theme") == "dark")

        # I5 — deny-by-default keys
        check("I5a unknown key PUT -> 422", put(ta, "rocket_fuel", "x").status_code == 422)
        check("I5b unknown key GET -> 404", c.get("/settings/rocket_fuel", headers=H(ta)).status_code == 404)

        # I6 — the owner stamp is the TOKEN's: a smuggled body `owner` cannot redirect the write to bob
        sneaky = put(ta, "items_per_page", 7, extra={"owner": "bob"})
        check("I6a smuggled body owner ignored — write succeeds as the caller", sneaky.status_code == 200)
        check("I6b the write landed under alice (the token), not bob", getone(ta, "items_per_page") == 7)
        check("I6c bob is untouched by alice's smuggle attempt", getone(tb, "items_per_page") == 20)

        # I6d — durable seam: the override is stored under the composite key owner\x1fkey (owner = the subject)
        check("I6d row persisted in the store seam under the authenticated owner",
              store.get("settings_overrides", "alice\x1ftheme") == "dark")

    print(f"SETTINGS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
