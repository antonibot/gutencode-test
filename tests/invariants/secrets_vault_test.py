"""SECRETS_VAULT INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the python app (cwd =
<app>/python; DATABASE_PATH set by the harness). Credited by EXIT CODE ONLY.

Proves:  I1 VERSION IMMUTABILITY — after many rotations, reveal(version=N) still returns EXACTLY the bytes
            written at N; rotation only adds versions, never mutates an old one.
         I2 NO LEAK — neither the metadata read nor the name list ever contains a secret value; only reveal
            returns it (white-box: the value lives in the versions namespace, not in meta). The name list is also
            BOUNDED through the shared paginate seam (limit-honouring page + a cursor that round-trips), so a large
            vault can't be dumped in one unbounded response — and pagination never widens the names-only contract.
         I3 THE VERSION RACE — two processes writing the same name concurrently get DISTINCT sequential
            versions; both values are retrievable; current advances to the max.
         I4 unknown name / unknown version -> 404; default reveal returns the current version.
         I5 strict input.
         I11 AT-REST SEAL — with SECRETS_VAULT_KEK set the stored bytes are AES-256-GCM ciphertext (not the
            plaintext), reveal round-trips exactly, a wrong key fails LOUD, the name+version AAD binds a blob to its
            slot (a relocated blob won't unseal), and DESTROY scrubs the cipher row. (I6-I10 lifecycle/audit/anti-
            relocation are proven inline below.)"""
import os
import subprocess
import sys

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.core import store  # noqa: E402
from app_pkg.app import app  # noqa: E402

failures = []

# secrets_vault is ADMIN-ONLY: enable the test-session seam (Bearer test:<subject>, inert in prod) and send
# every request as the inert test admin 'root'. The white-box store reads below are direct and need no auth.
os.environ["APP_TEST_SESSIONS"] = "1"
ADMIN = {"Authorization": "Bearer test:root"}


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


RACE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
with TestClient(app, raise_server_exceptions=False, headers={"Authorization": "Bearer test:root"}) as c:
    r = c.put("/secrets_vault/raced", json={"value": sys.argv[1]})
    print(r.json()["version"] if r.status_code == 201 else f"status={r.status_code}")
"""


def main():
    with TestClient(app, raise_server_exceptions=False, headers=ADMIN) as c:
        def put(name, value):
            return c.put(f"/secrets_vault/{name}", json={"value": value})

        def reveal(name, version=None):
            return c.post(f"/secrets_vault/{name}/reveal", json={} if version is None else {"version": version})

        # I1 — version immutability across rotations
        values = [f"value-{i}" for i in range(1, 6)]
        for v in values:
            put("api_token", v)
        for i, v in enumerate(values, start=1):
            r = reveal("api_token", i)
            check(f"I1 version {i} still reveals its original bytes", r.json()["value"] == v, f"got {r.json()}")
        check("I1b default reveal returns the latest version", reveal("api_token").json()["value"] == values[-1])
        check("I1c metadata reports the current version", c.get("/secrets_vault/api_token").json()["current_version"] == 5)

        # I2 — no leak
        meta = c.get("/secrets_vault/api_token").json()
        check("I2a metadata read carries NO value", "value" not in meta and set(meta) == {"name", "current_version"})
        listing = c.get("/secrets_vault").json()
        names = listing["results"]   # paginated shape: {results: [...names...], next_cursor: ...}
        check("I2b the name list is names only", "api_token" in names and all(isinstance(x, str) for x in names))
        # NO LEAK through the listing: every secret's bytes ever written must be ABSENT from the whole envelope
        leaked = [v for v in values + ["v6-secret"] if v in str(listing)]
        check("I2b-noleak the listing never exposes a secret value", leaked == [], f"leaked {leaked}")
        put_resp = put("api_token", "v6-secret").json()
        check("I2c the PUT response never echoes the value", "value" not in put_resp)
        # white-box: the value is in the versions namespace, the meta row has no value
        check("I2d white-box: meta holds no value", "value" not in store.get("secrets_vault_meta", "api_token"))

        # I2e — the name list is BOUNDED through the shared paginate seam: with >1 secret, limit=1 yields exactly
        # one name + a cursor that round-trips to a DISJOINT next page, the two pages cover the whole set in stable
        # sorted order, and a malformed cursor/limit is rejected (422). Pagination never widens the names-only output.
        put("zzz_late", "v-late")   # ensure >= 2 distinct names so the round-trip is real and deterministic
        all_names = c.get("/secrets_vault").json()["results"]
        check("I2e the full listing is in stable sorted order", all_names == sorted(all_names), f"got {all_names}")
        check("I2e the full listing carries >= 2 names", len(all_names) >= 2, f"got {all_names}")
        p1 = c.get("/secrets_vault?limit=1").json()
        check("I2e bounded page honours limit=1", len(p1["results"]) == 1 and p1["results"][0] == all_names[0], f"got {p1}")
        check("I2e a next_cursor is issued when more remain", bool(p1["next_cursor"]), f"got {p1}")
        p2 = c.get(f"/secrets_vault?limit=1&cursor={p1['next_cursor']}").json()
        check("I2e the cursor round-trips to a disjoint next page",
              p2["results"] == [all_names[1]] and p2["results"][0] != p1["results"][0], f"p1={p1} p2={p2}")
        check("I2e paginated pages are still names-only strings (no value widening)",
              all(isinstance(x, str) for x in p1["results"] + p2["results"]) and
              not any(v in str(p1) + str(p2) for v in values + ["v6-secret", "v-late"]), f"p1={p1} p2={p2}")
        check("I2e malformed cursor -> 422", c.get("/secrets_vault?cursor=MQ%3D%3D").status_code == 422)
        check("I2e malformed limit -> 422", c.get("/secrets_vault?limit=0").status_code == 422)

        # I4 — 404s + default
        check("I4a unknown name meta -> 404", c.get("/secrets_vault/ghost").status_code == 404)
        check("I4b unknown name reveal -> 404", reveal("ghost").status_code == 404)
        check("I4c unknown version -> 404", reveal("api_token", 999).status_code == 404)

        # I5 — strict input
        for bad in ({}, {"value": ""}, {"value": 7}):
            check(f"I5a invalid put {bad!r} -> 422", c.put("/secrets_vault/api_token", json=bad).status_code == 422)
        for bad in ({"version": 0}, {"version": "two"}, {"version": -1}):
            check(f"I5b invalid reveal {bad!r} -> 422",
                  c.post("/secrets_vault/api_token/reveal", json=bad).status_code == 422)

        ALICE = {"Authorization": "Bearer test:alice"}  # a valid identity that is NOT admin (per-request override)

        # I6 — DESTROY (irreversible): reveal -> 404; the bytes are GONE from the store; metadata shows 'destroyed';
        # the current version still reveals; a destroyed version can't be re-enabled. (The on-disk secure_delete SCRUB
        # is sqlite/WAL/OS-sensitive, so it is not asserted in this deterministic suite.)
        put("destroyme", "destroy-AAA")
        put("destroyme", "destroy-BBB")   # v2 = current
        d = c.post("/secrets_vault/destroyme/destroy", json={"version": 1})
        check("I6a destroy returns the 'destroyed' state", d.status_code == 200 and d.json().get("state") == "destroyed", f"got {d.json()}")
        check("I6b a destroyed version reveals 404", c.post("/secrets_vault/destroyme/reveal", json={"version": 1}).status_code == 404)
        check("I6b white-box: the destroyed version's bytes are gone", store.get("secrets_vault_versions", "destroyme\x1f1") is None)
        check("I6c metadata exposes the destroyed state", c.get("/secrets_vault/destroyme").json().get("states", {}).get("1") == "destroyed")
        check("I6d the current version still reveals", c.post("/secrets_vault/destroyme/reveal", json={}).json().get("value") == "destroy-BBB")
        check("I6e a destroyed version can't be re-enabled (404)", c.post("/secrets_vault/destroyme/enable", json={"version": 1}).status_code == 404)

        # I7 — DISABLE / ENABLE (reversible): a disabled version reveals 404 but its bytes are KEPT; enable restores it.
        put("toggle", "toggle-secret")
        check("I7a disable hides the version", c.post("/secrets_vault/toggle/disable", json={"version": 1}).status_code == 200)
        check("I7b a disabled version reveals 404", c.post("/secrets_vault/toggle/reveal", json={"version": 1}).status_code == 404)
        check("I7c white-box: a disabled version's bytes are KEPT", store.get("secrets_vault_versions", "toggle\x1f1") == "toggle-secret")
        check("I7d enable restores reveal", c.post("/secrets_vault/toggle/enable", json={"version": 1}).status_code == 200)
        check("I7e the re-enabled value is intact", c.post("/secrets_vault/toggle/reveal", json={"version": 1}).json().get("value") == "toggle-secret")

        # I8 — max_versions PRUNE: past the cap, the OLDEST version is evicted (reveal 404 + bytes gone); within-cap survives.
        os.environ["SECRETS_VAULT_MAX_VERSIONS"] = "2"
        for v in ("p1", "p2", "p3"):   # cap=2: writing p3 evicts version 1
            put("pruneme", v)
        check("I8a a pruned (evicted) version reveals 404", c.post("/secrets_vault/pruneme/reveal", json={"version": 1}).status_code == 404)
        check("I8b white-box: the pruned version's bytes are gone", store.get("secrets_vault_versions", "pruneme\x1f1") is None)
        check("I8c versions within the cap still reveal", c.post("/secrets_vault/pruneme/reveal", json={"version": 2}).json().get("value") == "p2")
        check("I8d the current version reveals", c.post("/secrets_vault/pruneme/reveal", json={}).json().get("value") == "p3")
        del os.environ["SECRETS_VAULT_MAX_VERSIONS"]   # restore the default for the I3 race subprocess (inherits the env)

        # I9 — ACCESS AUDIT (domain-local, AU-3): 'all' logs a reveal with {actor,action,name,version,outcome,at,source}
        # and NEVER the value; the default 'deny' still logs a FAILED (403) access; GET /access is admin-only + value-free.
        os.environ["APP_SECRETS_VAULT_AUDIT"] = "all"
        before = len(store.values("secrets_vault_access"))
        c.post("/secrets_vault/api_token/reveal", json={"version": 1})
        rows = store.values("secrets_vault_access")
        check("I9a a reveal appends one audit row", len(rows) == before + 1, f"{before}->{len(rows)}")
        last = rows[-1] if rows else {}
        check("I9b the row carries the AU-3 fields", set(last) >= {"actor", "action", "name", "version", "outcome", "at", "source"}, f"got {last}")
        check("I9c who/what/which/outcome are recorded",
              last.get("actor") == "root" and last.get("action") == "reveal" and last.get("name") == "api_token" and last.get("outcome") == "allowed", f"got {last}")
        check("I9d the audit NEVER stores a value", not any("value" in r for r in rows) and "value-1" not in str(rows))
        del os.environ["APP_SECRETS_VAULT_AUDIT"]   # back to the default 'deny'
        before2 = len(store.values("secrets_vault_access"))
        c.post("/secrets_vault/api_token/reveal", json={}, headers=ALICE)   # a 403 denial (alice is not admin)
        denials = store.values("secrets_vault_access")
        check("I9e a denied (403) access is audited in the default deny mode",
              len(denials) == before2 + 1 and denials[-1].get("outcome") == "denied", f"{before2}->{len(denials)} last={denials[-1] if denials else None}")
        check("I9f GET /access is admin-only (alice -> 403)", c.get("/secrets_vault/access", headers=ALICE).status_code == 403)
        acc = c.get("/secrets_vault/access").json()
        check("I9g GET /access returns the paginated audit, never a value", "results" in acc and "value-1" not in str(acc))

        # I10 — ANTI-RELOCATION: the plaintext lives ONLY in the versions namespace — never in meta, the audit, or any
        # other namespace (white-box scan of every namespace's serialized rows for a known plaintext marker).
        marker = "value-3"   # a known api_token version value
        all_ns = [row[0] for row in store._driver._conn.execute("SELECT DISTINCT ns FROM _kv").fetchall()]  # white-box: the sqlite driver's raw conn (the store backend behind the facade)
        leaked_ns = [ns for ns in all_ns if ns != "secrets_vault_versions"
                     and any(marker in str(x) for x in store.values(ns))]
        check("I10 the plaintext value lives ONLY in the versions namespace", leaked_ns == [], f"leaked into {leaked_ns}")

        # I11 — AT-REST SEAL (KEK engaged): with SECRETS_VAULT_KEK set, the stored bytes are AES-256-GCM CIPHERTEXT
        # (not the plaintext), reveal round-trips EXACTLY, a WRONG key fails LOUD (never plaintext/garbage), the
        # name+version AAD binds a blob to its slot (a relocated blob won't unseal), and DESTROY still scrubs the row.
        # The optional 'cryptography' dep is used ONLY on this path -> skip LOUDLY (not fail) if it is absent.
        try:
            import base64
            import cryptography  # noqa: F401
            have_crypto = True
        except ImportError:
            have_crypto = False
        if not have_crypto:
            print("  [SKIP] I11 at-rest seal — optional 'cryptography' dep not installed; seal proofs not run")
        else:
            kek = base64.b64encode(bytes(range(32))).decode()      # a fixed, known 32-byte key (deterministic)
            os.environ["SECRETS_VAULT_KEK"] = kek
            put("sealed", "TOP-SECRET-XYZ")
            raw = store.get("secrets_vault_versions", "sealed\x1f1")
            check("I11a the stored value is SEALED, not the plaintext",
                  isinstance(raw, str) and raw != "TOP-SECRET-XYZ" and raw.startswith("svgcm:"), f"got {raw!r}")
            check("I11a-noplain the plaintext is ABSENT from the stored blob", "TOP-SECRET-XYZ" not in (raw or ""), f"got {raw!r}")
            check("I11b reveal round-trips the EXACT plaintext", reveal("sealed", 1).json().get("value") == "TOP-SECRET-XYZ")
            # I11c — a WRONG key: reveal must NOT return 200-with-plaintext (loud failure, no leak)
            os.environ["SECRETS_VAULT_KEK"] = base64.b64encode(bytes([9]) + bytes(range(1, 32))).decode()
            wrong = reveal("sealed", 1)
            check("I11c a wrong KEK fails LOUD (not 200, no plaintext)",
                  wrong.status_code != 200 and "TOP-SECRET-XYZ" not in wrong.text, f"status={wrong.status_code}")
            os.environ["SECRETS_VAULT_KEK"] = kek                   # restore the correct key
            # I11d — AAD binding: plant `sealed`'s blob under a DIFFERENT slot; it must fail to unseal (name+version AAD)
            put("relocate_target", "decoy")
            store.put("secrets_vault_versions", "relocate_target\x1f1", raw)   # white-box: relocate the sealed blob
            moved = reveal("relocate_target", 1)
            check("I11d a blob relocated to another slot fails to unseal (AAD binds name+version)",
                  moved.status_code != 200 and "TOP-SECRET-XYZ" not in moved.text, f"status={moved.status_code}")
            # I11e — DESTROY under a KEK still scrubs the (cipher) row -> reveal 404, bytes gone (crypto-shred at the row)
            check("I11e destroy under a KEK returns 'destroyed'",
                  c.post("/secrets_vault/sealed/destroy", json={"version": 1}).json().get("state") == "destroyed")
            check("I11e a destroyed sealed version reveals 404",
                  c.post("/secrets_vault/sealed/reveal", json={"version": 1}).status_code == 404)
            check("I11e white-box: the destroyed ciphertext row is gone",
                  store.get("secrets_vault_versions", "sealed\x1f1") is None)
            del os.environ["SECRETS_VAULT_KEK"]                     # restore the default (KEK unset) for the I3 race subprocess

    # I3 — the version race: two processes write the same name; distinct sequential versions, both retrievable
    if os.getenv("DATABASE_PATH"):
        procs = [subprocess.Popen([sys.executable, "-c", RACE_WORKER, f"concurrent-{i}"], cwd=os.getcwd(),
                                  env={**os.environ, "LOG_LEVEL": "silent"},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for i in range(2)]
        outs = []
        for p in procs:
            so, se = p.communicate(timeout=120)
            outs.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:120]))
        versions = sorted(int(o) for rc, o in outs if rc == 0 and str(o).isdigit())
        check("I3a two racing writes -> distinct sequential versions", versions == [1, 2], f"got {outs}")
        with TestClient(app, raise_server_exceptions=False, headers=ADMIN) as c:
            both = {c.post("/secrets_vault/raced/reveal", json={"version": v}).json()["value"] for v in (1, 2)}
            check("I3b both racers' values are retrievable", both == {"concurrent-0", "concurrent-1"}, f"got {both}")
            check("I3c current advanced to the max", c.get("/secrets_vault/raced").json()["current_version"] == 2)
    else:
        print("  [FAIL] I3 version race NOT RUN — DATABASE_PATH unset")
        failures.append("I3 not run")

    print(f"SECRETS_VAULT INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
