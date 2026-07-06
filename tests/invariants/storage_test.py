"""STORAGE INVARIANTS — USER-SCOPED object storage keyed to the AUTHENTICATED identity (the core
require_identity seam), plus the integrity properties. Run against the python app (cwd=<app>/python; the app
includes auth — storage `requires` it). Credited by EXIT CODE ONLY.

Proves:  I1 byte-for-byte round-trip — what you put is exactly what you get, including unicode and the empty
            payload; size is the utf-8 BYTE length (the ×3-identical semantic).
         I2 content-addressed etag — etag == sha256(content), recomputed independently here; same content, same
            etag (across keys), any change a different etag.
         I3 lifecycle honesty — missing is 404; delete is 204 then 404; deleting the missing is 404; the listing
            reflects reality (sorted bare keys, deleted keys gone).
         I4 replace-on-put — re-putting a key replaces content, size, and etag; the old etag is gone.
         I5 the provider seam + the OWNER-COMPOSED key — the response names the provider; white-box, the WHOLE
            object lives in the store seam under the composite `<owner>\x1f<key>` (never the bare key), and the
            seam is the ONLY storage.
         I6 strict input — bad keys/bodies are rejected (after auth).
         I7 deny-by-default — every route is 401 without a valid bearer token (no / malformed / forged).
         I8 cross-owner isolation — caller A's a.txt and caller B's a.txt are DISTINCT objects (no overwrite); a
            cross-owner get/delete is 404, byte-identical to a missing row (existence never leaks); and a
            cross-owner delete cannot destroy the real owner's object.
         I9 list isolation — a caller's list (the {results} page) is EXACTLY its own bare keys, keyed by its real
            token (owner-scoping is PRESERVED through pagination).
         I10 bounded page — the list is a {results,next_cursor} page over the OWNER's stable-ordered keys via the
            shared paginate part (the soft-DoS ceiling): a limit yields a bounded slice + an opaque cursor that
            round-trips to the rest with no repeat; the paged union is exactly the owner's own keys; a malformed
            cursor/limit is 422, never a silent full dump."""
import hashlib
import os
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # recognize `Bearer test:<subj>` tokens (inert in production)

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.core import store  # noqa: E402
from app_pkg.app import app  # noqa: E402

_SEP = "\x1f"   # the owner-key unit separator (white-box check of the composite store key)
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

        def put(t, key, content):
            return c.post("/storage", json={"key": key, "content": content}, headers=H(t))

        def get(t, key):
            return c.get(f"/storage/{key}", headers=H(t))

        # I7 — deny-by-default: a valid bearer token is required on every route
        check("I7a PUT no token -> 401", c.post("/storage", json={"key": "a.txt", "content": "x"}).status_code == 401)
        check("I7b GET list no token -> 401", c.get("/storage").status_code == 401)
        check("I7c GET object no token -> 401", c.get("/storage/a.txt").status_code == 401)
        check("I7d DELETE no token -> 401", c.delete("/storage/a.txt").status_code == 401)
        check("I7e forged token -> 401", c.get("/storage", headers={"Authorization": "Bearer deadbeef"}).status_code == 401)
        check("I7f malformed scheme -> 401", c.get("/storage", headers={"Authorization": ta}).status_code == 401)

        # I1 — round-trip, including unicode + empty; size is the utf-8 byte length (as alice)
        for key, content in (("plain.txt", "hello world"), ("uni.txt", "pässwörd-中文-🔑"), ("empty.bin", "")):
            r = put(ta, key, content)
            g = get(ta, key)
            check(f"I1 round-trip byte-for-byte ({key})",
                  r.status_code == 201 and g.status_code == 200 and g.json()["content"] == content)
            check(f"I1 size is utf-8 BYTE length ({key})",
                  g.json()["size"] == len(content.encode("utf-8")),
                  f"got {g.json()['size']}, want {len(content.encode('utf-8'))}")

        # I2 — content-addressed etag, independently recomputed
        e = get(ta, "uni.txt").json()["etag"]
        check("I2a etag == sha256(content), recomputed here",
              e == hashlib.sha256("pässwörd-中文-🔑".encode()).hexdigest())
        put(ta, "copy.txt", "hello world")
        check("I2b same content, same etag across keys",
              get(ta, "copy.txt").json()["etag"] == get(ta, "plain.txt").json()["etag"])
        put(ta, "tweaked.txt", "hello world!")
        check("I2c any change, a different etag",
              get(ta, "tweaked.txt").json()["etag"] != get(ta, "plain.txt").json()["etag"])

        # I3 — lifecycle honesty (within alice's namespace)
        check("I3a missing -> 404", get(ta, "never.txt").status_code == 404)
        check("I3b delete -> 204", c.delete("/storage/copy.txt", headers=H(ta)).status_code == 204)
        check("I3c get after delete -> 404", get(ta, "copy.txt").status_code == 404)
        check("I3d delete the missing -> 404", c.delete("/storage/copy.txt", headers=H(ta)).status_code == 404)
        listing = c.get("/storage", headers=H(ta)).json()
        keys = listing["results"]
        check("I3e the listing is the bounded {results,next_cursor} page, sorted, reflecting reality",
              set(listing) == {"results", "next_cursor"} and keys == sorted(keys)
              and "copy.txt" not in keys and "plain.txt" in keys)

        # I4 — replace-on-put
        before = get(ta, "plain.txt").json()["etag"]
        put(ta, "plain.txt", "entirely new bytes")
        after = get(ta, "plain.txt").json()
        check("I4 re-put replaces content + etag",
              after["content"] == "entirely new bytes" and after["etag"] != before)

        # I5 — the provider seam + the OWNER-COMPOSED key (white-box)
        r = put(ta, "seam.txt", "seam-check")
        check("I5a the response names the selected provider", r.json()["provider"] == "store")
        row = store.get("storage_objects", "alice" + _SEP + "seam.txt")   # the composite key, NOT the bare key
        check("I5b white-box: the WHOLE object lives in the store seam under <owner>\\x1f<key>",
              row is not None and row["content"] == "seam-check" and row["etag"] == r.json()["etag"]
              and row["owner"] == "alice")
        check("I5c the bare key is NOT a store key (the owner prefix is mandatory)",
              store.get("storage_objects", "seam.txt") is None)

        # I6 — strict input (after auth)
        for bad in ({"content": "x"}, {"key": "", "content": "x"}, {"key": 7, "content": "x"},
                    {"key": "k"}, {"key": "k", "content": 7}):
            check(f"I6 invalid put body {bad!r} -> 422", c.post("/storage", json=bad, headers=H(ta)).status_code == 422)
        check("I6 control-char key on GET -> 422", c.get("/storage/p%1Fq", headers=H(ta)).status_code == 422)

        # I8 — cross-owner isolation: same key, different owner = DISTINCT objects; cross-owner access = 404
        ra = put(ta, "shared.txt", "alice-secret")
        rb = put(tb, "shared.txt", "bob-secret")
        check("I8a same key, different owner -> both 201, independent content",
              ra.status_code == 201 and rb.status_code == 201
              and ra.json()["etag"] != rb.json()["etag"])
        check("I8b each owner reads their OWN object back",
              get(ta, "shared.txt").json()["content"] == "alice-secret"
              and get(tb, "shared.txt").json()["content"] == "bob-secret")
        # bob's put did NOT overwrite alice's (no cross-owner overwrite)
        check("I8c no cross-owner overwrite (alice's bytes intact after bob's put)",
              get(ta, "shared.txt").json()["content"] == "alice-secret")
        # carol (a third owner) cannot see/read alice's object
        tc = token_for("carol")
        cross = get(tc, "shared.txt")
        missing = get(tc, "no-such-object.txt")
        check("I8d cross-owner read is 404 (never the row)", cross.status_code == 404)
        check("I8e cross-owner 404 == missing 404 (existence does not leak)", cross.json() == missing.json())
        check("I8f the 404 never carries the other owner's content", b"alice-secret" not in cross.content)
        # carol's delete cannot destroy alice's object
        check("I8g cross-owner DELETE is 404 (cannot destroy another's object)",
              c.delete("/storage/shared.txt", headers=H(tc)).status_code == 404)
        check("I8h alice's object survives the cross-owner delete attempt",
              get(ta, "shared.txt").json()["content"] == "alice-secret")

        # I9 — list isolation: exactly your own bare keys (the page is owner-scoped — owner-isolation is PRESERVED)
        la = set(c.get("/storage", headers=H(ta)).json()["results"])
        lb = set(c.get("/storage", headers=H(tb)).json()["results"])
        check("I9a alice's list holds her keys, NOT bob-only keys", "shared.txt" in la and "plain.txt" in la)
        check("I9b bob's list is exactly his own bare keys", lb == {"shared.txt"})
        check("I9c bob does not see alice's other objects", "plain.txt" not in lb and "seam.txt" not in lb)
        check("I9d the list returns BARE keys (no owner prefix)", all(_SEP not in k for k in la | lb))

        # I10 — the list is a BOUNDED page over the OWNER's keys (the soft-DoS ceiling) with a round-trip cursor.
        # dave gets 3 objects; a limit-1 page yields exactly 1 key + a next_cursor; walking the cursor returns the
        # REST and never repeats; the union of pages == dave's full sorted key set (and ONLY dave's — owner-scoped).
        td = token_for("dave")
        for k in ("d-a", "d-b", "d-c"):
            put(td, k, k)
        full = sorted(("d-a", "d-b", "d-c"))
        p1 = c.get("/storage?limit=1", headers=H(td)).json()
        check("I10a a limit-1 page returns exactly one key + a next_cursor",
              p1["results"] == [full[0]] and p1["next_cursor"] is not None,
              f"got {p1}")
        p2 = c.get(f"/storage?cursor={p1['next_cursor']}", headers=H(td)).json()
        check("I10b the cursor round-trips: the next page continues past page 1 with no repeat",
              full[0] not in p2["results"] and p2["results"] == full[1:],
              f"got {p2}")
        check("I10c the paged union is EXACTLY the owner's own full key set (owner-scoped, no leakage)",
              set(p1["results"]) | set(p2["results"]) == set(full))
        check("I10d default page bound is enforced (results never exceed PAGE_MAX=200)",
              len(c.get("/storage", headers=H(td)).json()["results"]) <= 200)
        check("I10e an invalid cursor is rejected 422 (not a silent full dump)",
              c.get("/storage?cursor=MQ%3D%3D", headers=H(td)).status_code == 422)
        check("I10f an invalid limit is rejected 422", c.get("/storage?limit=0", headers=H(td)).status_code == 422)

    print(f"STORAGE INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
