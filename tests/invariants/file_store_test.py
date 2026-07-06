"""FILE_STORE INVARIANTS — a durable, owner-scoped store of REAL BYTE objects. Run against the python app
(cwd=<app>/python; the app includes auth — file_store `requires` it). Credited by EXIT CODE ONLY. Drives the REAL
routes (never a re-implementation) + white-boxes the store seam.

Proves:  I1  byte round-trip + the download CONTRACT — upload b64 of bytes 0x00..0xFF (+ empty + multibyte) ->
              raw GET returns the EXACT bytes; headers: Content-Type == stored EXACTLY (bare — the starlette-charset
              trap), ETag == "<etag>" quoted, X-Content-Type-Options: nosniff, Content-Disposition: attachment,
              Content-Length == size.
         I2  content-addressed etag — etag == sha256(canonical b64), recomputed INDEPENDENTLY here (not the digest
              part); same content across keys -> same etag; any change -> a different etag.
         I3  lifecycle honesty — missing 404; delete 204 then 404; delete-missing 404.
         I4  replace-on-put — content + size + etag replaced; the old etag is gone.
         I5  the provider seam + the OWNER-COMPOSED key — white-box: the WHOLE row lives under <owner>\x1f<key>
              (never the bare key), the index carries the {key,size} entry, the response names the provider.
         I6  strict input — the b64/content_type/key reject families driven live + oversize-decoded -> 422 under a
              tiny FILE_STORE_MAX_BYTES (vs oversize-envelope -> 413, the runtime's).
         I7  deny-by-default — 401 without a valid bearer on all 5 routes (no / forged / malformed scheme).
         I8  cross-owner isolation — same key distinct objects; cross get/meta/delete 404, byte-identical to a
              missing row; a cross-owner delete cannot destroy the real owner's object.
         I9  list isolation + CODEPOINT ordering — the page is exactly the owner's own bare keys, codepoint-sorted
              (an astral/high-BMP pair pins it), no \x1f leaks.
         I10 bounded BOTH ways — a per-owner file-COUNT cap AND a per-owner total-BYTES quota, reject-past-cap.
         I11 quota conservation (clean churn) + drift bound (replace-tear) — index total == sum entry sizes == sum
              decoded row lens; a simulated replace-tear drift is bounded by MAX_BYTES and self-heals on the next clean write.
         I12 header-bound REACHING — a CRLF content_type -> 422 AND no stored row (delete the grammar -> a CRLF wire
              header); a VALID text/html download still carries nosniff + attachment (the stored-XSS read-side wall).
         I13 last-slot cap — filling to MAX_KEYS then a new key is 422 (exactly one holds the slot); the admission
         I14 tear repair + the distinguishing pair — a white-box phantom (entry, no row): GET 404, listed, DELETE
              204 frees it (vs a truly-missing key -> 404); a re-PUT over a phantom lands AND restores conservation."""
import base64
import hashlib
import os
import sys

# Windows stdout defaults to cp1252, which cannot encode the astral/CJK key names the I9 checks print; force UTF-8
# so a print never crashes the run (this suite is credited by EXIT CODE — an output-encoding death is a false RED).
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

os.environ["APP_TEST_SESSIONS"] = "1"   # recognize `Bearer test:<subj>` tokens (inert in production)
os.environ["APP_TEST_CLOCK"] = "1"      # honor ?now for deterministic created_at (inert in production)

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.core import store  # noqa: E402
from app_pkg.app import app  # noqa: E402

_SEP = "\x1f"
_OBJ = "file_store_objects"
_IDX = "file_store_index"
failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        def H(sub):
            return {"Authorization": f"Bearer test:{sub}"}

        def put(sub, key, content_b64, ct=None, now=None):
            body = {"key": key, "content_b64": content_b64}
            if ct is not None:
                body["content_type"] = ct
            path = "/file_store" + (f"?now={now}" if now else "")
            return c.post(path, json=body, headers=H(sub))

        def get_raw(sub, key):
            return c.get(f"/file_store/{key}", headers=H(sub))

        def meta(sub, key):
            return c.get(f"/file_store/{key}/meta", headers=H(sub))

        def listing(sub):
            return c.get("/file_store", headers=H(sub)).json()["results"]

        # I7 — deny-by-default: a valid bearer is required on every route
        check("I7a POST no token -> 401", c.post("/file_store", json={"key": "a", "content_b64": "YQ=="}).status_code == 401)
        check("I7b GET list no token -> 401", c.get("/file_store").status_code == 401)
        check("I7c GET object no token -> 401", c.get("/file_store/a").status_code == 401)
        check("I7d GET meta no token -> 401", c.get("/file_store/a/meta").status_code == 401)
        check("I7e DELETE no token -> 401", c.delete("/file_store/a").status_code == 401)
        check("I7f forged token -> 401", c.get("/file_store", headers={"Authorization": "Bearer deadbeef"}).status_code == 401)
        check("I7g malformed scheme -> 401", c.get("/file_store", headers={"Authorization": "test:alice"}).status_code == 401)

        # I1 — byte round-trip + the download contract (all 256 byte values, empty, multibyte)
        for label, data, ct in (("allbytes", bytes(range(256)), None), ("empty", b"", None),
                                ("multi", "pä-中-🔑".encode(), None), ("text", b"<p>hi</p>", "text/plain")):
            bb = b64(data)
            r = put("alice", f"f-{label}", bb, ct=ct)
            g = get_raw("alice", f"f-{label}")
            check(f"I1 raw bytes EXACT ({label})", r.status_code == 201 and g.status_code == 200 and g.content == data,
                  f"put={r.status_code} get={g.status_code} len={len(g.content)} want={len(data)}")
            check(f"I1 Content-Length == size ({label})", g.headers.get("content-length") == str(len(data)),
                  f"got {g.headers.get('content-length')} want {len(data)}")
            check(f"I1 ETag quoted content-addressed ({label})",
                  g.headers.get("etag") == '"' + hashlib.sha256(bb.encode()).hexdigest() + '"')
            check(f"I1 nosniff ({label})", g.headers.get("x-content-type-options") == "nosniff")
            check(f"I1 attachment ({label})", g.headers.get("content-disposition") == "attachment")
            want_ct = ct if ct else "application/octet-stream"
            check(f"I1 Content-Type reflected BARE (no ; charset) ({label})", g.headers.get("content-type") == want_ct,
                  f"got {g.headers.get('content-type')} want {want_ct}")

        # I2 — content-addressed etag, independently recomputed
        bb = b64(b"hello world")
        put("alice", "h1", bb)
        put("alice", "h2", bb)
        e1, e2 = meta("alice", "h1").json()["etag"], meta("alice", "h2").json()["etag"]
        check("I2a etag == sha256(canonical b64), recomputed here", e1 == hashlib.sha256(bb.encode()).hexdigest())
        check("I2b same content, same etag across keys", e1 == e2)
        put("alice", "h3", b64(b"hello world!"))
        check("I2c any change, a different etag", meta("alice", "h3").json()["etag"] != e1)

        # I3 — lifecycle honesty
        check("I3a missing meta -> 404", meta("alice", "never").status_code == 404)
        check("I3b delete -> 204", c.delete("/file_store/h2", headers=H("alice")).status_code == 204)
        check("I3c meta after delete -> 404", meta("alice", "h2").status_code == 404)
        check("I3d delete the missing -> 404", c.delete("/file_store/h2", headers=H("alice")).status_code == 404)

        # I4 — replace-on-put
        put("alice", "rep", b64(b"first"))
        before = meta("alice", "rep").json()["etag"]
        put("alice", "rep", b64(b"second longer bytes"))
        after = meta("alice", "rep").json()
        check("I4 re-put replaces content + size + etag",
              after["etag"] != before and after["size"] == len(b"second longer bytes"))

        # I5 — the provider seam + the OWNER-COMPOSED key (white-box)
        r = put("alice", "seam", b64(b"seam-bytes"))
        row = store.get(_OBJ, "alice" + _SEP + "seam")
        check("I5a the WHOLE row lives under <owner>\\x1f<key>",
              row is not None and row["content_b64"] == b64(b"seam-bytes") and row["owner"] == "alice")
        check("I5b the bare key is NOT a store key (owner prefix mandatory)", store.get(_OBJ, "seam") is None)
        check("I5c the response names the selected provider", r.json()["provider"] == "store")
        check("I5d the index carries the {key,size} entry (the count/quota authority)",
              any(e["key"] == "seam" and e["size"] == len(b"seam-bytes") for e in store.get(_IDX, "alice")))

        # I6 — strict input (each REACHING the defended path)
        for bad in ("@@@@", "QQQ", "QR==", "QQ=Q", "QQ =="):
            check(f"I6 b64 reject {bad!r} -> 422", put("alice", "bk", bad).status_code == 422)
        for bad in ("text/html\r\nX-Evil: 1", "text/ html", "texthtml", "", "text/html;charset=utf-8", "*/*"):
            check(f"I6 content_type reject {bad!r} -> 422", put("alice", "ck", "YQ==", ct=bad).status_code == 422)
        for bad in ("a/b", "a\\b", ".", ".."):
            check(f"I6 key reject {bad!r} -> 422", put("alice", bad, "YQ==").status_code == 422)
        check("I6 key >1024 utf-8 BYTES (300 astral = 1200 bytes, <=1024 codepoints) -> 422",
              put("alice", "😀" * 300, "YQ==").status_code == 422)
        check("I6 key >1024 CODE POINTS -> 422", put("alice", "a" * 1025, "YQ==").status_code == 422)
        check("I6 control-char path key %1F -> 422", get_raw("alice", "p%1Fq").status_code == 422)
        os.environ["FILE_STORE_MAX_BYTES"] = "8"
        check("I6 oversize-decoded -> 422 (tiny MAX_BYTES)", put("alice", "big", b64(b"0123456789")).status_code == 422)
        check("I6 within-cap -> 201 (same tiny MAX_BYTES)", put("alice", "sm", b64(b"01234")).status_code == 201)
        del os.environ["FILE_STORE_MAX_BYTES"]

        # I8 — cross-owner isolation (>=3 identities + a negative cross-owner assertion)
        put("alice", "shared", b64(b"alice-secret"))
        put("bob", "shared", b64(b"bob-secret"))
        check("I8a same key, different owner -> distinct objects",
              meta("alice", "shared").json()["etag"] != meta("bob", "shared").json()["etag"])
        check("I8b each owner reads their OWN bytes",
              get_raw("alice", "shared").content == b"alice-secret" and get_raw("bob", "shared").content == b"bob-secret")
        cross, missing = meta("carol", "shared"), meta("carol", "noexist")
        check("I8c cross-owner meta -> 404", cross.status_code == 404)
        check("I8d cross-owner 404 == missing 404 (existence does not leak)", cross.json() == missing.json())
        check("I8e cross-owner raw 404 never carries the other's bytes", b"alice-secret" not in get_raw("carol", "shared").content)
        check("I8f cross-owner DELETE -> 404", c.delete("/file_store/shared", headers=H("carol")).status_code == 404)
        check("I8g the real owner's object survives the cross-owner delete", get_raw("alice", "shared").content == b"alice-secret")

        # I9 — list isolation + CODEPOINT ordering
        for k in ("z", "a", "m"):
            put("dave", k, "YQ==")
        put("dave", "😀", "YQ==")
        put("dave", "｡", "YQ==")   # U+FF61 sorts BEFORE U+1F600 in codepoint order (node's default UTF-16 sort inverts this)
        keys = [e["key"] for e in listing("dave")]
        check("I9a list is codepoint-sorted (incl. an astral key)", keys == sorted(keys, key=lambda s: [ord(ch) for ch in s]))
        check("I9b ｡ (U+FF61) precedes 😀 (U+1F600)", keys.index("｡") < keys.index("😀"))
        check("I9c the list carries no \\x1f (bare keys only)", all(_SEP not in k for k in keys))
        check("I9d dave's list is EXACTLY dave's own keys", set(keys) == {"z", "a", "m", "😀", "｡"})

        # I10 — bounded BOTH ways
        os.environ["FILE_STORE_MAX_KEYS"] = "2"
        check("I10a fill to 1", put("capper", "c1", "YQ==").status_code == 201)
        check("I10b fill to 2 (== cap)", put("capper", "c2", "YQ==").status_code == 201)
        check("I10c a 3rd NEW key -> 422 (count cap)", put("capper", "c3", "YQ==").status_code == 422)
        check("I10d replace an existing key under the cap -> 201", put("capper", "c1", "Yg==").status_code == 201)
        check("I10e delete one frees a slot", c.delete("/file_store/c1", headers=H("capper")).status_code == 204)
        check("I10f now a new key fits", put("capper", "c3", "YQ==").status_code == 201)
        del os.environ["FILE_STORE_MAX_KEYS"]
        os.environ["FILE_STORE_MAX_TOTAL_BYTES"] = "10"
        check("I10g byte quota: 5 bytes fits", put("byter", "b1", b64(b"12345")).status_code == 201)
        check("I10h byte quota: +5 == 10 fits", put("byter", "b2", b64(b"12345")).status_code == 201)
        check("I10i byte quota: +1 == 11 -> 422", put("byter", "b3", b64(b"1")).status_code == 422)
        del os.environ["FILE_STORE_MAX_TOTAL_BYTES"]

        # I11 — conservation (clean churn) + drift bound (replace-tear)
        for k, d in (("x1", b"aa"), ("x2", b"bbbb"), ("x3", b"")):
            put("consv", k, b64(d))
        idx = store.get(_IDX, "consv")
        total_entries = sum(e["size"] for e in idx)
        total_rows = sum(len(base64.b64decode(store.get(_OBJ, "consv" + _SEP + e["key"])["content_b64"])) for e in idx)
        check("I11a index sizes == decoded row lens == 6 (conservation on clean churn)",
              total_entries == total_rows == 6, f"entries={total_entries} rows={total_rows}")
        # simulate a replace-tear: the index committed the NEW (smaller) size, the row write was lost (old bytes stay)
        put("drift", "d", b64(b"aaaa"))                     # size 4
        idx = store.get(_IDX, "drift")
        for e in idx:
            if e["key"] == "d":
                e["size"] = 1                               # index now says 1; the row still holds 4 bytes
        store.put(_IDX, "drift", idx)
        row = store.get(_OBJ, "drift" + _SEP + "d")
        entry_size = next(e["size"] for e in store.get(_IDX, "drift") if e["key"] == "d")
        drift = abs(entry_size - len(base64.b64decode(row["content_b64"])))
        check("I11b replace-tear drift is bounded by MAX_BYTES per key", drift <= 524288, f"drift={drift}")
        put("drift", "d", b64(b"zz"))                       # a clean re-PUT recomputes from the entry INSIDE the do
        row2 = store.get(_OBJ, "drift" + _SEP + "d")
        entry2 = next(e["size"] for e in store.get(_IDX, "drift") if e["key"] == "d")
        check("I11c a clean re-PUT restores conservation", entry2 == len(base64.b64decode(row2["content_b64"])) == 2)

        # I12 — header-bound REACHING (both sides)
        put("alice", "htmlx", b64(b"<script>alert(1)</script>"), ct="text/html")
        g = get_raw("alice", "htmlx")
        check("I12a a VALID text/html download carries nosniff (delete it -> stored XSS)",
              g.headers.get("x-content-type-options") == "nosniff")
        check("I12b ... and bare attachment (the read-side stored-XSS wall)", g.headers.get("content-disposition") == "attachment")
        crlf = put("alice", "crlf", "YQ==", ct="text/html\r\nSet-Cookie: pwn=1")
        check("I12c a CRLF content_type -> 422 AND no stored row (delete the grammar -> a CRLF wire header)",
              crlf.status_code == 422 and store.get(_OBJ, "alice" + _SEP + "crlf") is None)

        # I13 — the last-slot cap (the admission is ONE atomic index do(); cross-process exactly-one-wins is
        os.environ["FILE_STORE_MAX_KEYS"] = "1"
        put("race", "only", "YQ==")
        second = put("race", "second", "YQ==")
        check("I13a the (K+1)th distinct key is 422 (exactly one holds the last slot)", second.status_code == 422)
        check("I13b the slot holder is intact", meta("race", "only").status_code == 200)
        del os.environ["FILE_STORE_MAX_KEYS"]

        # I14 — tear repair + the distinguishing pair (white-box phantom: entry present, row deleted)
        put("tear", "ph", "YQ==")
        store.delete_(_OBJ, "tear" + _SEP + "ph")           # a create-tear: the index entry stays, the row is gone
        check("I14a phantom GET -> 404 (the row is the content authority)", get_raw("tear", "ph").status_code == 404)
        check("I14b the phantom is still LISTED (the index)", any(e["key"] == "ph" for e in listing("tear")))
        check("I14c DELETE clears the phantom -> 204 (the index is the existence authority)",
              c.delete("/file_store/ph", headers=H("tear")).status_code == 204)
        check("I14d ... vs a truly-missing key -> 404 (the distinguishing pair)",
              c.delete("/file_store/neverwas", headers=H("tear")).status_code == 404)
        check("I14e the phantom is gone from the list", not any(e["key"] == "ph" for e in listing("tear")))
        put("tear", "ph2", "YQ==")
        store.delete_(_OBJ, "tear" + _SEP + "ph2")          # phantom again
        put("tear", "ph2", "Ym8=")                          # re-PUT over the phantom
        row = store.get(_OBJ, "tear" + _SEP + "ph2")
        entry = next(e["size"] for e in store.get(_IDX, "tear") if e["key"] == "ph2")
        check("I14f a re-PUT over a phantom lands AND restores conservation",
              row is not None and entry == len(base64.b64decode(row["content_b64"])))

    print(f"FILE_STORE INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
