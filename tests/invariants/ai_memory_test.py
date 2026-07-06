"""AI_MEMORY INVARIANTS — correctness proofs for this domain's dangerous property: RETENTION-ENFORCED / BOUNDED (a
memory past its retention — TTL-expired, cap-evicted, or explicitly forgotten — is DETERMINISTICALLY not retrievable,
and an owner's store can NEVER grow unbounded). Run against the python app (cwd = <app>/python; DATABASE_PATH set by
the harness). Credited by EXIT CODE ONLY. Every check uses a REACHING input — delete the defense in your head and the
check goes RED (rule 9).

Proves:  I-BOUNDED-SCOPES (the HEADLINE) a per-owner cap on the NUMBER of scopes: a NEW scope past MAX_SCOPES is 422,
                         never a silent success — a free-form `scope` string can't mint unlimited (capped) partitions.
         I-BOUNDED       the per-scope READ surface holds exactly MAX_MEMORIES; an evicted memory is 404 + list-excluded.
         I-EXPIRY        exact: at now == expires_at -> LIVE (200); now+1 -> 404 + list-excluded (the `>` boundary).
         I-EVICT-CORRECT eviction is importance-weighted + EXPIRED-FIRST: never drops a LIVE memory while an expired one
                         keeps its slot; a high-importance mark-to-keep survives an older low one.
         I-FORGET        DELETE by id purges the index entry + row (a re-add is a NEW id, not a resurrected dead one);
                         DELETE by scope removes exactly that scope, leaving others intact.
         I-OWNER         cross-owner get/delete -> 404; a smuggled owner is discarded; bob adding the SAME content in the
                         SAME scope does NOT clobber alice's; scopes are disjoint; a \x1f key-forgery attempt is 422.
         I-RACE          two processes adding to the SAME (owner,scope) serialize through the do seam: no lost update.
         I-RECENCY/I-Q   newest-first (created_at desc); ?q= is ASCII-ONLY case-fold substring (non-ASCII byte-exact x3).
         I-HOSTILE       a lone surrogate in content / a metadata KEY / a tag is CONTAINED (U+FFFD) before store, so a
                         later RE-READ never 5xx (the email_outbox I6a / reporting-KEY class)."""
import os
import subprocess
import sys

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.core import store  # noqa: E402
from app_pkg.app import app  # noqa: E402

failures = []

# owner = the authenticated subject: enable the test-session seam (Bearer test:<subject>, inert in prod). The test-clock
# seam (?now=, inert in prod) makes TTL/expiry deterministic.
os.environ["APP_TEST_SESSIONS"] = "1"
os.environ["APP_TEST_CLOCK"] = "1"
ALICE = {"Authorization": "Bearer test:alice"}
BOB = {"Authorization": "Bearer test:bob"}
JSON = "application/json"


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


RACE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
with TestClient(app, raise_server_exceptions=False, headers={"Authorization": "Bearer test:racer"}) as c:
    r = c.post("/ai_memory/memories?now=1000", json={"content": sys.argv[1], "scope": "raced"})
    print(r.json()["id"] if r.status_code == 201 else f"status={r.status_code}")
"""


def main():
    with TestClient(app, raise_server_exceptions=False, headers=ALICE) as c:
        def add(content, headers, scope="default", now=1000, **extra):
            return c.post(f"/ai_memory/memories?now={now}", json={"content": content, "scope": scope, **extra}, headers=headers)

        def getm(mid, headers, now=1000):
            return c.get(f"/ai_memory/memories/{mid}?now={now}", headers=headers)

        def listm(headers, scope="default", now=1000, tag=None, q=None):
            qs = f"scope={scope}&now={now}"
            if tag is not None:
                qs += f"&tag={tag}"
            if q is not None:
                qs += f"&q={q}"
            return c.get(f"/ai_memory/memories?{qs}", headers=headers)

        def forget(mid, headers):
            return c.delete(f"/ai_memory/memories/{mid}", headers=headers)

        def forget_scope(scope, headers):
            return c.delete(f"/ai_memory/memories?scope={scope}", headers=headers)

        def contents(headers, scope, now=2000):
            return {m["content"] for m in listm(headers, scope=scope, now=now).json()["results"]}

        # ── I-BOUNDED-SCOPES — the HEADLINE: the per-owner scope COUNT is bounded (a fresh owner, no prior scopes) ──
        SC = {"Authorization": "Bearer test:scopecap"}
        os.environ["AI_MEMORY_MAX_SCOPES"] = "3"
        for i in range(3):
            check(f"I-BOUNDED-SCOPES scope s{i} within cap -> 201", add("m", SC, scope=f"s{i}").status_code == 201)
        check("I-BOUNDED-SCOPES a 4th NEW scope past MAX_SCOPES -> 422 (delete the per-owner cap -> 201)",
              add("m", SC, scope="s3").status_code == 422, "a free-form scope must not mint unlimited capped partitions")
        check("I-BOUNDED-SCOPES a 5th NEW scope -> 422 (not a silent success)", add("m", SC, scope="s4").status_code == 422)
        check("I-BOUNDED-SCOPES an EXISTING scope still accepts (the bound is on NEW scopes)",
              add("m2", SC, scope="s0").status_code == 201)
        check("I-BOUNDED-SCOPES existing scopes are intact", contents(SC, "s0") == {"m", "m2"})
        del os.environ["AI_MEMORY_MAX_SCOPES"]

        # ── I-BOUNDED — the per-scope READ surface is capped; evicted memories are 404 + excluded ──
        MC = {"Authorization": "Bearer test:memcap"}
        os.environ["AI_MEMORY_MAX_MEMORIES"] = "3"
        ids = [add(f"m{i}", MC, scope="c", now=1000 + i).json()["id"] for i in range(5)]  # 5 into a cap-3 scope
        surface = contents(MC, "c")
        check("I-BOUNDED the read surface holds exactly MAX_MEMORIES (not 5)", len(surface) == 3, f"got {surface}")
        check("I-BOUNDED default importance => pure FIFO evicts the 2 OLDEST", surface == {"m2", "m3", "m4"}, f"got {surface}")
        check("I-BOUNDED an evicted memory is 404 by id", getm(ids[0], MC, now=2000).status_code == 404)
        check("I-BOUNDED an evicted memory's ROW is white-box gone", store.get("ai_memory_memory", f"memcap\x1f{ids[0]}") is None)
        del os.environ["AI_MEMORY_MAX_MEMORIES"]

        # ── I-EXPIRY — exact boundary: now == expires_at is LIVE; now+1 is gone ──
        EX = {"Authorization": "Bearer test:exp"}
        r = add("expiring", EX, scope="e", ttl_seconds=100, now=1000)  # expires_at = 1100
        mid = r.json()["id"]
        check("I-EXPIRY expires_at is derived = created_at + ttl", r.json().get("expires_at") == 1100, f"got {r.json()}")
        check("I-EXPIRY before expiry (now=1099) -> 200", getm(mid, EX, now=1099).status_code == 200)
        check("I-EXPIRY AT expiry (now=1100 == expires_at) -> 200 (AT the boundary is LIVE; `>=` would 404 -> RED)",
              getm(mid, EX, now=1100).status_code == 200)
        check("I-EXPIRY after expiry (now=1101) -> 404", getm(mid, EX, now=1101).status_code == 404)
        check("I-EXPIRY an expired memory is EXCLUDED from the list", listm(EX, scope="e", now=1101).json()["results"] == [])
        check("I-EXPIRY AT expiry the list still INCLUDES it", len(listm(EX, scope="e", now=1100).json()["results"]) == 1)

        # ── I-EVICT-CORRECT — importance-weighted + expired-first ──
        EV = {"Authorization": "Bearer test:evict"}
        os.environ["AI_MEMORY_MAX_MEMORIES"] = "2"
        a = add("A", EV, scope="ev", importance=0, now=1000).json()["id"]
        add("B", EV, scope="ev", importance=5, now=1001)  # high importance -> mark-to-keep
        add("C", EV, scope="ev", importance=0, now=1002)  # adding C past cap evicts the min: A (imp 0, older than C)
        check("I-EVICT importance: a high-importance memory survives an older low one", contents(EV, "ev") == {"B", "C"}, f"got {contents(EV, 'ev')}")
        check("I-EVICT the low-importance A was evicted", getm(a, EV, now=2000).status_code == 404)
        # expired-first: an EXPIRED high-importance memory is evicted before a LIVE low-importance one
        d = add("D-exp", EV, scope="ef", ttl_seconds=10, importance=9, now=1000).json()["id"]  # expires 1010, HIGH imp
        add("E-live", EV, scope="ef", importance=0, now=1001)                                   # live, LOW imp
        add("F-live", EV, scope="ef", importance=0, now=2000)  # at now=2000 D is EXPIRED -> evict D (expired-first), keep E
        check("I-EVICT-CORRECT expired-first evicts the EXPIRED memory, NOT the live low-importance one (delete expired-first -> RED)",
              contents(EV, "ef") == {"E-live", "F-live"}, f"got {contents(EV, 'ef')}")
        check("I-EVICT-CORRECT the expired D is gone despite its HIGHEST importance", getm(d, EV, now=2000).status_code == 404)
        del os.environ["AI_MEMORY_MAX_MEMORIES"]

        # ── I-FORGET — purge index + row; a re-add is a NEW id; delete-scope removes exactly that scope ──
        FG = {"Authorization": "Bearer test:forget"}
        m = add("secret", FG, scope="f").json()["id"]
        check("I-FORGET DELETE {id} -> 204", forget(m, FG).status_code == 204)
        check("I-FORGET after delete, GET {id} -> 404", getm(m, FG).status_code == 404)
        check("I-FORGET the row is white-box gone", store.get("ai_memory_memory", f"forget\x1f{m}") is None)
        check("I-FORGET the scope index no longer references the id (purged)",
              not any(e["id"] == m for e in (store.get("ai_memory_scope", "forget\x1ff") or [])))
        m2 = add("secret", FG, scope="f", now=1001).json()["id"]
        check("I-FORGET a re-add of the SAME content mints a NEW id (not a resurrected dead one)", m2 != m)
        check("I-FORGET the re-added memory is live", getm(m2, FG).status_code == 200)
        add("keep", FG, scope="keepme")
        add("drop", FG, scope="dropme")
        check("I-FORGET delete_all(scope) -> 204", forget_scope("dropme", FG).status_code == 204)
        check("I-FORGET delete_all removed the target scope", listm(FG, scope="dropme").json()["results"] == [])
        check("I-FORGET delete_all left OTHER scopes intact", contents(FG, "keepme") == {"keep"})

        # ── I-OWNER — cross-owner isolation + no clobber + guarded owner + \x1f forgery ──
        am = add("ALICE secret", ALICE, scope="o").json()["id"]
        check("I-OWNER cross-owner GET -> 404 (delete owner from the key -> 200 -> RED)", getm(am, BOB).status_code == 404)
        check("I-OWNER cross-owner DELETE -> 404", forget(am, BOB).status_code == 404)
        check("I-OWNER after bob's failed delete, alice's memory is intact", getm(am, ALICE).status_code == 200)
        bm = add("BOB secret", BOB, scope="o", now=1001).json()["id"]
        check("I-OWNER bob's same-scope add is a DISTINCT memory (no clobber)",
              bm != am and getm(bm, BOB).json()["content"] == "BOB secret")
        check("I-OWNER alice's memory is UNCHANGED after bob's add", getm(am, ALICE).json()["content"] == "ALICE secret")
        check("I-OWNER bob's 'o' list excludes alice's", contents(BOB, "o") == {"BOB secret"})
        add("in-s1", ALICE, scope="s1")
        add("in-s2", ALICE, scope="s2")
        check("I-OWNER scope s1 is disjoint from s2", contents(ALICE, "s1") == {"in-s1"})
        gm = add("guard", ALICE, scope="g", owner="bob", id=999).json()["id"]  # smuggled owner/id -> discarded
        check("I-OWNER a smuggled owner is discarded (stored owner = token subject)",
              store.get("ai_memory_memory", f"alice\x1f{gm}")["owner"] == "alice")
        check("I-OWNER bob cannot see alice's guarded memory", getm(gm, BOB).status_code == 404)
        fk = c.post("/ai_memory/memories?now=1000", content='{"content": "x", "scope": "a\\u001fb"}',
                    headers={**ALICE, "content-type": JSON})
        check("I-OWNER a \\x1f in scope (key-forgery attempt) -> 422 (the \\x1f separator is unforgeable)", fk.status_code == 422, f"got {fk.status_code}")

        # ── I-RECENCY / I-Q — newest-first; ASCII-only case-fold substring ──
        MI = {"Authorization": "Bearer test:misc"}
        add("first", MI, scope="rec", now=1000)
        add("second", MI, scope="rec", now=1001)
        add("third", MI, scope="rec", now=1002)
        order = [m["content"] for m in listm(MI, scope="rec", now=2000).json()["results"]]
        check("I-RECENCY newest-first (created_at desc)", order == ["third", "second", "first"], f"got {order}")
        add("the Cat sat", MI, scope="q", now=1000)
        add("a dog ran", MI, scope="q", now=1001)
        qres = [m["content"] for m in listm(MI, scope="q", now=2000, q="cat").json()["results"]]
        check("I-Q ascii-fold substring matches case-insensitively", qres == ["the Cat sat"], f"got {qres}")
        add("straße", MI, scope="q2", now=1000)  # "straße" — ß is non-ASCII
        check("I-Q non-ASCII stays byte-exact (STRASSE != straße under ASCII-only fold -> no false match; locale casefold -> RED)",
              listm(MI, scope="q2", now=2000, q="STRASSE").json()["results"] == [])
        check("I-Q the ASCII prefix folds (STRA matches straße)", len(listm(MI, scope="q2", now=2000, q="STRA").json()["results"]) == 1)

        # ── I-HOSTILE — contain a lone surrogate in content / a metadata KEY / a tag BEFORE store; a re-read never 5xx ──
        sg = c.post("/ai_memory/memories?now=1000", content='{"content": "a\\ud800b", "scope": "h"}',
                    headers={**MI, "content-type": JSON})
        check("I-HOSTILE a lone-surrogate content -> 201 contained (not 500)", sg.status_code == 201, f"got {sg.status_code}")
        check("I-HOSTILE the contained content re-reads as U+FFFD", getm(sg.json()["id"], MI).json()["content"] == "a�b")
        sk = c.post("/ai_memory/memories?now=1000",
                    content='{"content": "x", "scope": "h2", "metadata": {"k\\ud800": "v"}, "tags": ["t\\ud800"]}',
                    headers={**MI, "content-type": JSON})
        check("I-HOSTILE a surrogate in a metadata KEY + a tag -> 201 (contained)", sk.status_code == 201, f"got {sk.status_code} {sk.text[:160]}")
        rr = getm(sk.json()["id"], MI)  # the RE-READ must not 500 (un-contained KEY would 5xx on json encode)
        check("I-HOSTILE the re-read of a surrogate-keyed metadata + tag does NOT 500", rr.status_code == 200, f"got {rr.status_code}")
        check("I-HOSTILE the metadata KEY was contained to U+FFFD (delete make_well_formed on the key -> re-read 500 -> RED)",
              "k�" in rr.json()["metadata"], f"got {rr.json().get('metadata')}")
        check("I-HOSTILE the tag was contained to U+FFFD", rr.json()["tags"] == ["t�"], f"got {rr.json().get('tags')}")

        # ── I-HOSTILE-PROTO — a "__proto__" metadata KEY is stored as DATA + re-read, never dropped/merged (x3; node
        #    Object.create(null) matches the py dict / go map). Delete Object.create(null) -> node re-reads {} -> RED. ──
        pm = add("proto", MI, scope="proto", now=1000, metadata={"__proto__": "PWN", "real": "keep"}).json()["id"]
        pr = getm(pm, MI, now=1000).json().get("metadata", {})
        check("I-HOSTILE a __proto__ metadata key is stored as data (not dropped)",
              pr.get("__proto__") == "PWN" and pr.get("real") == "keep", f"got {pr}")

        # ── I-RACE-FORGET-SCOPE — the OWNER index is authoritative: an orphan scope (present in the scope index but NOT
        #    the owner index — the residue of a forget_scope||add two-key race) is NON-RETRIEVABLE and NON-COUNTED, so
        #    the RETRIEVABLE store stays bounded by MAX_SCOPES x MAX_MEMORIES. Delete the owner-index read-gate in
        #    list/get and the orphan becomes retrievable -> RED (a reaching white-box proof of the race fix). ──
        RC = {"Authorization": "Bearer test:racer2"}
        add("legit", RC, scope="keep", now=1000)
        store.put("ai_memory_memory", "racer2\x1f900001",
                  {"id": 900001, "owner": "racer2", "scope": "ghost", "content": "ORPHAN", "tags": [],
                   "metadata": {}, "importance": 0, "created_at": 1000, "expires_at": 0})
        store.put("ai_memory_scope", "racer2\x1fghost",
                  [{"id": 900001, "created_at": 1000, "expires_at": 0, "importance": 0}])
        check("I-RACE-FORGET-SCOPE an orphan scope (not in the owner index) lists EMPTY",
              listm(RC, scope="ghost", now=2000).json()["results"] == [], "the owner-index read-gate must hide it")
        check("I-RACE-FORGET-SCOPE an orphan memory is 404 by id (owner-index-gated liveness)",
              getm(900001, RC, now=2000).status_code == 404)
        check("I-RACE-FORGET-SCOPE the legit scope is unaffected", contents(RC, "keep") == {"legit"})

    # ── I-RACE — two processes add to the SAME (owner,scope); the index do serializes (no lost update) ──
    if os.getenv("DATABASE_PATH"):
        procs = [subprocess.Popen([sys.executable, "-c", RACE_WORKER, f"raced-{i}"], cwd=os.getcwd(),
                                  env={**os.environ, "LOG_LEVEL": "silent"},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for i in range(2)]
        outs = []
        for p in procs:
            so, se = p.communicate(timeout=120)
            outs.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:120]))
        ids = sorted(int(o) for rc, o in outs if rc == 0 and str(o).isdigit())
        check("I-RACE two racing adds -> two DISTINCT ids", len(ids) == 2 and ids[0] != ids[1], f"got {outs}")
        with TestClient(app, raise_server_exceptions=False, headers={"Authorization": "Bearer test:racer"}) as c:
            entries = store.get("ai_memory_scope", "racer\x1fraced") or []
            check("I-RACE the scope index has BOTH entries (get-then-put would lose one -> RED)", len(entries) == 2, f"got {len(entries)}")
            got = {c.get(f"/ai_memory/memories/{i}?now=1000").json().get("content") for i in ids}
            check("I-RACE both racers' memories are retrievable", got == {"raced-0", "raced-1"}, f"got {got}")
    else:
        print("  [FAIL] I-RACE NOT RUN — DATABASE_PATH unset")
        failures.append("I-RACE not run")

    print(f"AI_MEMORY INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
