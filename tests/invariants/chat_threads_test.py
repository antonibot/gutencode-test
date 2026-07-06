"""CHAT_THREADS INVARIANTS — correctness proofs for this domain's dangerous property: APPEND-ONLY ORDERED HISTORY
+ OWNER ISOLATION + BOUNDED BOTH WAYS. Run against the python app (cwd = <app>/python; DATABASE_PATH set by the
harness). Credited by EXIT CODE ONLY. Every check uses a REACHING input — delete the defense in your head and the
check goes RED (rule 9).

Proves:  I-ORDER          interleaved appends across two threads yield per-thread seqs exactly 1..k, transcript ==
                          append order (mint the seq from anything but the thread row's atomic counter -> RED).
         I-RACE-APPEND    TWO PROCESSES race appending to the SAME thread: both 201, seqs DISTINCT + consecutive,
                          last_seq == 2, both retrievable (a get-then-put mint loses an update -> RED).
         I-IMMUTABLE      after PATCH + more appends, earlier message rows re-read byte-identical (white-box); no
                          route can touch a written seq slot.
         I-BOUNDED-MSG    a full thread REJECTS the next append 422 (delete the cap branch in the do-fn -> RED);
                          the transcript holds exactly the cap.
         I-BOUNDED-THREADS the per-owner thread COUNT is bounded: a create past MAX_THREADS is 422, never a silent
                          success or an eviction; PLUS a 2-process race for the LAST slot -> exactly one 201 (the
                          index-do serializes; delete the index reject branch -> RED).
         I-CROSS-OWNER    >=2 identities: B's get/patch/delete/append/messages against A's thread are 404
                          byte-indistinguishable from missing; A's list and B's list are disjoint.
         I-CASCADE        DELETE frees the cap slot (a fresh create then SUCCEEDS — delete the index-removal step
                          -> RED), thread/messages/append all 404, message rows white-box reaped.
         I-CONTAIN        a lone surrogate in content / a title / a metadata KEY is CONTAINED (U+FFFD) before
                          store and every RE-READ is clean (no 5xx — the stored-poison class); a control char in
                          the title is 422; multi-line + control-char content is stored byte-exact as DATA.
         I-LIVENESS       white-box delete-tear residue (row present, index entry gone) is 404 on EVERY surface —
                          the index gate; no orphan resurrection.
         I-ACTIVITY       an append to an older thread lifts it to the list head (updated_at authority); equal
                          updated_at ties break newest-id-first.
         I-GAP            a missing seq slot (the mint/write tear) is SKIPPED: transcript order intact, no 5xx,
                          last_seq stays the honest high-water mark."""
import os
import subprocess
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # the 'test:' bearer resolves only under this seam (inert in production)
os.environ["APP_TEST_CLOCK"] = "1"      # ?now= honored, so created_at/updated_at are deterministic

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402
from app_pkg.core import store  # noqa: E402

failures = []

ALICE = {"Authorization": "Bearer test:alice"}
BOB = {"Authorization": "Bearer test:bob"}
JSON = "application/json"


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def H(subject):
    return {"Authorization": f"Bearer test:{subject}"}


RACE_APPEND_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
with TestClient(app, raise_server_exceptions=False, headers={"Authorization": "Bearer test:racer"}) as c:
    r = c.post(f"/chat_threads/{sys.argv[2]}/messages?now=1000", json={"role": "user", "content": sys.argv[1]})
    print(r.json()["seq"] if r.status_code == 201 else f"status={r.status_code}")
"""

RACE_CREATE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
with TestClient(app, raise_server_exceptions=False, headers={"Authorization": "Bearer test:racecap"}) as c:
    r = c.post("/chat_threads?now=1000", json={"title": sys.argv[1]})
    print(r.status_code)
"""


def main():
    with TestClient(app, raise_server_exceptions=False, headers=ALICE) as c:
        def create(headers, now=1000, **body):
            return c.post(f"/chat_threads?now={now}", json=body, headers=headers)

        def append(tid, headers, role="user", content="x", now=1000, **extra):
            return c.post(f"/chat_threads/{tid}/messages?now={now}",
                          json={"role": role, "content": content, **extra}, headers=headers)

        def gett(tid, headers):
            return c.get(f"/chat_threads/{tid}", headers=headers)

        def transcript(tid, headers):
            return c.get(f"/chat_threads/{tid}/messages", headers=headers)

        def contents(tid, headers):
            return [m["content"] for m in transcript(tid, headers).json()["results"]]

        def listing(headers):
            return c.get("/chat_threads", headers=headers)

        # ── I-ORDER — interleaved appends across two threads: per-thread seqs exactly 1..k, transcript == append order ──
        OD = H("order")
        ta = create(OD).json()["id"]
        tb = create(OD).json()["id"]
        plan = [(ta, "a1"), (tb, "b1"), (ta, "a2"), (tb, "b2"), (ta, "a3")]
        seqs = {ta: [], tb: []}
        for i, (tid, text) in enumerate(plan):
            r = append(tid, OD, content=text, now=1000 + i)
            check(f"I-ORDER append {text} -> 201", r.status_code == 201, f"got {r.status_code}")
            seqs[tid].append(r.json()["seq"])
        check("I-ORDER thread A seqs are exactly 1..3 in append order (an interleaved sibling never perturbs them)",
              seqs[ta] == [1, 2, 3], f"got {seqs[ta]}")
        check("I-ORDER thread B seqs are exactly 1..2", seqs[tb] == [1, 2], f"got {seqs[tb]}")
        check("I-ORDER transcript A reads back in exactly append order", contents(ta, OD) == ["a1", "a2", "a3"])
        check("I-ORDER transcript B reads back in exactly append order", contents(tb, OD) == ["b1", "b2"])
        check("I-ORDER the thread row's last_seq is the count of accepted appends", gett(ta, OD).json()["last_seq"] == 3)
        check("I-ORDER message rows sit at their per-seq slots (white-box)",
              store.get("chat_threads_message", f"order\x1f{ta}\x1f2")["content"] == "a2")

        # ── I-IMMUTABLE — earlier turns are byte-identical after PATCH + more appends; no route touches a written slot ──
        IM = H("immut")
        ti = create(IM, title="before").json()["id"]
        append(ti, IM, content="turn one", now=1001)
        append(ti, IM, role="assistant", content="turn two", now=1002, metadata={"model": "m1"})
        before = [store.get("chat_threads_message", f"immut\x1f{ti}\x1f{s}") for s in (1, 2)]
        c.patch(f"/chat_threads/{ti}?now=2000", json={"title": "after", "metadata": {"k": "v"}}, headers=IM)
        append(ti, IM, content="turn three", now=2001)
        after = [store.get("chat_threads_message", f"immut\x1f{ti}\x1f{s}") for s in (1, 2)]
        check("I-IMMUTABLE earlier message rows are byte-identical after PATCH + more appends", before == after,
              f"before={before} after={after}")
        check("I-IMMUTABLE the transcript order is unchanged", contents(ti, IM) == ["turn one", "turn two", "turn three"])

        # ── I-BOUNDED-MSG — the per-thread message cap REJECTS (never evicts) ──
        MB = H("msgcap")
        os.environ["CHAT_THREADS_MAX_MESSAGES"] = "3"
        tm = create(MB).json()["id"]
        for i in range(3):
            check(f"I-BOUNDED-MSG append {i + 1} within cap -> 201", append(tm, MB, content=f"m{i}", now=1000 + i).status_code == 201)
        over = append(tm, MB, content="overflow", now=2000)
        check("I-BOUNDED-MSG the 4th append past MAX_MESSAGES -> 422 (delete the cap branch in the do-fn -> 201 -> RED)",
              over.status_code == 422, f"got {over.status_code}")
        check("I-BOUNDED-MSG the transcript holds exactly the cap (nothing evicted, nothing extra)",
              contents(tm, MB) == ["m0", "m1", "m2"])
        check("I-BOUNDED-MSG last_seq stayed at the cap (the rejected append minted nothing)",
              gett(tm, MB).json()["last_seq"] == 3)
        del os.environ["CHAT_THREADS_MAX_MESSAGES"]

        # ── I-BOUNDED-THREADS — the per-owner thread COUNT is bounded (the partition-COUNT axis) ──
        TC = H("capown")
        os.environ["CHAT_THREADS_MAX_THREADS"] = "3"
        for i in range(3):
            check(f"I-BOUNDED-THREADS create {i + 1} within cap -> 201", create(TC, title=f"t{i}").status_code == 201)
        over = create(TC, title="overflow")
        check("I-BOUNDED-THREADS a 4th create past MAX_THREADS -> 422 (delete the index reject branch -> 201 -> RED)",
              over.status_code == 422, f"got {over.status_code}")
        check("I-BOUNDED-THREADS a 5th create -> 422 (not a silent success)", create(TC, title="again").status_code == 422)
        titles = [t["title"] for t in listing(TC).json()["results"]]
        check("I-BOUNDED-THREADS the existing threads are intact (REJECT, never evict)",
              sorted(titles) == ["t0", "t1", "t2"], f"got {titles}")
        del os.environ["CHAT_THREADS_MAX_THREADS"]

        # ── I-CROSS-OWNER — >=2 identities; not-yours == 404 byte-indistinguishable from missing; lists disjoint ──
        at = create(H("alice"), title="alice secret thread").json()["id"]
        append(at, H("alice"), content="alice secret turn", now=1001)
        miss = gett(999999, H("bob"))
        x_get = gett(at, H("bob"))
        x_patch = c.patch(f"/chat_threads/{at}?now=1002", json={"title": "pwn"}, headers=BOB)
        x_del = c.delete(f"/chat_threads/{at}", headers=BOB)
        x_app = append(at, H("bob"), content="intruder turn", now=1002)
        x_msgs = transcript(at, H("bob"))
        check("I-CROSS-OWNER b's GET of a's thread -> 404 (drop the owner from the key -> 200 -> RED)", x_get.status_code == 404)
        check("I-CROSS-OWNER b's PATCH -> 404", x_patch.status_code == 404)
        check("I-CROSS-OWNER b's DELETE -> 404", x_del.status_code == 404)
        check("I-CROSS-OWNER b's APPEND -> 404 (no cross-owner turn injection)", x_app.status_code == 404)
        check("I-CROSS-OWNER b's transcript read -> 404", x_msgs.status_code == 404)
        check("I-CROSS-OWNER the cross-owner 404 body == the missing 404 body (existence never leaks)",
              x_get.json() == miss.json())
        check("I-CROSS-OWNER the 404 bodies never carry alice's data",
              b"alice secret" not in x_get.content and b"alice secret" not in x_msgs.content)
        check("I-CROSS-OWNER alice's thread is untouched by bob's failed writes",
              gett(at, H("alice")).json()["title"] == "alice secret thread" and contents(at, H("alice")) == ["alice secret turn"])
        a_ids = {t["id"] for t in listing(H("alice")).json()["results"]}
        b_ids = {t["id"] for t in listing(H("bob")).json()["results"]}
        check("I-CROSS-OWNER alice's list and bob's list are disjoint (bob sees none of alice's)",
              a_ids.isdisjoint(b_ids) and at in a_ids and b_ids == set(), f"a={a_ids} b={b_ids}")

        # ── I-CASCADE — DELETE frees the cap slot, cascades to messages, and the residue is unreachable ──
        CS = H("casc")
        os.environ["CHAT_THREADS_MAX_THREADS"] = "2"
        t1 = create(CS, title="one").json()["id"]
        t2 = create(CS, title="two").json()["id"]
        append(t1, CS, content="doomed", now=1001)
        check("I-CASCADE the cap is full (a 3rd create -> 422)", create(CS, title="three").status_code == 422)
        check("I-CASCADE DELETE -> 204", c.delete(f"/chat_threads/{t1}", headers=CS).status_code == 204)
        check("I-CASCADE the thread is gone", gett(t1, CS).status_code == 404)
        check("I-CASCADE the transcript is gone (no orphaned turns behind a deleted conversation)",
              transcript(t1, CS).status_code == 404)
        check("I-CASCADE an append to the deleted thread -> 404", append(t1, CS, content="late", now=1002).status_code == 404)
        check("I-CASCADE the list excludes it", t1 not in {t["id"] for t in listing(CS).json()["results"]})
        check("I-CASCADE the message row is white-box reaped", store.get("chat_threads_message", f"casc\x1f{t1}\x1f1") is None)
        t3 = create(CS, title="reuse")
        check("I-CASCADE the cap slot was FREED — a fresh create now succeeds (delete the index-removal step -> 422 -> RED)",
              t3.status_code == 201, f"got {t3.status_code}")
        check("I-CASCADE the survivor thread is intact", gett(t2, CS).status_code == 200)
        del os.environ["CHAT_THREADS_MAX_THREADS"]

        # ── I-CONTAIN — containment BEFORE store; every re-read clean; the title/content carve is exact ──
        CN = H("hostile")
        th = create(CN).json()["id"]
        sg = c.post(f"/chat_threads/{th}/messages?now=1000", content='{"role": "user", "content": "a\\ud800b"}',
                    headers={**CN, "content-type": JSON})
        check("I-CONTAIN a lone-surrogate content -> 201 contained (not 500)", sg.status_code == 201, f"got {sg.status_code}")
        check("I-CONTAIN the contained content re-reads as U+FFFD", contents(th, CN) == ["a�b"])
        st = c.post("/chat_threads?now=1000", content='{"title": "t\\ud800t"}', headers={**CN, "content-type": JSON})
        check("I-CONTAIN a lone-surrogate title -> 201 contained", st.status_code == 201, f"got {st.status_code}")
        check("I-CONTAIN the contained title re-reads as U+FFFD (no stored poison)",
              gett(st.json()["id"], CN).json()["title"] == "t�t")
        sk = c.post("/chat_threads?now=1000", content='{"metadata": {"k\\ud800": "v\\ud800"}}',
                    headers={**CN, "content-type": JSON})
        check("I-CONTAIN a lone surrogate in a metadata KEY and VALUE -> 201 (contained)", sk.status_code == 201,
              f"got {sk.status_code} {sk.text[:120]}")
        rr = gett(sk.json()["id"], CN)
        check("I-CONTAIN the re-read of surrogate-keyed metadata does NOT 500 (delete make_well_formed on the key -> RED)",
              rr.status_code == 200 and rr.json()["metadata"] == {"k�": "v�"}, f"got {rr.status_code}")
        ct = c.post("/chat_threads?now=1000", content='{"title": "a\\u001fb"}', headers={**CN, "content-type": JSON})
        check("I-CONTAIN a control char in the TITLE -> 422 (a title is a display line, the identifier rule)",
              ct.status_code == 422, f"got {ct.status_code}")
        ml = append(th, CN, content="line one\nline two\ttabbed", now=1001)
        check("I-CONTAIN multi-line content -> 201 (content is TEXT — a chat turn with newlines is the norm)",
              ml.status_code == 201, f"got {ml.status_code}")
        check("I-CONTAIN the multi-line content re-reads byte-exact",
              contents(th, CN)[-1] == "line one\nline two\ttabbed")
        cc = c.post(f"/chat_threads/{th}/messages?now=1002", content='{"role": "user", "content": "a\\u001fb"}',
                    headers={**CN, "content-type": JSON})
        check("I-CONTAIN a control char in CONTENT is stored as DATA (never a key component -> no forgery surface)",
              cc.status_code == 201 and contents(th, CN)[-1] == "a\x1fb", f"got {cc.status_code}")

        # ── I-LIVENESS — white-box delete-tear residue (row present, index entry gone) is 404 on EVERY surface ──
        TR = H("tear")
        tt = create(TR, title="ghost").json()["id"]
        append(tt, TR, content="ghost turn", now=1001)

        def drop_tid(tids):
            return [t for t in (tids or []) if t != tt], None

        store.do("chat_threads_index", "tear", drop_tid)   # simulate the delete crash residue: index entry gone, row remains
        check("I-LIVENESS the ghost row exists white-box (the tear is real)",
              store.get("chat_threads_thread", f"tear\x1f{tt}") is not None)
        check("I-LIVENESS GET of the ghost -> 404 (the index is the liveness authority)", gett(tt, TR).status_code == 404)
        check("I-LIVENESS PATCH of the ghost -> 404",
              c.patch(f"/chat_threads/{tt}?now=1002", json={"title": "back"}, headers=TR).status_code == 404)
        check("I-LIVENESS DELETE of the ghost -> 404", c.delete(f"/chat_threads/{tt}", headers=TR).status_code == 404)
        check("I-LIVENESS APPEND to the ghost -> 404 (residue can never accept new turns)",
              append(tt, TR, content="late", now=1003).status_code == 404)
        check("I-LIVENESS the ghost's transcript -> 404 (orphan turns are unreachable)", transcript(tt, TR).status_code == 404)
        check("I-LIVENESS the list excludes the ghost", listing(TR).json()["results"] == [])

        # ── I-ACTIVITY — updated_at is the list authority; ties break newest-id-first ──
        AC = H("activity")
        a1 = create(AC, now=1000, title="older").json()["id"]
        a2 = create(AC, now=1001, title="newer").json()["id"]
        order0 = [t["id"] for t in listing(AC).json()["results"]]
        check("I-ACTIVITY newest creation leads before any append", order0 == [a2, a1], f"got {order0}")
        append(a1, AC, content="wake up", now=2000)
        order1 = [t["id"] for t in listing(AC).json()["results"]]
        check("I-ACTIVITY an append LIFTS the older thread to the head (updated_at authority; drop the bump -> RED)",
              order1 == [a1, a2], f"got {order1}")
        a3 = create(AC, now=3000, title="tie1").json()["id"]
        a4 = create(AC, now=3000, title="tie2").json()["id"]
        order2 = [t["id"] for t in listing(AC).json()["results"][:2]]
        check("I-ACTIVITY equal updated_at ties break newest-id-first (pinned across the languages)",
              order2 == [a4, a3], f"got {order2}")

        # ── I-GAP — a missing seq slot (the mint/write tear) is skipped: order intact, count honest, no 5xx ──
        GP = H("gap")
        tg = create(GP).json()["id"]
        append(tg, GP, content="g1", now=1001)
        append(tg, GP, content="g2", now=1002)
        store.delete_("chat_threads_message", f"gap\x1f{tg}\x1f1")   # simulate the mint/write tear residue
        tr = transcript(tg, GP)
        check("I-GAP a torn seq slot never 5xxs the transcript", tr.status_code == 200, f"got {tr.status_code}")
        check("I-GAP the surviving turns keep their order", [m["content"] for m in tr.json()["results"]] == ["g2"])
        check("I-GAP last_seq stays the honest high-water mark (accepted appends, not retrievable count)",
              gett(tg, GP).json()["last_seq"] == 2)

    # ── I-RACE-APPEND — two processes append to the SAME thread; the do-seam serializes the seq mint ──
    if os.getenv("DATABASE_PATH"):
        with TestClient(app, raise_server_exceptions=False, headers=H("racer")) as c:
            rid = c.post("/chat_threads?now=1000", json={"title": "raced"}, headers=H("racer")).json()["id"]
        procs = [subprocess.Popen([sys.executable, "-c", RACE_APPEND_WORKER, f"raced-{i}", str(rid)],
                                  cwd=os.getcwd(), env={**os.environ, "LOG_LEVEL": "silent"},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for i in range(2)]
        outs = []
        for p in procs:
            so, se = p.communicate(timeout=120)
            outs.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:120]))
        seqs = sorted(int(o) for rc, o in outs if rc == 0 and str(o).isdigit())
        check("I-RACE-APPEND both racing appends succeed with DISTINCT seqs", len(seqs) == 2 and seqs[0] != seqs[1],
              f"got {outs}")
        check("I-RACE-APPEND the seqs are consecutive 1,2 (no lost update — a get-then-put mint would collide -> RED)",
              seqs == [1, 2], f"got {seqs}")
        with TestClient(app, raise_server_exceptions=False, headers=H("racer")) as c:
            row = c.get(f"/chat_threads/{rid}", headers=H("racer")).json()
            check("I-RACE-APPEND last_seq counted BOTH appends (no lost update on the thread row)", row["last_seq"] == 2,
                  f"got {row}")
            got = {m["content"] for m in c.get(f"/chat_threads/{rid}/messages", headers=H("racer")).json()["results"]}
            check("I-RACE-APPEND both racers' turns are retrievable", got == {"raced-0", "raced-1"}, f"got {got}")

        # ── I-BOUNDED-THREADS (race arm) — two processes race the LAST thread slot; exactly one wins ──
        env = {**os.environ, "LOG_LEVEL": "silent", "CHAT_THREADS_MAX_THREADS": "1"}
        procs = [subprocess.Popen([sys.executable, "-c", RACE_CREATE_WORKER, f"cap-{i}"],
                                  cwd=os.getcwd(), env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for i in range(2)]
        stats = []
        for p in procs:
            so, se = p.communicate(timeout=120)
            stats.append((so or "").strip().splitlines()[-1] if (so or "").strip() else f"rc={p.returncode} {se[:80]}")
        check("I-BOUNDED-THREADS raced last slot -> exactly one 201 and one 422 (the index-do serializes the cap)",
              sorted(stats) == ["201", "422"], f"got {stats}")
        with TestClient(app, raise_server_exceptions=False, headers=H("racecap")) as c:
            n = len(c.get("/chat_threads", headers=H("racecap")).json()["results"])
            check("I-BOUNDED-THREADS the raced owner holds exactly ONE thread (never over-cap)", n == 1, f"got {n}")
    else:
        print("  [FAIL] I-RACE-APPEND / I-BOUNDED-THREADS race NOT RUN — DATABASE_PATH unset (the harness must provide it)")
        failures.append("races not run")

    print(f"CHAT_THREADS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
