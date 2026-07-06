"""PAYMENTS INVARIANTS (waves 1–3) — correctness proofs for the authorize/get/list + capture/void/refund dangerous properties.
Run against the python app (cwd = <app>/python; DATABASE_PATH + APP_TEST_SESSIONS set by the harness). Credited by
EXIT CODE ONLY.

Wave 1 (authorize / get / list):
  I-ONCE   exactly-once authorization — a replayed key returns the STORED intent (same DERIVED id); the same key with a
           different amount/currency is 409 and the original intent survives.
  I-GET    an intent is retrievable by its derived id; a missing id is 404.
  I-OWN    OWNER ISOLATION — caller B can never GET caller A's intent (404); the Idempotency-Key is caller-PRIVATE.
  I-LIST   the list returns ONLY the caller's own intents (owner-filtered), bounded (a page + a cursor).
  I-AMOUNT strict, CAPPED amounts (the cross-language overflow floor) + the closed ISO-4217 currency set.
Wave 2 (capture / void — the conserved state machine):
  I-CAPTURE / I-CAPTURE-PARTIAL  capture settles the authorization; a partial capture auto-VOIDS the remainder, so
           amount_captured + amount_voided == amount (every authorized cent accounted for — CONSERVATION).
  I-CONSERVE-CAP  an over-capture (> authorized) is 422 and the intent survives (no money created).
  I-VOID   void releases the full authorization (amount_voided == amount, amount_captured == 0).
  I-STATE  the forbidden transitions are all 409 — void-after-capture, double-capture, capture-after-void, double-void.
  I-OWN-TX caller B can never capture/void caller A's intent (404, not 409/200); the victim's intent is untouched.
Wave 3 (refund — idempotent + conserved):
  I-REFUND / I-CONSERVE-REF  refunds accumulate; Σrefunds may NEVER exceed amount_captured (no money created -> 422).
  I-ONCE-REFUND  the same Idempotency-Key is idempotent (no double-refund); a different amount under it is 409.
  I-STATE-REF / I-CURRENCY / I-OWN-REF  refund requires the captured state (409 else); currency is immutable; B can't refund A's.
Races (cross-PROCESS — the only wall the gates are vacuous on for do()-only transitions):
  I-RACE-CREATE  two processes racing one key authorize EXACTLY ONCE (same intent id).
  I-RACE-CAP     two processes capturing one intent -> exactly one 200 + one 409 (no double-capture).
  I-RACE-REFUND  two processes over-refunding one intent -> exactly one 200 + one 422 (conservation holds under a race).
Every route requires the authenticated caller, so every call carries a 'Bearer test:<subject>' token resolved by
the APP_TEST_SESSIONS=1 seam (set below; inherited by the race subprocesses)."""
import os
import subprocess
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # the test-session seam: a 'test:<subject>' bearer resolves (inert in prod)

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


RACE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
with TestClient(app, raise_server_exceptions=False) as c:
    r = c.post("/payments", json={"amount": 4242, "currency": "usd"},
               headers={"Authorization": "Bearer test:alice", "Idempotency-Key": "RACE"})
    print(r.json()["id"] if r.status_code == 201 else f"status={r.status_code}")
"""

CAPTURE_RACE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
PID = sys.argv[1]
with TestClient(app, raise_server_exceptions=False) as c:
    r = c.post(f"/payments/{PID}/capture", json={"amount": 100}, headers={"Authorization": "Bearer test:alice"})
    print(r.status_code)
"""

REFUND_RACE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
PID, KEY = sys.argv[1], sys.argv[2]
with TestClient(app, raise_server_exceptions=False) as c:
    r = c.post(f"/payments/{PID}/refund", json={"amount": 60},
               headers={"Authorization": "Bearer test:alice", "Idempotency-Key": KEY})
    print(r.status_code)
"""


def main():
    rc_pid = None
    with TestClient(app, raise_server_exceptions=False) as c:
        def authorize(amount, key, sub="alice", currency="usd"):
            return c.post("/payments", json={"amount": amount, "currency": currency},
                          headers={"Authorization": f"Bearer test:{sub}", "Idempotency-Key": key})

        def get(pid, sub="alice"):
            return c.get(f"/payments/{pid}", headers={"Authorization": f"Bearer test:{sub}"})

        def capture(pid, amount, sub="alice"):
            return c.post(f"/payments/{pid}/capture", json={"amount": amount},
                          headers={"Authorization": f"Bearer test:{sub}"})

        def void(pid, sub="alice"):
            return c.post(f"/payments/{pid}/void", headers={"Authorization": f"Bearer test:{sub}"})

        def refund(pid, amount, key, sub="alice"):
            return c.post(f"/payments/{pid}/refund", json={"amount": amount},
                          headers={"Authorization": f"Bearer test:{sub}", "Idempotency-Key": key})

        # ── WAVE 1 ─────────────────────────────────────────────────────────────────────────────────────────────
        # I-ONCE — exactly-once authorization: a replay returns the SAME intent; a different body under the same key 409s
        first = authorize(2000, "K1")
        check("I-ONCE a first authorize -> 201 authorized",
              first.status_code == 201 and first.json()["status"] == "authorized")
        replay = authorize(2000, "K1")
        check("I-ONCE b replay (same key+body) -> the SAME intent",
              replay.status_code == 201 and replay.json() == first.json())
        check("I-ONCE c same key, different amount -> 409", authorize(999, "K1").status_code == 409)
        check("I-ONCE d same key, different currency -> 409", authorize(2000, "K1", currency="eur").status_code == 409)
        check("I-ONCE e the original intent survives the conflict attempts", authorize(2000, "K1").json() == first.json())

        # I-GET — retrieve a real intent by its DERIVED id; a missing id is 404
        pid = first.json()["id"]
        got = get(pid)
        check("I-GET a authorize then get by id -> 200, same intent", got.status_code == 200 and got.json() == first.json())
        check("I-GET b a missing id -> 404", get("nosuchintent").status_code == 404)

        # I-OWN — owner isolation: caller B can NEVER see caller A's intent by id; the key is caller-private
        a_pid = authorize(5000, "OWN", sub="alice").json()["id"]
        check("I-OWN a bob cannot GET alice's intent (cross-caller -> 404)", get(a_pid, sub="bob").status_code == 404)
        bob_own = authorize(7000, "OWN", sub="bob")     # SAME key, DIFFERENT caller -> B's OWN distinct intent
        check("I-OWN b bob's same-key authorize is a DIFFERENT intent (caller-private key)",
              bob_own.status_code == 201 and bob_own.json()["id"] != a_pid and bob_own.json()["amount"] == 7000)
        check("I-OWN c alice cannot GET bob's intent", get(bob_own.json()["id"], sub="alice").status_code == 404)

        # I-LIST — the list returns ONLY the caller's own intents (owner-filtered), bounded
        carol1 = authorize(11, "C1", sub="carol").json()["id"]
        carol2 = authorize(22, "C2", sub="carol").json()["id"]
        clist = c.get("/payments", headers={"Authorization": "Bearer test:carol"})
        cids = {r["id"] for r in clist.json()["results"]}
        check("I-LIST a carol's list contains exactly her two intents",
              clist.status_code == 200 and cids == {carol1, carol2})
        check("I-LIST b carol's list never leaks another caller's intent", a_pid not in cids and pid not in cids)
        p1 = c.get("/payments?limit=1", headers={"Authorization": "Bearer test:carol"})
        check("I-LIST c a bounded page returns 1 + a next cursor",
              len(p1.json()["results"]) == 1 and p1.json()["next_cursor"] is not None)

        # I-AMOUNT — strict, CAPPED amounts (the overflow floor) + the closed currency set
        for bad in (0, -5, "x", 500.0, (1 << 53)):   # zero · negative · string · float · over-cap (2^53 = MAX+1)
            check(f"I-AMOUNT invalid amount {bad!r} -> 422", authorize(bad, "BAD").status_code == 422)
        check("I-AMOUNT the cap boundary MAX_AMOUNT (2^53-1) is accepted",
              authorize((1 << 53) - 1, "CAPOK").status_code == 201)
        check("I-AMOUNT a non-ISO-4217 currency -> 422", authorize(10, "BADCUR", currency="xyz").status_code == 422)

        # ── WAVE 2 — capture / void (the conserved state machine) ───────────────────────────────────────────────
        # I-CAPTURE — full capture: captured=amount, voided=0; the GET reflects it
        cap_pid = authorize(1000, "CAP").json()["id"]
        capped = capture(cap_pid, 1000)
        check("I-CAPTURE a full capture -> 200 captured",
              capped.status_code == 200 and capped.json()["status"] == "captured")
        check("I-CAPTURE b captured=amount, voided=0 (conservation: captured+voided==authorized)",
              capped.json()["amount_captured"] == 1000 and capped.json()["amount_voided"] == 0)
        check("I-CAPTURE c the GET reflects the captured state", get(cap_pid).json() == capped.json())

        # I-CAPTURE-PARTIAL — the uncaptured remainder is auto-voided (conservation closes)
        par = capture(authorize(1000, "PAR").json()["id"], 600)
        check("I-CAPTURE-PARTIAL captured=600, voided=400 (600+400==1000, every cent accounted)",
              par.status_code == 200 and par.json()["amount_captured"] == 600 and par.json()["amount_voided"] == 400)

        # I-CONSERVE-CAP — an over-capture is refused; the intent stays authorized (no money created)
        oc_pid = authorize(1000, "OC").json()["id"]
        check("I-CONSERVE-CAP a capture > authorized -> 422", capture(oc_pid, 1500).status_code == 422)
        check("I-CONSERVE-CAP b the intent survives, still authorized", get(oc_pid).json()["status"] == "authorized")

        # I-VOID — void releases the full authorization; captured stays 0
        voided = void(authorize(800, "V").json()["id"])
        check("I-VOID a void -> 200 voided", voided.status_code == 200 and voided.json()["status"] == "voided")
        check("I-VOID b voided=amount, captured=0 (conservation)",
              voided.json()["amount_voided"] == 800 and voided.json()["amount_captured"] == 0)

        # I-STATE — the forbidden transitions are all 409 (the state machine)
        s1 = authorize(100, "S1").json()["id"]
        capture(s1, 100)
        check("I-STATE a void-after-capture -> 409", void(s1).status_code == 409)
        check("I-STATE b double-capture -> 409", capture(s1, 100).status_code == 409)
        s2 = authorize(100, "S2").json()["id"]
        void(s2)
        check("I-STATE c capture-after-void -> 409", capture(s2, 100).status_code == 409)
        check("I-STATE d double-void -> 409", void(s2).status_code == 409)

        # I-OWN-TX — caller B can never capture/void caller A's intent (404), and the victim's intent is untouched
        own_pid = authorize(500, "TOWN", sub="alice").json()["id"]
        check("I-OWN-TX a bob cannot capture alice's intent -> 404", capture(own_pid, 500, sub="bob").status_code == 404)
        check("I-OWN-TX b bob cannot void alice's intent -> 404", void(own_pid, sub="bob").status_code == 404)
        check("I-OWN-TX c alice's intent is untouched (still authorized)", get(own_pid).json()["status"] == "authorized")

        # ── WAVE 3 — refund (idempotent, conserved Σrefunds <= captured) ────────────────────────────────────────
        # I-REFUND — a refund on a captured intent accumulates; amount_refunded tracks, status stays captured
        rf_pid = authorize(1000, "RF").json()["id"]
        capture(rf_pid, 1000)
        r1 = refund(rf_pid, 300, "RK1")
        check("I-REFUND a a refund on a captured intent -> 200, amount_refunded tracks",
              r1.status_code == 200 and r1.json()["amount_refunded"] == 300 and r1.json()["status"] == "captured")
        check("I-REFUND b a second refund accumulates (300+200=500)",
              refund(rf_pid, 200, "RK2").json()["amount_refunded"] == 500)

        # I-ONCE-REFUND — same key is idempotent (no double-refund); a different amount under the same key is 409
        again = refund(rf_pid, 300, "RK1")
        check("I-ONCE-REFUND a same key+amount -> SAME intent, amount_refunded UNCHANGED (no double-refund)",
              again.status_code == 200 and again.json()["amount_refunded"] == 500)
        check("I-ONCE-REFUND b same key, different amount -> 409", refund(rf_pid, 999, "RK1").status_code == 409)

        # I-CONSERVE-REF — Σrefunds may never exceed captured (no money created)
        check("I-CONSERVE-REF a a refund exceeding the remaining captured -> 422 (500 refunded, 600 > 500 left)",
              refund(rf_pid, 600, "RK3").status_code == 422)
        check("I-CONSERVE-REF b the exact remaining (500) is allowed -> fully refunded (1000)",
              refund(rf_pid, 500, "RK3").json()["amount_refunded"] == 1000)
        check("I-CONSERVE-REF c any refund beyond a fully-refunded intent -> 422",
              refund(rf_pid, 1, "RK4").status_code == 422)

        # I-STATE-REF — refund requires the CAPTURED state (refund-before-capture / after-void -> 409)
        check("I-STATE-REF a refund an authorized (un-captured) intent -> 409",
              refund(authorize(100, "SR1").json()["id"], 50, "RKx").status_code == 409)
        sr2 = authorize(100, "SR2").json()["id"]
        void(sr2)
        check("I-STATE-REF b refund a voided intent -> 409", refund(sr2, 50, "RKy").status_code == 409)

        # I-CURRENCY — the lifecycle never mutates the intent currency (immutable by construction)
        cur_pid = authorize(500, "CUR", currency="eur").json()["id"]
        capture(cur_pid, 500)
        refund(cur_pid, 100, "CURK")
        check("I-CURRENCY the currency is immutable across capture+refund (still 'eur')",
              get(cur_pid).json()["currency"] == "eur")

        # I-OWN-REF — caller B can never refund caller A's captured intent (404)
        orf_pid = authorize(200, "ORF", sub="alice").json()["id"]
        capture(orf_pid, 200)
        check("I-OWN-REF bob cannot refund alice's intent -> 404", refund(orf_pid, 50, "ORK", sub="bob").status_code == 404)

        # pre-authorize durable intents for the cross-process races (run after the block, against the same DB)
        rc_pid = authorize(100, "RACECAP").json()["id"]
        rref_pid = authorize(100, "RACEREF").json()["id"]
        capture(rref_pid, 100)

    # ── cross-PROCESS races (require a real DATABASE_PATH so two processes share the store) ─────────────────────
    if os.getenv("DATABASE_PATH"):
        def run(workers):
            procs = [subprocess.Popen([sys.executable, "-c"] + w, cwd=os.getcwd(),
                                      env={**os.environ, "LOG_LEVEL": "silent"},
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for w in workers]
            outs = []
            for p in procs:
                so, se = p.communicate(timeout=120)
                outs.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:160]))
            return outs

        # I-RACE-CREATE — two processes racing one key authorize EXACTLY ONCE (both receive the same intent id)
        co = run([[RACE_WORKER], [RACE_WORKER]])
        ids = [o for rc, o in co if rc == 0]
        check("I-RACE-CREATE two processes racing one key -> the SAME intent id (no double-authorize)",
              len(ids) == 2 and ids[0] == ids[1] and not ids[0].startswith("status="), f"got {co}")

        # I-RACE-CAP — two processes capturing one intent -> exactly one 200 + one 409 (no double-capture)
        ro = run([[CAPTURE_RACE_WORKER, rc_pid], [CAPTURE_RACE_WORKER, rc_pid]])
        codes = sorted(int(o) for rc, o in ro if rc == 0 and o.isdigit())
        check("I-RACE-CAP two processes capturing one intent -> exactly one 200 + one 409 (no double-capture)",
              codes == [200, 409], f"got {ro}")

        # I-RACE-REFUND — two processes refunding amounts that TOGETHER exceed captured (60+60 > 100) -> exactly one
        # 200 + one 422 (conservation holds under a race: Σrefunds never exceeds captured)
        fo = run([[REFUND_RACE_WORKER, rref_pid, "RR1"], [REFUND_RACE_WORKER, rref_pid, "RR2"]])
        rcodes = sorted(int(o) for rc, o in fo if rc == 0 and o.isdigit())
        check("I-RACE-REFUND two processes over-refunding one intent -> exactly one 200 + one 422 (conservation holds)",
              rcodes == [200, 422], f"got {fo}")
    else:
        print("  [FAIL] cross-process races NOT RUN — DATABASE_PATH unset (the harness must provide it)")
        failures.append("races not run")

    print(f"PAYMENTS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
