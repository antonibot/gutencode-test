"""INVOICES INVARIANTS — correctness proofs for the create-draft / get / list dangerous properties.
Run against the python app (cwd = <app>/python; DATABASE_PATH + APP_TEST_SESSIONS set by the harness). Credited by
EXIT CODE ONLY.

Wave 1 (create-draft / get / list):
  I-CONSERVE  the server RECOMPUTES every total (line amount = unit*qty, subtotal = sum of amounts, total = subtotal+tax)
              and DISCARDS any client-supplied subtotal/total/amount_paid — a stored bill always reconciles to lines+tax.
  I-OVERFLOW  the per-line PRODUCT and the running subtotal/total are CAPPED at 2^53-1 (the cross-language sum floor):
              a line whose unit*qty overflows -> 422; a set of lines whose sum overflows -> 422; the boundary is accepted.
  I-IDEMPOTENT a replayed key+body returns the STORED draft (same DERIVED id); the same key with a different body is a
              409 and the original draft survives.
  I-GET       a draft is retrievable by its derived id; a missing id is 404.
  I-OWN       OWNER ISOLATION — caller B can never GET caller A's bill (404); the Idempotency-Key is caller-PRIVATE.
  I-LIST      the list returns ONLY the caller's own bills (owner-filtered), bounded (a page + a cursor).
  I-FIELDS    strict, CAPPED amounts + a >=1 line count + the closed ISO-4217 currency set + well-formed text.
Wave 2 (edit-draft / finalize — the immutability trap door + the legal number):
  I-IMMUTABLE a DRAFT is editable (PATCH recomputes); finalize FREEZES the bill, and a post-finalize PATCH is 409.
  I-FINALIZE  finalize is draft -> open + assigns a NUMBER (minted OUTSIDE the transition do()); re-finalize is
              idempotent (the same number). A half-finalized (crash) bill is COMPLETED by a re-finalize.
  I-MONOTONIC-NODUP  per-owner numbers are monotonic + UNIQUE (no two bills ever share a number; gaps are allowed).
  I-STATE-TX  finalize a missing bill is 404; ownership holds (B cannot finalize/PATCH A's bill; A's bill untouched).
Wave 3 (pay / void / mark_uncollectible — the terminal state machine):
  I-PAY       open -> paid: amount_paid == total (CONSERVATION — fully paid, never partial); re-pay is idempotent.
  I-VOID / I-UNCOLLECTIBLE  open -> void / uncollectible; amount_paid stays 0; idempotent.
  I-PAY-STATE only a finalized (open) bill transitions: pay-a-draft / void-a-paid / pay-a-void are all 409; bill survives.
  I-HALF-FINALIZED a TORN finalize (open + number=null, the crash/race window) REFUSES pay/void (409) until a re-finalize
              completes its number — no terminal bill ever strands without a legal number (the Pillar-1 concurrency fix).
  I-OWN-TX2   caller B can never pay/void caller A's bill (404, not 409/200).
Races (cross-PROCESS — the only wall the gates are vacuous on for do()/claim-only transitions):
  I-RACE-CREATE    two processes racing one key create EXACTLY ONE draft (same bill id).
  I-RACE-FINALIZE  two processes finalizing one draft -> exactly ONE number attached, no duplicate (loser's = a gap).
  I-RACE-TERMINAL  two processes racing pay-vs-void on one open bill -> exactly one 200 + one 409, ONE terminal state.
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
MAX = (1 << 53) - 1   # the cross-language-safe amount ceiling (2^53-1)


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
    r = c.post("/invoices", json={"customer": "acme", "currency": "usd", "tax": 0,
               "line_items": [{"description": "race", "quantity": 1, "unit_amount": 4242}]},
               headers={"Authorization": "Bearer test:alice", "Idempotency-Key": "RACE"})
    print(r.json()["id"] if r.status_code == 201 else f"status={r.status_code}")
"""

FINALIZE_RACE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
IID = sys.argv[1]
with TestClient(app, raise_server_exceptions=False) as c:
    r = c.post(f"/invoices/{IID}/finalize", headers={"Authorization": "Bearer test:racef"})
    print(r.json().get("number") if r.status_code == 200 else f"status={r.status_code}")
"""

TERMINAL_RACE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
IID, ACTION = sys.argv[1], sys.argv[2]
with TestClient(app, raise_server_exceptions=False) as c:
    r = c.post(f"/invoices/{IID}/{ACTION}", headers={"Authorization": "Bearer test:racet"})
    print(r.status_code)
"""

STATE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
IID = sys.argv[1]
with TestClient(app, raise_server_exceptions=False) as c:
    print(c.get(f"/invoices/{IID}", headers={"Authorization": "Bearer test:racet"}).json()["status"])
"""


def line(desc, q, u):
    return {"description": desc, "quantity": q, "unit_amount": u}


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        def create(line_items, key, sub="alice", currency="usd", tax=0, customer="acme", extra=None):
            body = {"customer": customer, "currency": currency, "tax": tax, "line_items": line_items}
            if extra:
                body.update(extra)
            return c.post("/invoices", json=body,
                          headers={"Authorization": f"Bearer test:{sub}", "Idempotency-Key": key})

        def get(iid, sub="alice"):
            return c.get(f"/invoices/{iid}", headers={"Authorization": f"Bearer test:{sub}"})

        # I-CONSERVE — the server recomputes; a client-supplied subtotal/total/amount_paid is DISCARDED
        inv = create([line("widget", 3, 500), line("setup fee", 1, 1000)], "C1", tax=100)
        check("I-CONSERVE a create -> 201 draft", inv.status_code == 201 and inv.json()["status"] == "draft")
        j = inv.json()
        check("I-CONSERVE b line amounts = unit*qty (1500, 1000)",
              [li["amount"] for li in j["line_items"]] == [1500, 1000])
        check("I-CONSERVE c subtotal = sum of amounts (1500+1000=2500)", j["subtotal"] == 2500)
        check("I-CONSERVE d total = subtotal + tax (2500+100=2600)", j["total"] == 2600)
        forged = create([line("widget", 3, 500)], "C2", extra={"total": 0, "subtotal": 0, "amount_paid": 9999})
        fj = forged.json()
        check("I-CONSERVE e a client-supplied total/subtotal/amount_paid is DISCARDED (server recomputes from lines)",
              fj["subtotal"] == 1500 and fj["total"] == 1500 and fj["amount_paid"] == 0)

        # I-OVERFLOW — the per-line product + the running sum are capped (the Go-int64-wrap / Node-float floor)
        check("I-OVERFLOW a a line whose unit*qty exceeds 2^53-1 -> 422 (product overflow; 2^52 * 4 = 2^54)",
              create([line("x", 4503599627370496, 4)], "OV1").status_code == 422)
        check("I-OVERFLOW b a SET of lines whose sum exceeds 2^53-1 -> 422 (sum overflow)",
              create([line("a", 1, MAX), line("b", 1, MAX)], "OV2").status_code == 422)
        check("I-OVERFLOW c the cap boundary (one line == MAX, tax 0) is accepted",
              create([line("x", 1, MAX)], "OV3").status_code == 201)
        check("I-OVERFLOW d subtotal + tax over the cap -> 422",
              create([line("x", 1, MAX)], "OV4", tax=1).status_code == 422)

        # I-IDEMPOTENT — a replay returns the SAME draft; a different body under the same key 409s
        first = create([line("w", 1, 500)], "K1")
        replay = create([line("w", 1, 500)], "K1")
        check("I-IDEMPOTENT a replay (same key+body) -> the SAME draft",
              replay.status_code == 201 and replay.json() == first.json())
        check("I-IDEMPOTENT b same key, different body -> 409", create([line("w", 2, 500)], "K1").status_code == 409)
        check("I-IDEMPOTENT c the original draft survives the conflict", get(first.json()["id"]).json() == first.json())

        # I-GET — retrieve by derived id; a missing id is 404
        iid = first.json()["id"]
        g = get(iid)
        check("I-GET a get by id -> 200, same draft", g.status_code == 200 and g.json() == first.json())
        check("I-GET b a missing id -> 404", get("nosuchbill").status_code == 404)

        # I-OWN — owner isolation: caller B can NEVER see caller A's bill; the key is caller-private
        a_iid = create([line("a", 1, 5000)], "OWN", sub="alice").json()["id"]
        check("I-OWN a bob cannot GET alice's bill (cross-caller -> 404)", get(a_iid, sub="bob").status_code == 404)
        bob_own = create([line("b", 1, 7000)], "OWN", sub="bob")   # SAME key, DIFFERENT caller -> B's OWN distinct bill
        check("I-OWN b bob's same-key create is a DIFFERENT bill (caller-private key)",
              bob_own.status_code == 201 and bob_own.json()["id"] != a_iid and bob_own.json()["total"] == 7000)
        check("I-OWN c alice cannot GET bob's bill", get(bob_own.json()["id"], sub="alice").status_code == 404)

        # I-LIST — the list returns ONLY the caller's own bills (owner-filtered), bounded
        carol1 = create([line("c", 1, 11)], "L1", sub="carol").json()["id"]
        carol2 = create([line("c", 1, 22)], "L2", sub="carol").json()["id"]
        clist = c.get("/invoices", headers={"Authorization": "Bearer test:carol"})
        cids = {r["id"] for r in clist.json()["results"]}
        check("I-LIST a carol's list contains exactly her two bills",
              clist.status_code == 200 and cids == {carol1, carol2})
        check("I-LIST b carol's list never leaks another caller's bill", a_iid not in cids)
        p1 = c.get("/invoices?limit=1", headers={"Authorization": "Bearer test:carol"})
        check("I-LIST c a bounded page returns 1 + a next cursor",
              len(p1.json()["results"]) == 1 and p1.json()["next_cursor"] is not None)

        # I-FIELDS — strict, capped amounts + line count + closed currency + well-formed text
        check("I-FIELDS a an empty line list -> 422", create([], "F1").status_code == 422)
        check("I-FIELDS b a zero quantity -> 422", create([line("x", 0, 5)], "F2").status_code == 422)
        check("I-FIELDS c a float unit_amount -> 422",
              c.post("/invoices", json={"customer": "acme", "currency": "usd", "tax": 0,
                     "line_items": [{"description": "x", "quantity": 1, "unit_amount": 5.0}]},
                     headers={"Authorization": "Bearer test:alice", "Idempotency-Key": "F3"}).status_code == 422)
        check("I-FIELDS d an over-cap unit_amount (2^53) -> 422", create([line("x", 1, 1 << 53)], "F4").status_code == 422)
        check("I-FIELDS e a non-ISO-4217 currency -> 422", create([line("x", 1, 5)], "F5", currency="xyz").status_code == 422)
        check("I-FIELDS f a control-char customer -> 422", create([line("x", 1, 5)], "F6", customer="a\x01b").status_code == 422)

        # ── WAVE 2 — edit-draft (PATCH) + finalize (the immutability trap door + the monotonic number) ────────────
        # I-IMMUTABLE — a DRAFT is editable (PATCH recomputes); finalize FREEZES it; a post-finalize PATCH is 409
        ed_id = create([line("v1", 1, 100)], "ED", sub="edit").json()["id"]
        patched = c.patch(f"/invoices/{ed_id}",
                          json={"customer": "acme2", "currency": "usd", "tax": 50, "line_items": [line("v2", 2, 200)]},
                          headers={"Authorization": "Bearer test:edit"})
        check("I-IMMUTABLE a a draft is editable (PATCH recomputes: 2*200=400 + 50 tax = 450)",
              patched.status_code == 200 and patched.json()["subtotal"] == 400 and patched.json()["total"] == 450
              and patched.json()["customer"] == "acme2")
        check("I-IMMUTABLE b the GET reflects the edit", get(ed_id, sub="edit").json() == patched.json())

        # I-FINALIZE — draft -> open + a NUMBER is assigned; re-finalize is idempotent (the SAME number)
        fin = create([line("f", 1, 900)], "FIN", sub="finA")
        fin_id = fin.json()["id"]
        check("I-FINALIZE a a fresh draft has no number", fin.json()["number"] is None and fin.json()["status"] == "draft")
        finalized = c.post(f"/invoices/{fin_id}/finalize", headers={"Authorization": "Bearer test:finA"})
        check("I-FINALIZE b finalize -> 200 open + the first number (INV-000001)",
              finalized.status_code == 200 and finalized.json()["status"] == "open"
              and finalized.json()["number"] == "INV-000001")
        again = c.post(f"/invoices/{fin_id}/finalize", headers={"Authorization": "Bearer test:finA"})
        check("I-FINALIZE c re-finalize is idempotent (same number, still open)",
              again.status_code == 200 and again.json() == finalized.json())

        # I-IMMUTABLE c — a PATCH after finalize is 409, and the finalized bill is byte-for-byte unchanged
        froze = c.patch(f"/invoices/{fin_id}",
                        json={"customer": "hacked", "currency": "usd", "tax": 0, "line_items": [line("z", 1, 1)]},
                        headers={"Authorization": "Bearer test:finA"})
        check("I-IMMUTABLE c a PATCH on a finalized bill -> 409 (frozen)", froze.status_code == 409)
        check("I-IMMUTABLE d the finalized bill is UNCHANGED (total still 900, customer still acme)",
              get(fin_id, sub="finA").json() == finalized.json())

        # I-MONOTONIC-NODUP — per-owner numbers are monotonic + unique (no two bills share a number)
        nums = []
        for i in range(3):
            mid = create([line("m", 1, 10 + i)], f"M{i}", sub="monB").json()["id"]
            nums.append(c.post(f"/invoices/{mid}/finalize", headers={"Authorization": "Bearer test:monB"}).json()["number"])
        check("I-MONOTONIC-NODUP three finalizes -> monotonic, unique numbers (INV-000001..3)",
              nums == ["INV-000001", "INV-000002", "INV-000003"] and len(set(nums)) == 3)

        # I-STATE-TX — finalize a missing bill is 404; ownership holds (B cannot finalize/PATCH A's bill)
        own2 = create([line("o", 1, 500)], "OWN2", sub="alice").json()["id"]
        check("I-STATE-TX a finalize a missing bill -> 404",
              c.post("/invoices/nope/finalize", headers={"Authorization": "Bearer test:alice"}).status_code == 404)
        check("I-STATE-TX b bob cannot finalize alice's draft -> 404",
              c.post(f"/invoices/{own2}/finalize", headers={"Authorization": "Bearer test:bob"}).status_code == 404)
        check("I-STATE-TX c bob cannot PATCH alice's draft -> 404",
              c.patch(f"/invoices/{own2}",
                      json={"customer": "x", "currency": "usd", "tax": 0, "line_items": [line("x", 1, 1)]},
                      headers={"Authorization": "Bearer test:bob"}).status_code == 404)
        check("I-STATE-TX d alice's draft is untouched (still draft, total 500)",
              get(own2).json()["status"] == "draft" and get(own2).json()["total"] == 500)

        # ── WAVE 3 — the TERMINAL transitions (pay / void / mark_uncollectible) ─────────────────────────────────────
        def finalize_bill(key, sub, amount=300):
            iid = create([line("t", 1, amount)], key, sub=sub).json()["id"]
            c.post(f"/invoices/{iid}/finalize", headers={"Authorization": f"Bearer test:{sub}"})
            return iid

        def tx(iid, action, sub):
            return c.post(f"/invoices/{iid}/{action}", headers={"Authorization": f"Bearer test:{sub}"})

        # I-PAY — open -> paid; amount_paid == total (CONSERVATION: fully paid); re-pay is idempotent (no double-pay)
        pay_id = finalize_bill("PAY", "payer", 300)
        paid = tx(pay_id, "pay", "payer")
        check("I-PAY a pay an open bill -> 200 paid, amount_paid == total (300)",
              paid.status_code == 200 and paid.json()["status"] == "paid" and paid.json()["amount_paid"] == 300)
        check("I-PAY b re-pay is idempotent (still paid, amount_paid still 300 — no double-pay)",
              tx(pay_id, "pay", "payer").json() == paid.json())

        # I-VOID / I-UNCOLLECTIBLE — open -> void / uncollectible; amount_paid stays 0; idempotent
        void_id = finalize_bill("VOID", "voider", 400)
        voided = tx(void_id, "void", "voider")
        check("I-VOID a void an open bill -> 200 void, amount_paid stays 0",
              voided.status_code == 200 and voided.json()["status"] == "void" and voided.json()["amount_paid"] == 0)
        check("I-VOID b re-void is idempotent", tx(void_id, "void", "voider").json() == voided.json())
        unc_id = finalize_bill("UNC", "uncol", 500)
        unc = tx(unc_id, "mark_uncollectible", "uncol")
        check("I-UNCOLLECTIBLE open -> uncollectible, amount_paid stays 0",
              unc.status_code == 200 and unc.json()["status"] == "uncollectible" and unc.json()["amount_paid"] == 0)

        # I-PAY-STATE — only an OPEN (finalized) bill transitions; the state machine forbids the rest (409)
        draft_id = create([line("d", 1, 100)], "DPAY", sub="payer").json()["id"]
        check("I-PAY-STATE a pay a DRAFT (un-finalized) -> 409", tx(draft_id, "pay", "payer").status_code == 409)
        check("I-PAY-STATE b void a PAID bill -> 409 (terminal)", tx(pay_id, "void", "payer").status_code == 409)
        check("I-PAY-STATE c pay a VOID bill -> 409 (terminal)", tx(void_id, "pay", "voider").status_code == 409)
        check("I-PAY-STATE d the paid bill is untouched after the failed void (still paid, amount_paid 300)",
              get(pay_id, sub="payer").json()["status"] == "paid" and get(pay_id, sub="payer").json()["amount_paid"] == 300)

        # I-OWN-TX2 — caller B can never pay/void caller A's bill (404, not 409/200)
        a_open = finalize_bill("AOPEN", "alice", 250)
        check("I-OWN-TX2 a bob cannot pay alice's bill -> 404", tx(a_open, "pay", "bob").status_code == 404)
        check("I-OWN-TX2 b bob cannot void alice's bill -> 404", tx(a_open, "void", "bob").status_code == 404)
        check("I-OWN-TX2 c alice's bill is untouched (still open)", get(a_open).json()["status"] == "open")

        # I-HALF-FINALIZED — a TORN finalize (open + number=null: a crash, or a race in
        # the window between finalize's two steps) must NOT be payable/voidable. The terminal transitions require a
        # FULLY-finalized (NUMBERED) bill, so a half-finalized one 409s until a re-finalize completes its number — else a
        # paid/void bill could strand with NO legal number (EU VAT Art. 226). Crafted via the store seam (no HTTP route
        # produces open+null on its own — finalize always completes the number).
        from app_pkg.core import store as _store
        hf_id = create([line("hf", 1, 600)], "HALF", sub="halfp").json()["id"]
        c.post(f"/invoices/{hf_id}/finalize", headers={"Authorization": "Bearer test:halfp"})   # open + numbered
        hf_slot = f"halfp\x1f{hf_id}"
        hf_rec = _store.get("invoices_records", hf_slot)
        hf_rec["number"] = None                          # simulate the crash/race state between finalize step-1 and step-2
        _store.put("invoices_records", hf_slot, hf_rec)
        check("I-HALF-FINALIZED a a half-finalized (open, number=null) bill REFUSES pay -> 409",
              tx(hf_id, "pay", "halfp").status_code == 409)
        check("I-HALF-FINALIZED b ...and REFUSES void -> 409", tx(hf_id, "void", "halfp").status_code == 409)
        recovered = c.post(f"/invoices/{hf_id}/finalize", headers={"Authorization": "Bearer test:halfp"})
        check("I-HALF-FINALIZED c a re-finalize COMPLETES the number (the recovery path)",
              recovered.status_code == 200 and recovered.json()["number"] is not None
              and recovered.json()["status"] == "open")
        check("I-HALF-FINALIZED d after recovery, pay succeeds -> 200 paid",
              tx(hf_id, "pay", "halfp").status_code == 200)

        # pre-create durable bills for the cross-process races (run after the block, against the same DB)
        racefin_id = create([line("rf", 1, 100)], "RACEFIN", sub="racef").json()["id"]
        racet_id = finalize_bill("RACETERM", "racet", 700)   # a finalized (open) bill for the pay-vs-void race

    # ── cross-PROCESS races (requires a real DATABASE_PATH so two processes share the store) ─────────────────────
    if os.getenv("DATABASE_PATH"):
        def run(worker, argsets):
            # one subprocess per arg-tuple in argsets (so the two racers can carry DIFFERENT args, e.g. pay vs void)
            procs = [subprocess.Popen([sys.executable, "-c", worker, *a], cwd=os.getcwd(),
                                      env={**os.environ, "LOG_LEVEL": "silent"},
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for a in argsets]
            outs = []
            for p in procs:
                so, se = p.communicate(timeout=120)
                outs.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:160]))
            return outs

        # I-RACE-CREATE — two processes racing one key create EXACTLY ONE draft (the same bill id)
        co = run(RACE_WORKER, [(), ()])
        ids = [o for rc, o in co if rc == 0]
        check("I-RACE-CREATE two processes racing one key -> the SAME bill id (no double-create)",
              len(ids) == 2 and ids[0] == ids[1] and not ids[0].startswith("status="), f"got {co}")

        # I-RACE-FINALIZE — two processes finalizing ONE draft -> exactly ONE number attached (no duplicate; the loser's
        # mint is a rare owned gap). Both callers observe the SAME single number — never two numbers for one bill.
        fo = run(FINALIZE_RACE_WORKER, [(racefin_id,), (racefin_id,)])
        fnums = [o for rc, o in fo if rc == 0]
        check("I-RACE-FINALIZE two processes finalizing one draft -> the SAME single number (no duplicate)",
              len(fnums) == 2 and fnums[0] == fnums[1] and fnums[0].startswith("INV-"), f"got {fo}")

        # I-RACE-TERMINAL — two processes racing DIFFERENT terminal transitions (pay vs void) on ONE open bill -> exactly
        # one 200 + one 409 (the state machine serializes: the loser sees a non-open state). ONE terminal state, never both.
        to = run(TERMINAL_RACE_WORKER, [(racet_id, "pay"), (racet_id, "void")])
        tcodes = sorted(int(o) for rc, o in to if rc == 0 and o.isdigit())
        so = run(STATE_WORKER, [(racet_id,)])   # read the FINAL stored state in a fresh process (c is closed here)
        final_state = so[0][1] if so and so[0][0] == 0 else "?"
        check("I-RACE-TERMINAL pay-vs-void on one open bill -> exactly one 200 + one 409, one terminal state",
              tcodes == [200, 409] and final_state in ("paid", "void"), f"got {to}, state={final_state}")
    else:
        print("  [FAIL] cross-process races NOT RUN — DATABASE_PATH unset (the harness must provide it)")
        failures.append("races not run")

    print(f"INVOICES INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
