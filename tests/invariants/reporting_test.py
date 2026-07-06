"""REPORTING INVARIANTS — the dangerous-property proofs for this domain, driven against the REAL python app
(cwd = <app>/python; DATABASE_PATH set by the harness). Credited by EXIT CODE only. Each check uses a REACHING input:
delete the defense in your head and the check goes RED (rule 9).

Proves:  I-AGG      AGGREGATION CORRECTNESS — COUNT/SUM/MIN/MAX equal an INDEPENDENTLY test-computed expectation
                    (never read back from the handler).
         I-OWNER    OWNER-SCOPED AGGREGATION — with alice AND bob facts in the SAME dataset+group, alice's SUM ==
                    the sum of ALICE's measures ONLY (bob's would inflate it if the owner conjunct were dropped), and
                    a bob key is NOT IN alice's fact list.
         I-OVER     DERIVED-OVERFLOW — a group whose measures SUM past 2^53 (the ODD 2^53-1 + 2 vector) is 422, not a
                    wrapped/precision-lost number.
         I-INT      MEASURE STRICT-INT — 5.0 / 5.5 are 422 (a float measure would re-introduce the x3 float SUM).
         I-ORDER    DETERMINISTIC GROUP ORDER — facts ingested in a SHUFFLED order (incl. a missing-dim null key and an
                    astral value) come back in the digest-hash order recomputed here (store scan order would differ).
         I-ONCE     EXACTLY-ONCE INGEST — the same (owner,dataset,key) twice is ONE immutable fact; a COUNT is not inflated.
         I-INJ      INJECTIVE PREIMAGE — (dataset="a:b",key="c") and (dataset="a",key="b:c") are DISTINCT facts
                    (they collide under a bare digest_hex join; the _h pre-hash separates them).
         I-CONTAIN  CONTAIN-BEFORE-HASH — a lone surrogate in a dimension KEY/value and a query group_by name/`as`
                    does NOT 5xx, and a surrogate-keyed fact survives a subsequent GET (no stored poison).
         I-DRAIN    TEARDOWN — a filtered drain removes ALL matching owner facts; a bare (no-dataset) drain is 422;
                    another owner's facts are untouched."""
import os
import sys

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402
from app_pkg.core import store  # noqa: E402
from app_pkg.parts.digest import digest_hex  # noqa: E402

os.environ["APP_TEST_SESSIONS"] = "1"
ALICE = {"Authorization": "Bearer test:alice"}
BOB = {"Authorization": "Bearer test:bob"}
failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def _kh(values):
    # the group key exactly as the handler computes it: digest_hex of the pre-hashed values ("" marks a missing dim)
    return digest_hex(*[digest_hex(v) if v is not None else "" for v in values])


def main():
    with TestClient(app, raise_server_exceptions=False, headers=ALICE) as c:
        def fact(ds, key, dims, meas, headers=ALICE):
            return c.post("/reporting/facts", json={"dataset": ds, "key": key, "dimensions": dims, "measures": meas}, headers=headers)

        def query(body, headers=ALICE):
            return c.post("/reporting/query", json=body, headers=headers)

        # ---- I-AGG: aggregation correctness vs an independent recompute -------------------------------------------
        rows = [("won", "eu", 100), ("won", "us", 250), ("lost", "eu", 50), ("won", "eu", 25)]
        for i, (stage, region, value) in enumerate(rows):
            fact("agg", f"a{i}", {"stage": stage, "region": region}, {"value": value, "count": 1})
        want = {}
        for stage, region, value in rows:
            g = want.setdefault(stage, {"count": 0, "sum": 0, "vals": []})
            g["count"] += 1
            g["sum"] += value
            g["vals"].append(value)
        qr = query({"dataset": "agg", "group_by": ["stage"],
                    "aggregate": [{"op": "count"}, {"op": "sum", "field": "value", "as": "total"},
                                  {"op": "min", "field": "value", "as": "lo"}, {"op": "max", "field": "value", "as": "hi"}]})
        got = {g["key"]["stage"]: g["values"] for g in qr.json()["groups"]}
        ok_agg = qr.status_code == 200 and all(
            got.get(s, {}).get("count") == g["count"] and got.get(s, {}).get("total") == g["sum"]
            and got.get(s, {}).get("lo") == min(g["vals"]) and got.get(s, {}).get("hi") == max(g["vals"])
            for s, g in want.items())
        check("I-AGG count/sum/min/max equal the independent recompute", ok_agg, f"got {got} want {want}")

        # ---- I-OWNER: cross-owner isolation (REACHING — bob's facts would inflate alice's sum) --------------------
        fact("iso", "shared", {"stage": "won"}, {"value": 10}, headers=ALICE)
        fact("iso", "shared", {"stage": "won"}, {"value": 9999}, headers=BOB)   # SAME (dataset,key,dims) as alice
        a_sum = query({"dataset": "iso", "group_by": ["stage"], "aggregate": [{"op": "sum", "field": "value", "as": "t"}]}).json()
        check("I-OWNER alice's sum counts ONLY alice's facts (bob's 9999 excluded)",
              a_sum["groups"] == [{"key": {"stage": "won"}, "values": {"t": 10}}], f"got {a_sum['groups']}")
        alice_keys = [r["key"] for r in c.get("/reporting/facts?dataset=iso", headers=ALICE).json()["results"]]
        b_only = c.get("/reporting/facts?dataset=iso", headers=BOB).json()["results"]
        check("I-OWNER bob's fact is a DISTINCT row not in alice's list", len(b_only) == 1 and b_only[0]["measures"]["value"] == 9999)
        # white-box: two owners, same (dataset,key) -> two distinct slots (no clobber)
        iso = [e for e in store.values("reporting_facts") if e["dataset"] == "iso" and e["key"] == "shared"]
        check("I-OWNER white-box: two owners, same (dataset,key) -> two rows (owner-partitioned slot)",
              len(iso) == 2 and len({e["owner"] for e in iso}) == 2, f"got {iso}")

        # ---- I-OVER: derived SUM overflow, the ODD 2^53-1 + 2 vector -> 422 (REACHING: no guard -> py 201) --------
        fact("ov", "o1", {}, {"v": 9007199254740991})   # 2^53-1
        fact("ov", "o2", {}, {"v": 2})                   # sum -> 2^53+1 (ODD; node would round to 2^53, py/go exact)
        over = query({"dataset": "ov", "group_by": [], "aggregate": [{"op": "sum", "field": "v", "as": "s"}]})
        check("I-OVER a SUM past 2^53 fails loud (422), never a wrapped/lossy number", over.status_code == 422, f"got {over.status_code} {over.json()}")
        # the individual facts each stored fine (each <= 2^53-1) — the overflow is DERIVED, not an input bound
        check("I-OVER the inputs themselves were accepted (the overflow is in the derived sum)",
              query({"dataset": "ov", "group_by": [], "aggregate": [{"op": "max", "field": "v", "as": "m"}]}).json()["groups"][0]["values"]["m"] == 9007199254740991)

        # ---- I-INT: measure strict-int (REACHING — safe_number would accept 5.5) ----------------------------------
        check("I-INT a fractional measure 5.5 -> 422", fact("t", "int1", {}, {"n": 5.5}).status_code == 422)
        check("I-INT a float 5.0 -> 422 (no coercion)", fact("t", "int2", {}, {"n": 5.0}).status_code == 422)
        check("I-INT a real integer -> 201", fact("t", "int3", {}, {"n": 5}).status_code == 201)

        # ---- I-ORDER: deterministic hash-order over a SHUFFLED ingest (incl. null key + astral value) -------------
        astral = "z\U0001F600"                             # an astral (non-BMP) dimension value — digest is x3-identical
        ingest_order = [("mango", "om"), ("apple", "oa"), (astral, "oz"), (None, "onull")]
        for gv, k in ingest_order:                         # ingested mango, apple, astral, missing — NOT hash order
            dims = {} if gv is None else {"g": gv}
            fact("ord", k, dims, {"v": 1})
        expect_order = sorted([gv for gv, _ in ingest_order], key=lambda gv: _kh([gv]))
        qo = query({"dataset": "ord", "group_by": ["g"], "aggregate": [{"op": "count"}]})
        got_order = [g["key"].get("g") for g in qo.json()["groups"]]
        check("I-ORDER groups come back in the recomputed digest-hash order (not store scan order)",
              qo.status_code == 200 and got_order == expect_order, f"got {got_order} want {expect_order}")

        # ---- I-ONCE: exactly-once immutable ingest ---------------------------------------------------------------
        r1 = fact("once", "k", {"stage": "a"}, {"v": 100})
        r2 = fact("once", "k", {"stage": "CHANGED"}, {"v": 999})   # same (dataset,key), different data
        check("I-ONCE a repeat (dataset,key) returns the SAME immutable fact", r1.json()["id"] == r2.json()["id"] and r2.json()["measures"]["v"] == 100, f"{r1.json()} vs {r2.json()}")
        onerows = [e for e in store.values("reporting_facts") if e["dataset"] == "once" and e["key"] == "k"]
        check("I-ONCE white-box: exactly ONE stored fact (no double-count)", len(onerows) == 1, f"got {len(onerows)}")

        # ---- I-INJ: injective preimage (REACHING — without _h, ('a:b','c') and ('a','b:c') collide) --------------
        j1 = fact("a:b", "c", {}, {"v": 1})
        j2 = fact("a", "b:c", {}, {"v": 1})
        check("I-INJ (dataset='a:b',key='c') and (dataset='a',key='b:c') are DISTINCT facts",
              j1.json()["id"] != j2.json()["id"] and j2.json()["dataset"] == "a", f"{j1.json()} vs {j2.json()}")

        # ---- I-CONTAIN: contain-before-hash incl. KEYS + query names (REACHING — a surrogate KEY would 5xx on re-read) ----
        # Send the surrogate bodies as RAW json bytes carrying a literal \uXXXX escape — httpx's json= would reject a
        # lone surrogate CLIENT-side (json.dumps(...).encode('utf-8') raises); the escape lets the SERVER decode it.
        def raw(url, body):
            return c.post(url, content=body.encode("ascii"), headers={**ALICE, "content-type": "application/json"})
        rc = raw("/reporting/facts", '{"dataset":"con","key":"c1","dimensions":{"d\\ud800k":"v\\ud801","ok":"fine"},"measures":{"m\\ud802":3}}')
        check("I-CONTAIN a lone surrogate in a dimension/measure KEY is contained at ingest (no 5xx)", rc.status_code == 201, f"got {rc.status_code} {rc.text[:120]}")
        gc = c.get("/reporting/facts?dataset=con", headers=ALICE)
        check("I-CONTAIN a surrogate-keyed fact survives a subsequent GET (no stored 5xx poison)", gc.status_code == 200, f"got {gc.status_code}")
        stored_dim_keys = "".join("".join(e["dimensions"].keys()) for e in store.values("reporting_facts") if e["dataset"] == "con")
        check("I-CONTAIN the stored dimension keys carry no lone surrogate (contained to U+FFFD)",
              stored_dim_keys != "" and all(not (0xD800 <= ord(ch) <= 0xDFFF) for ch in stored_dim_keys))
        qn = raw("/reporting/query", '{"dataset":"con","group_by":["g\\ud803name"],"aggregate":[{"op":"count","as":"c\\ud804"}]}')
        check("I-CONTAIN a surrogate in a query group_by name / `as` does NOT 5xx", qn.status_code == 200, f"got {qn.status_code}")

        # ---- I-DRAIN: teardown -----------------------------------------------------------------------------------
        for k, region in [("d1", "eu"), ("d2", "us"), ("d3", "eu")]:
            fact("drn", k, {"region": region}, {"v": 1})
        fact("drn", "bob1", {"region": "eu"}, {"v": 1}, headers=BOB)
        d = c.request("DELETE", "/reporting/facts?dataset=drn&region=eu", headers=ALICE)
        check("I-DRAIN a filtered drain removes ALL matching owner facts", d.status_code == 200 and d.json()["deleted"] == 2, f"got {d.status_code} {d.json()}")
        left = [r["key"] for r in c.get("/reporting/facts?dataset=drn", headers=ALICE).json()["results"]]
        check("I-DRAIN only the non-matching owner fact remains", left == ["d2"], f"got {left}")
        bob_left = c.get("/reporting/facts?dataset=drn", headers=BOB).json()["results"]
        check("I-DRAIN another owner's facts are untouched by the drain", len(bob_left) == 1, f"got {bob_left}")
        bare = c.request("DELETE", "/reporting/facts", headers=ALICE)
        check("I-DRAIN a bare (no-dataset) drain is 422 (>=1 anchor, never delete-all)", bare.status_code == 422, f"got {bare.status_code}")

    print(f"REPORTING INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
