"""LLM_USAGE INVARIANTS — cost-integrity proofs for this domain's dangerous property. Run against the python app
(cwd = <app>/python; DATABASE_PATH set by the harness). Credited by EXIT CODE ONLY.

Proves:  I1 NO-DOUBLE-COUNT — recording (owner, identifier, body) twice yields ONE stored event; the replay returns
            the SAME record; the aggregate counts it once — INCLUDING across a clock-second boundary (the server-
            defaulted `at` never enters the dedup fingerprint).
         I2 BODY-DRIFT — same (owner, identifier) with a different cost-input is a 409 (no silent re-bill).
         I3 COST-SERVER-DERIVED — a client-supplied cost field is IGNORED (stored cost == the price-table computation);
            unknown (provider, model) and an unpriced dimension are 422 (deny-by-default); the cost is INTEGER-EXACT.
         I4 APPEND-ONLY — no update/delete route exists; an owner's running total only grows.
         I5 DERIVED-AGGREGATE — GET /summary cost == the sum of the owner's event costs (never a stored total).
         I6 OWNER-ISOLATION — owner B's identifier collides with A's as a DISTINCT event; B's summary excludes A's.
         I7 OVERFLOW-SAFE + CEILING — a per-dimension token count above the ceiling is 422.
         I8 CONCURRENCY — two processes racing the same (owner, identifier) produce exactly ONE event (no double-count)."""
import os
import subprocess
import sys

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402
from app_pkg.core import store  # noqa: E402

os.environ["APP_TEST_SESSIONS"] = "1"
ROOT = {"Authorization": "Bearer test:root"}
ALICE = {"Authorization": "Bearer test:alice"}
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
with TestClient(app, raise_server_exceptions=False, headers={"Authorization": "Bearer test:root"}) as c:
    r = c.post("/llm_usage/events", json={"identifier": "raced", "provider": "openai", "model": "gpt-4o", "input_tokens": 1000})
    print(r.json().get("id") if r.status_code == 201 else f"status={r.status_code}")
"""


def main():
    with TestClient(app, raise_server_exceptions=False, headers=ROOT) as c:
        def post(body, headers=None):
            return c.post("/llm_usage/events", json=body, headers=headers)

        base = {"identifier": "i1", "provider": "openai", "model": "gpt-4o", "input_tokens": 1000, "output_tokens": 500}

        # I1 — no double-count
        r1 = post(base)
        check("I1a record -> 201 with server-derived cost", r1.status_code == 201 and r1.json()["cost_nanodollars"] == 7500000, f"{r1.status_code} {r1.json()}")
        r2 = post(base)
        check("I1b replay is idempotent (same id + cost)", r2.status_code == 201 and r2.json()["id"] == r1.json()["id"] and r2.json()["cost_nanodollars"] == 7500000, f"got {r2.json()}")
        one = [e for e in store.values("llm_usage_events") if e["identifier"] == "i1" and e["owner"] == "root"]
        check("I1c white-box: exactly ONE stored event for the identifier", len(one) == 1, f"got {len(one)}")
        check("I1d white-box: the event never stores a client cost, only the derived one", one and one[0]["cost_nanodollars"] == 7500000)

        # I1e — boundary determinism: two byte-identical no-`at` posts whose server clocks straddle a second boundary
        # (?now=1000 then ?now=1001 via the test-clock seam) are ONE event — the server-defaulted `at` must NOT enter
        # the dedup fingerprint, or the replay 409s at wall-clock second ticks.
        os.environ["APP_TEST_CLOCK"] = "1"     # honored per-call by the clock seam; inert in prod
        tb = {"identifier": "i1e", "provider": "openai", "model": "gpt-4o", "input_tokens": 1000}
        t1 = c.post("/llm_usage/events?now=1000", json=tb)
        t2 = c.post("/llm_usage/events?now=1001", json=tb)
        os.environ.pop("APP_TEST_CLOCK", None)
        check("I1e identical no-`at` retry across a clock second replays (same id, original at)",
              t1.status_code == 201 and t2.status_code == 201 and t2.json()["id"] == t1.json()["id"] and t2.json()["at"] == 1000,
              f"got {t1.status_code}/{t2.status_code} {t2.text[:200]}")

        # I2 — body-drift -> 409
        check("I2 same identifier, different tokens -> 409", post({**base, "input_tokens": 2000}).status_code == 409)

        # I3 — cost-server-derived + deny-by-default + integer-exact
        r3 = post({"identifier": "i3a", "provider": "openai", "model": "gpt-4o", "input_tokens": 1000, "cost_nanodollars": 999999999})
        check("I3a a client `cost_nanodollars` is IGNORED; stored cost is the derived 2500000", r3.status_code == 201 and r3.json()["cost_nanodollars"] == 2500000, f"got {r3.json()}")
        check("I3b unknown model -> 422 (deny-by-default)", post({"identifier": "i3b1", "provider": "openai", "model": "ghost-9", "input_tokens": 1}).status_code == 422)
        check("I3b unpriced dimension (gpt-4o has no reasoning rate) -> 422", post({"identifier": "i3b2", "provider": "openai", "model": "gpt-4o", "reasoning_tokens": 1}).status_code == 422)
        # integer-EXACT: a non-round token count; gpt-4o input rate is 2_500_000 nd/1000tok -> 1234 tokens = 1234*2_500_000//1000
        r3c = post({"identifier": "i3c", "provider": "openai", "model": "gpt-4o", "input_tokens": 1234})
        check("I3c cost is integer-exact (1234 tok -> 3085000)", r3c.status_code == 201 and r3c.json()["cost_nanodollars"] == 1234 * 2_500_000 // 1000, f"got {r3c.json()}")
        # multi-dimension: cache_read priced at its own rate (Anthropic sonnet: in 3M, cache_read 0.3M, cache_write 3.75M /1000tok)
        r3d = post({"identifier": "i3d", "provider": "anthropic", "model": "claude-3-5-sonnet", "input_tokens": 100, "cache_read_input_tokens": 200, "cache_creation_input_tokens": 50})
        expd = 100 * 3_000_000 // 1000 + 200 * 300_000 // 1000 + 50 * 3_750_000 // 1000
        check("I3d multi-dimension cost sums each dimension's rate", r3d.status_code == 201 and r3d.json()["cost_nanodollars"] == expd, f"got {r3d.json()} want {expd}")

        # I4 — append-only: the route table has no PUT/PATCH/DELETE on an event (white-box: only POST/GET paths)
        methods = {(r.methods and tuple(sorted(r.methods)), r.path) for r in app.routes if hasattr(r, "path") and r.path.startswith("/llm_usage")}
        has_mutator = any(("PUT" in (m or ()) or "PATCH" in (m or ()) or "DELETE" in (m or ())) for m, _ in methods)
        check("I4 no update/delete route on an event (immutable by construction)", not has_mutator, f"routes {methods}")

        # I5 — derived aggregate: summary cost == sum of the owner's stored event costs
        s = c.get("/llm_usage/summary").json()
        derived = sum(e["cost_nanodollars"] for e in store.values("llm_usage_events") if e["owner"] == "root")
        check("I5 summary cost == sum of the owner's events (derived, not stored)", s["cost_nanodollars"] == derived, f"summary {s['cost_nanodollars']} vs {derived}")

        # I6 — owner-isolation: alice's same identifier "i1" is a DISTINCT event; alice's summary excludes root's
        ra = post(base, headers=ALICE)
        check("I6a owner B's same identifier is a DISTINCT event (not a replay of A's)", ra.status_code == 201)
        two = [e for e in store.values("llm_usage_events") if e["identifier"] == "i1"]
        check("I6b white-box: two owners, same identifier -> two records", len({e["owner"] for e in two}) == 2 and len(two) == 2, f"got {two}")
        sa = c.get("/llm_usage/summary", headers=ALICE).json()
        a_derived = sum(e["cost_nanodollars"] for e in store.values("llm_usage_events") if e["owner"] == "alice")
        check("I6c alice's summary counts ONLY alice's events", sa["cost_nanodollars"] == a_derived and sa["cost_nanodollars"] < s["cost_nanodollars"], f"alice {sa['cost_nanodollars']} root {s['cost_nanodollars']}")
        # I6d cross-owner NEGATIVE: a root event id is NOT IN alice's event list (the owner filter ISOLATES — a wrong-
        # variable filter + a shallow single-owner invariant must not both pass)
        alice_ids = [e["id"] for e in c.get("/llm_usage/events", headers=ALICE).json()["results"]]
        check("I6d a root event id is NOT IN alice's own event list", r1.json()["id"] not in alice_ids, f"root id {r1.json()['id']} in {alice_ids}")

        # I7 — per-dimension ceiling (the env default is 10_000_000)
        check("I7 a token count above the per-dimension ceiling -> 422", post({"identifier": "i7", "provider": "openai", "model": "gpt-4o", "input_tokens": 10_000_001}).status_code == 422)

    # I8 — concurrency: two processes race the SAME (owner, identifier); exactly one event, both served the winner
    if os.getenv("DATABASE_PATH"):
        procs = [subprocess.Popen([sys.executable, "-c", RACE_WORKER], cwd=os.getcwd(),
                                  env={**os.environ, "LOG_LEVEL": "silent"},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        outs = []
        for p in procs:
            so, se = p.communicate(timeout=120)
            outs.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:120]))
        ids = [o for rc, o in outs if rc == 0 and str(o).isdigit()]
        check("I8a both racers succeed and get the SAME event id (one winner)", len(ids) == 2 and ids[0] == ids[1], f"got {outs}")
        with TestClient(app, raise_server_exceptions=False, headers=ROOT) as c:
            raced = [e for e in store.values("llm_usage_events") if e["identifier"] == "raced" and e["owner"] == "root"]
            check("I8b white-box: exactly ONE event for the raced identifier (no double-count)", len(raced) == 1, f"got {len(raced)}")
    else:
        print("  [FAIL] I8 concurrency NOT RUN — DATABASE_PATH unset")
        failures.append("I8 not run")

    print(f"LLM_USAGE INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
