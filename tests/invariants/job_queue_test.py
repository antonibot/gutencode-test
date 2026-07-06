"""JOBS INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the python app
(cwd = <app>/python; DATABASE_PATH + APP_TEST_CLOCK + APP_TEST_SESSIONS set by the harness). Credited by EXIT CODE.

Proves:  I1 AT-MOST-ONCE CLAIM — two processes race claim to exhaustion; every job is claimed EXACTLY once, never
            twice (the do()-CAS wall — a get-then-put claimer fails this under load).
         I2 COMPLETION-AUTH (fencing) — a worker whose lease EXPIRED and whose job was RECLAIMED cannot complete it
            with its stale token (409); only the current lease holder can. Acquire-exclusivity != release-safety.
         I3 RETRY BOUNDED — a job is delivered at most max_attempts times whether it CRASHES (lease lapses, reclaim)
            or FAILS explicitly; the (max+1)th delivery never happens — the job is dead-lettered.
         I4 BACKOFF DETERMINISTIC — on each fail run_at advances by EXACTLY min(base*2^attempts, cap), no jitter.
         I5 LEASE RECOVERY — a claimed-but-never-finished job whose lease lapses is reclaimed (a crashed worker
            never strands a job forever).
         I6 PAYLOAD CONTAINED — a lone surrogate in the opaque payload is stored as U+FFFD (no 5xx); a >2^53 int
            in the payload is rejected 422.
         I7 HAPPY PATH — enqueue -> claim (a fresh lease token) -> complete -> done, end to end.
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

USER = {"Authorization": "Bearer test:alice"}
SVC = {"Authorization": "Bearer service_dev_token_change_me"}
failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


RACE_WORKER = """
import os, sys, json
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
got = []
with TestClient(app, raise_server_exceptions=False) as c:
    while True:
        r = c.post("/job_queue/claim?now=7001", headers={"Authorization": "Bearer service_dev_token_change_me"})
        if r.status_code != 200:
            break
        got.append(r.json()["id"])
print(json.dumps(got))
"""


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        def enqueue(now, **body):
            return c.post(f"/job_queue?now={now}", json=body, headers=USER)

        # I7 — HAPPY PATH: enqueue -> claim (fresh token) -> complete -> done
        j = enqueue(1000, kind="hp").json()["id"]
        cl = c.post("/job_queue/claim?now=1000", headers=SVC)
        check("I7a claim returns the enqueued job, running, attempts=1",
              cl.status_code == 200 and cl.json()["id"] == j and cl.json()["status"] == "running" and cl.json()["attempts"] == 1,
              f"got {cl.status_code} {cl.json() if cl.status_code == 200 else ''}")
        token = cl.json().get("lease_token", "")
        check("I7b claim hands the worker a non-empty lease token", bool(token))
        done = c.post(f"/job_queue/{j}/complete?now=1000", json={"lease_token": token}, headers=SVC)
        check("I7c complete with the lease token -> done", done.status_code == 200 and done.json()["status"] == "done")
        check("I7d the owner sees the job done (and the lease token is NOT exposed to the owner)",
              c.get(f"/job_queue/{j}", headers=USER).json().get("status") == "done"
              and "lease_token" not in c.get(f"/job_queue/{j}", headers=USER).json())

        # I2 — COMPLETION-AUTH (fencing): A claims, lease expires, B reclaims; A's stale token is refused
        j = enqueue(2000, kind="fence", max_attempts=5).json()["id"]
        a = c.post("/job_queue/claim?now=2000", headers=SVC)
        token_a = a.json()["lease_token"]
        check("I2a worker A claims the job", a.json()["id"] == j and a.json()["status"] == "running")
        b = c.post("/job_queue/claim?now=2301", headers=SVC)            # lease (2000+300=2300) has lapsed -> reclaim
        token_b = b.json()["lease_token"]
        check("I2b worker B reclaims the same job after the lease lapses, attempts incremented, NEW token",
              b.json()["id"] == j and b.json()["attempts"] == 2 and token_b != token_a)
        stale = c.post(f"/job_queue/{j}/complete?now=2301", json={"lease_token": token_a}, headers=SVC)
        check("I2c worker A's STALE token cannot complete the reclaimed job (409)", stale.status_code == 409)
        check("I2d the job is still B's, still running (A did not corrupt it)",
              c.get(f"/job_queue/{j}", headers=USER).json()["status"] == "running")
        stale_fail = c.post(f"/job_queue/{j}/fail?now=2301", json={"lease_token": token_a}, headers=SVC)
        check("I2e worker A's STALE token cannot FAIL the reclaimed job either (409 — no reset to a 3rd claimant)",
              stale_fail.status_code == 409)
        ok = c.post(f"/job_queue/{j}/complete?now=2301", json={"lease_token": token_b}, headers=SVC)
        check("I2f only the current lease holder (B) can complete", ok.status_code == 200 and ok.json()["status"] == "done")

        # I5 — LEASE RECOVERY: a claimed-but-unfinished job whose lease lapses is reclaimed
        j = enqueue(3000, kind="recover", max_attempts=5).json()["id"]
        r1 = c.post("/job_queue/claim?now=3000", headers=SVC)
        r2 = c.post("/job_queue/claim?now=3301", headers=SVC)            # no complete -> lease lapses -> reclaim
        check("I5 a crashed worker's job is reclaimed (same id, attempts grows)",
              r1.json()["id"] == j and r2.json()["id"] == j and r2.json()["attempts"] == 2)
        c.post(f"/job_queue/{j}/complete?now=3301", json={"lease_token": r2.json()["lease_token"]}, headers=SVC)  # cleanup

        # I3 — RETRY BOUNDED via CRASH (reclaim): max_attempts=2 -> 2 deliveries then dead, never a 3rd
        j = enqueue(4000, kind="crash", max_attempts=2).json()["id"]
        d1 = c.post("/job_queue/claim?now=4000", headers=SVC)            # delivery 1
        d2 = c.post("/job_queue/claim?now=4301", headers=SVC)            # delivery 2 (reclaim)
        d3 = c.post("/job_queue/claim?now=4602", headers=SVC)            # would be delivery 3 -> dead-lettered instead
        check("I3a two crash-deliveries happen (attempts 1 then 2)",
              d1.json().get("id") == j and d1.json().get("attempts") == 1 and d2.json().get("id") == j and d2.json().get("attempts") == 2)
        check("I3b the 3rd reclaim does NOT re-deliver (no claim returned)", d3.status_code == 204)
        check("I3c the job is dead-lettered at the bound (not stuck running, not re-queued)",
              c.get(f"/job_queue/{j}", headers=USER).json()["status"] == "dead")

        # I3' — RETRY BOUNDED via explicit FAIL: max_attempts=2 -> fail, retry, fail -> dead
        j = enqueue(5000, kind="failbound", max_attempts=2).json()["id"]
        f1 = c.post("/job_queue/claim?now=5000", headers=SVC)
        c.post(f"/job_queue/{j}/fail?now=5000", json={"lease_token": f1.json()["lease_token"]}, headers=SVC)
        # after fail, run_at = 5000 + min(2*2^1, 3600) = 5004; claim at 5004
        f2 = c.post("/job_queue/claim?now=5004", headers=SVC)
        last = c.post(f"/job_queue/{j}/fail?now=5004", json={"lease_token": f2.json()["lease_token"]}, headers=SVC)
        check("I3'a the 2nd fail at the bound dead-letters", last.status_code == 200 and last.json()["status"] == "dead")
        check("I3'b a dead job is never re-delivered", c.post("/job_queue/claim?now=5004", headers=SVC).status_code == 204)

        # I4 — BACKOFF DETERMINISTIC: run_at advances by EXACTLY min(base*2^attempts, cap) on each fail (base=2 default)
        j = enqueue(6000, kind="backoff", max_attempts=5).json()["id"]
        b1 = c.post("/job_queue/claim?now=6000", headers=SVC)            # attempts=1
        r = c.post(f"/job_queue/{j}/fail?now=6000", json={"lease_token": b1.json()["lease_token"]}, headers=SVC)
        check("I4a fail at attempts=1 -> run_at = now + 2*2^1 = now+4", r.json()["run_at"] == 6004 and r.json()["status"] == "queued")
        b2 = c.post("/job_queue/claim?now=6004", headers=SVC)            # attempts=2
        r = c.post(f"/job_queue/{j}/fail?now=6004", json={"lease_token": b2.json()["lease_token"]}, headers=SVC)
        check("I4b fail at attempts=2 -> run_at advances by 2*2^2 = 8 (deterministic, no jitter)", r.json()["run_at"] == 6012)
        b3 = c.post("/job_queue/claim?now=6012", headers=SVC)            # cleanup
        c.post(f"/job_queue/{j}/complete?now=6012", json={"lease_token": b3.json()["lease_token"]}, headers=SVC)

        # I6 — PAYLOAD CONTAINED: a lone surrogate -> U+FFFD (no 5xx); a >2^53 int -> 422. The surrogate is sent as a
        # RAW JSON body (the \ud800 escape) because an HTTP client cannot UTF-8-encode a lone surrogate via json=; the
        # app's parser decodes the escape to the real lone surrogate, exactly the hostile input this contains.
        surro_body = '{"kind": "psurro", "payload": {"s": "\\ud800", "n": 5}}'
        j = c.post("/job_queue?now=6500", content=surro_body, headers={**USER, "content-type": "application/json"}).json()["id"]
        got = c.get(f"/job_queue/{j}", headers=USER).json()["payload"]
        check("I6a a lone surrogate in the payload is contained as U+FFFD (no 5xx, no divergence)",
              got == {"s": "�", "n": 5}, f"got {got!r}")
        big = enqueue(6500, kind="payload", payload={"big": 99999999999999999999})
        check("I6b a >2^53 int in the payload is rejected (422)", big.status_code == 422)
        cl = c.post("/job_queue/claim?now=6500", headers=SVC)            # cleanup the surrogate job
        c.post(f"/job_queue/{cl.json()['id']}/complete?now=6500", json={"lease_token": cl.json()["lease_token"]}, headers=SVC)

        # I-OWNER — cross-owner isolation (>=2 identities + a negative assertion): bob cannot see alice's job
        BOB = {"Authorization": "Bearer test:bob"}
        ja = enqueue(6600, kind="iso").json()["id"]
        check("I-OWNERa a cross-owner get is 404 (existence never leaks)",
              c.get(f"/job_queue/{ja}", headers=BOB).status_code == 404)
        check("I-OWNERb bob's list is empty — he never sees alice's jobs",
              c.get("/job_queue", headers=BOB).json()["results"] == [])
        clo = c.post("/job_queue/claim?now=6600", headers=SVC)   # cleanup so the queue is empty before the race
        c.post(f"/job_queue/{clo.json()['id']}/complete?now=6600", json={"lease_token": clo.json()["lease_token"]}, headers=SVC)

        # set up I1: enqueue N fresh jobs (the only claimable ones left — every job above is terminal)
        n = 20
        race_ids = sorted(enqueue(7000, kind="race").json()["id"] for _ in range(n))

    # I1 — AT-MOST-ONCE CLAIM: two processes race claim to exhaustion; each job claimed EXACTLY once.
    if os.getenv("DATABASE_PATH"):
        env = {**os.environ, "LOG_LEVEL": "silent"}
        procs = [subprocess.Popen([sys.executable, "-c", RACE_WORKER], cwd=os.getcwd(), env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        claimed = []
        outs = []
        for p in procs:
            so, se = p.communicate(timeout=120)
            outs.append((p.returncode, so, se))
            if p.returncode == 0 and so.strip():
                claimed += json.loads(so.strip().splitlines()[-1])
        check("I1a every race job was claimed (none lost)", sorted(claimed) == race_ids
              or set(race_ids).issubset(set(claimed)), f"race_ids={race_ids} claimed={sorted(claimed)} outs={outs}")
        check("I1b NO job was claimed twice (the do()-CAS holds under a 2-process race)",
              len(claimed) == len(set(claimed)), f"duplicates in {sorted(claimed)}")
        check("I1c the count is exact — total distinct claims across both workers == N", len(set(claimed)) == n,
              f"expected {n}, got {len(set(claimed))}")
    else:
        print("  [FAIL] I1 race NOT RUN — DATABASE_PATH unset (the harness must provide it)")
        failures.append("I1 not run")

    print(f"JOBS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
