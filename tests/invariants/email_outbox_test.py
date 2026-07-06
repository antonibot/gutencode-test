"""EMAIL INVARIANTS — proofs for this domain's two dangerous properties. Run against the python app
(cwd = <app>/python; DATABASE_PATH set by the harness for the concurrency proof). Credited by EXIT CODE ONLY.

Proves:  I1 EXACTLY-ONCE — a keyed send recorded twice yields ONE stored message; the replay returns the SAME id.
         I2 BODY-DRIFT — same (owner, Idempotency-Key) with ANY different message (an added bcc, a changed subject)
            is a 409 (no silent re-send, no dropped recipient).
         I3 OWNER-ISOLATION — owner B cannot list/read owner A's message: 404, byte-indistinguishable from missing,
            and A's id is NOT IN B's own list (>=2 identities + a cross-owner negative).
         I4 HEADER SAFETY — CR/LF/NEL/line-separator/tab in the subject is 422; a template `data` value that injects
            a line break into the RENDERED subject is 422 (validate-AFTER-render).
         I5 APPEND-ONLY — no update/delete route exists on a message (immutable by construction).
         I6 RENDER CONTAINMENT — a lone surrogate in the subject/body is contained to U+FFFD (the stored bytes are
            UTF-8-clean, no uncontained 5xx); a missing template variable is 422.
         I7 BOUNDS — recipients are count-capped, the rendered body is octet-capped, the subject is length-capped.
         I8 CONCURRENCY — two processes racing the SAME (owner, Idempotency-Key) produce exactly ONE message."""
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
    r = c.post("/email_outbox/messages", json={"from": "s@x.com", "to": ["r@x.com"], "subject": "Raced", "text": "b"},
               headers={"Idempotency-Key": "raced"})
    print(r.json().get("id") if r.status_code == 201 else f"status={r.status_code}")
"""


def main():
    with TestClient(app, raise_server_exceptions=False, headers=ROOT) as c:
        def send(body, headers=None, key=None):
            h = dict(headers or ROOT)
            if key is not None:
                h["Idempotency-Key"] = key
            return c.post("/email_outbox/messages", json=body, headers=h)

        base = {"from": "s@x.com", "to": ["a@x.com"], "subject": "Hello", "text": "body"}

        # I1 — exactly-once on a key
        r1 = send(base, key="i1")
        check("I1a keyed send -> 201", r1.status_code == 201, f"{r1.status_code} {r1.text[:120]}")
        r2 = send(base, key="i1")
        check("I1b replay is idempotent (same id)", r2.status_code == 201 and r2.json()["id"] == r1.json()["id"], f"got {r2.json()}")
        one = [m for m in store.values("email_outbox_messages") if m["owner"] == "root" and m["subject"] == "Hello"]
        check("I1c white-box: exactly ONE stored message for the key", len(one) == 1, f"got {len(one)}")

        # I2 — body-drift -> 409 (a changed subject AND an added bcc both drift the fingerprint)
        check("I2a same key, changed subject -> 409", send({**base, "subject": "Changed"}, key="i1").status_code == 409)
        check("I2b same key, added bcc -> 409 (no silent dropped recipient)",
              send({**base, "bcc": ["b@x.com"]}, key="i1").status_code == 409)

        # I3 — owner-isolation: alice cannot see/read root's message; root's id is NOT IN alice's list
        root_id = r1.json()["id"]
        send({"from": "alice@x.com", "to": ["c@x.com"], "subject": "Alice", "text": "b"}, headers=ALICE, key="a1")
        miss = c.get(f"/email_outbox/messages/{root_id}", headers=ALICE)
        gone = c.get("/email_outbox/messages/999999", headers=ALICE)
        check("I3a alice reading root's message -> 404", miss.status_code == 404)
        check("I3b cross-owner 404 == missing 404 (no existence leak)", miss.json() == gone.json())
        check("I3c the 404 never carries root's subject", b"Hello" not in miss.content)
        alice_ids = [m["id"] for m in c.get("/email_outbox/messages", headers=ALICE).json()["results"]]
        check("I3d a root message id is NOT IN alice's own list", root_id not in alice_ids, f"root {root_id} in {alice_ids}")
        root_ids = [m["id"] for m in c.get("/email_outbox/messages", headers=ROOT).json()["results"]]
        check("I3e root's own list DOES contain it", root_id in root_ids)

        # I4 — HEADER SAFETY: CR/LF/NEL/line-sep/tab in the subject -> 422; injection THROUGH a rendered template -> 422
        bad_subjects = ["a\r\nBcc: e@x.com", "a\nb", "a\rb", "a" + chr(0x85) + "b",
                        "a" + chr(0x2028) + "b", "a" + chr(0x2029) + "b", "a\tb"]
        for bad in bad_subjects:
            check(f"I4a subject U+{ord([c for c in bad if ord(c) < 0x20 or ord(c) >= 0x7F][0]):04X} -> 422",
                  send({**base, "subject": bad}, key=None).status_code == 422, f"subject {bad!r}")
        inj = send({"from": "s@x.com", "to": ["a@x.com"],
                    "template": {"id": "notify", "data": {"title": "x\r\nBcc: e@x.com", "body": "hi"}}})
        check("I4b a template data value injecting into the rendered subject -> 422 (validate-after-render)",
              inj.status_code == 422, f"got {inj.status_code}")

        # I5 — append-only: no PUT/PATCH/DELETE route on a message
        methods = {(tuple(sorted(r.methods)) if r.methods else (), r.path) for r in app.routes
                   if hasattr(r, "path") and r.path.startswith("/email")}
        mutator = any(any(m in (ms or ()) for m in ("PUT", "PATCH", "DELETE")) for ms, _ in methods)
        check("I5 no update/delete route (immutable by construction)", not mutator, f"routes {methods}")

        # I6 — render containment: a lone surrogate is contained to U+FFFD (stored bytes UTF-8-clean); missing var 422.
        # The surrogate is sent as a RAW json \u escape (httpx cannot UTF-8-encode a surrogate via json=); the server's
        # json parser decodes it to a lone surrogate, which the handler must contain to U+FFFD (the ai_tools class).
        raw_sur = '{"from": "s@x.com", "to": ["a@x.com"], "subject": "x\\ud800y", "text": "b\\ud834z"}'
        sur = c.post("/email_outbox/messages", content=raw_sur,
                     headers={**ROOT, "Content-Type": "application/json", "Idempotency-Key": "i6"})
        check("I6a a lone-surrogate subject/body does NOT 5xx (contained)", sur.status_code == 201, f"got {sur.status_code}")
        stored = [m for m in store.values("email_outbox_messages") if m["owner"] == "root" and m["id"] == sur.json()["id"]][0]
        clean = all(not (0xD800 <= ord(ch) <= 0xDFFF) for ch in stored["subject"] + stored["text"])
        check("I6b white-box: the STORED subject/body carry NO lone surrogate (U+FFFD-contained)", clean)
        check("I6c the contained value is UTF-8-serializable", (stored["subject"] + stored["text"]).encode("utf-8") is not None)
        check("I6d a template with a missing variable -> 422",
              send({"from": "s@x.com", "to": ["a@x.com"], "template": {"id": "notify", "data": {"body": "b"}}}).status_code == 422)

        # I7 — bounds: recipient count, body octets, subject length
        many = [f"r{i}@x.com" for i in range(51)]
        check("I7a 51 recipients -> 422 (count cap)", send({**base, "to": many}, key=None).status_code == 422)
        check("I7b 50 recipients -> 201 (at the cap)", send({"from": "s@x.com", "to": many[:50], "subject": "ok", "text": "b"}, key="i7b").status_code == 201)
        check("I7c an over-cap body -> 422", send({**base, "text": "a" * 262145}, key=None).status_code == 422)
        check("I7d an over-long subject -> 422", send({**base, "subject": "a" * 999}, key=None).status_code == 422)

    # I8 — concurrency: two processes race the SAME (owner, key); exactly ONE message, both served the winner
    if os.getenv("DATABASE_PATH"):
        procs = [subprocess.Popen([sys.executable, "-c", RACE_WORKER], cwd=os.getcwd(),
                                  env={**os.environ, "LOG_LEVEL": "silent"},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        outs = []
        for p in procs:
            so, se = p.communicate(timeout=120)
            outs.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:120]))
        ids = [o for rc, o in outs if rc == 0 and str(o).isdigit()]
        check("I8a both racers succeed and get the SAME message id (one winner)", len(ids) == 2 and ids[0] == ids[1], f"got {outs}")
        with TestClient(app, raise_server_exceptions=False, headers=ROOT) as c:
            raced = [m for m in store.values("email_outbox_messages") if m["owner"] == "root" and m["subject"] == "Raced"]
            check("I8b white-box: exactly ONE message for the raced key (no double-send)", len(raced) == 1, f"got {len(raced)}")
    else:
        print("  [FAIL] I8 concurrency NOT RUN — DATABASE_PATH unset")
        failures.append("I8 not run")

    print(f"EMAIL INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
