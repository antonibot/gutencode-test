"""WEBHOOKS INVARIANTS — correctness proofs for this domain's dangerous property: DELIVERY INTEGRITY at a trust
boundary (verify a signature, reject forgeries AND replays, accept a rotated secret, process exactly-once). Run against
the python app (cwd=<app>/python; DATABASE_PATH + APP_TEST_CLOCK set by the harness). Credited by EXIT CODE ONLY.

Proves:  I1 roundtrip — what /send signs (with EVERY active secret), /verify accepts (same clock).
         I2 tamper — flipping ANY single character of a SINGLE-candidate signature -> valid:false (every position).
         I3 replay WINDOW — outside tolerance (both directions) -> valid:false; inside -> true.
         I4 ids are monotonic and never reused within a run.
         I5 inbound replay-DEDUP — the FIRST verify of a valid event is not a duplicate; a 2nd verify of the SAME
            event (same id, inside the window) is a duplicate; a DISTINCT id is independent [exactly-once].
         I6 MULTI-SECRET ROTATION — the app holds TWO active secrets (set before import): a webhook signed with EITHER
            verifies (zero-downtime rotation); a NON-active secret rejects; a MULTI-candidate header (garbage FIRST,
            valid second) verifies (any-match — a malformed sibling does not sink the valid one).
         I7 EVENT-SCOPED dedup ACROSS secrets — an event delivered under secret0 then re-verified under ONLY secret1's
            signature is a DUPLICATE (exactly-once keys on the event id, not which secret matched; a split-header replay
            during a rotation cannot re-process the event). The regression wall for the matched-index dedup bug.
(The SSRF IP-classification floor is url_safety's own proven ×3 contract, not re-proven here — webhooks does not
yet deliver, so the primitive lands as a standalone part for the deferred sender domain.)
/send is ADMIN-only (the test-session 'Bearer test:root' resolves via APP_TEST_SESSIONS=1, inert in prod); /verify
is PUBLIC (the HMAC is the identity). The two active secrets prove rotation without changing signature/dedup behavior."""
import base64
import hashlib
import hmac
import os
import sys

os.environ["APP_TEST_SESSIONS"] = "1"  # the test-session seam: a 'test:<subject>' bearer resolves (inert in prod)
# TWO active secrets BEFORE the app import (the app reads WEBHOOK_SECRETS at module load) — so I6 proves zero-downtime
# rotation: a webhook signed with EITHER active secret verifies. NEWLINE-separated (the domain's list grammar).
os.environ["WEBHOOK_SECRETS"] = "whsec_demo_change_me\nwhsec_rotated_new"

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

SECRETS = [s.strip() for s in os.getenv("WEBHOOK_SECRETS", "whsec_demo_change_me").split("\n") if s.strip()]
ADMIN = {"Authorization": "Bearer test:root"}  # /send is admin-only; /verify stays token-less
failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def sign_v1(secret, msg_id, ts, payload):
    """A SINGLE-candidate 'v1,<b64>' signature with ONE chosen secret — so a tamper test has exactly one candidate to
    corrupt and a rotation test can pick which secret signs. Mirrors the signing part; drives /verify with a controlled
    signature (the /send multi-secret path is proven separately by I1)."""
    mac = hmac.new(secret.encode(), f"{msg_id}.{ts}.{payload}".encode(), hashlib.sha256).digest()
    return "v1," + base64.b64encode(mac).decode()


def main():
    with TestClient(app, raise_server_exceptions=False, headers=ADMIN) as c:
        def vrf(msg_id, payload, signature, now=5000):
            return c.post(f"/webhooks/verify?now={now}",
                          json={"id": msg_id, "timestamp": 5000, "payload": payload, "signature": signature}).json()

        # I1 roundtrip — /send signs with EVERY active secret; /verify accepts (multi-candidate any-match)
        sent = c.post("/webhooks/send?payload=inv-proof&now=5000").json()
        r = vrf(sent["id"], sent["payload"], sent["signature"])
        check("I1 sign -> verify roundtrip is valid", r.get("valid") is True, str(r))

        # I2 tamper — EVERY single-character flip of a SINGLE-candidate signature must fail (no sibling candidate can
        # rescue a corrupted one). Same id throughout: a tampered sig is invalid -> never reaches the dedup behind it.
        sig = sign_v1(SECRETS[0], "tamper_1", 5000, "tamper-proof")
        check("I2 baseline single-candidate sig is valid", vrf("tamper_1", "tamper-proof", sig).get("valid") is True)
        tampered_ok = 0
        for i in range(len(sig)):
            flipped = sig[:i] + ("A" if sig[i] != "A" else "B") + sig[i + 1:]
            if vrf("tamper_1", "tamper-proof", flipped).get("valid") is False:
                tampered_ok += 1
        check("I2 every single-char tamper rejected", tampered_ok == len(sig), f"{tampered_ok}/{len(sig)}")

        # I3 replay window (tolerance 300): inside ok, outside (late AND early) rejected. Single candidate, fresh id.
        wsig = sign_v1(SECRETS[0], "win_1", 5000, "win-proof")
        check("I3a inside tolerance accepted", vrf("win_1", "win-proof", wsig, now=5299).get("valid") is True)
        check("I3b stale (late) rejected", vrf("win_1", "win-proof", wsig, now=5301).get("valid") is False)
        check("I3c future-dated (early) rejected", vrf("win_1", "win-proof", wsig, now=4699).get("valid") is False)

        # I4 monotonic ids, never reused
        ids = [c.post(f"/webhooks/send?payload=p{i}&now=5000").json()["id"] for i in range(3)]
        nums = [int(x.split("_")[1]) for x in ids]
        check("I4 ids monotonic + unique", nums == sorted(nums) and len(set(nums)) == 3, str(nums))

        # I5 inbound replay-DEDUP — first verify not a duplicate; a 2nd verify of the SAME event is a duplicate; a
        # distinct id is independent. Single candidate so the matched-secret index (the dedup scope) is stable.
        dsig = sign_v1(SECRETS[0], "dedup_1", 5000, "dedup-proof")
        r1 = vrf("dedup_1", "dedup-proof", dsig)
        check("I5a first delivery is not a duplicate", r1.get("valid") is True and r1.get("duplicate") is False, str(r1))
        r2 = vrf("dedup_1", "dedup-proof", dsig)
        check("I5b replay of the same event is a duplicate", r2.get("valid") is True and r2.get("duplicate") is True, str(r2))
        osig = sign_v1(SECRETS[0], "dedup_2", 5000, "dedup-proof")
        r3 = vrf("dedup_2", "dedup-proof", osig)
        check("I5c a distinct event id is independent", r3.get("valid") is True and r3.get("duplicate") is False, str(r3))

        # I6 MULTI-SECRET ROTATION — TWO active secrets (set before import). A webhook signed with EITHER verifies; a
        # NON-active secret rejects; a multi-candidate header (garbage FIRST, valid second) verifies (any-match — a
        # malformed sibling does not sink the valid one). This is the titular rotation + the malformed-sibling floor.
        check("I6a signed with the FIRST active secret verifies",
              vrf("rot_a", "rot-proof", sign_v1(SECRETS[0], "rot_a", 5000, "rot-proof")).get("valid") is True)
        check("I6b signed with the SECOND (rotated) active secret verifies",
              vrf("rot_b", "rot-proof", sign_v1(SECRETS[1], "rot_b", 5000, "rot-proof")).get("valid") is True)
        check("I6c signed with a NON-active secret rejects",
              vrf("rot_c", "rot-proof", sign_v1("whsec_not_configured", "rot_c", 5000, "rot-proof")).get("valid") is False)
        garbage = "v1," + base64.b64encode(b"\x00" * 32).decode()
        valid_v1 = sign_v1(SECRETS[1], "rot_d", 5000, "rot-proof")
        check("I6d multi-candidate (garbage FIRST, valid second) still verifies (any-match, malformed sibling survives)",
              vrf("rot_d", "rot-proof", f"{garbage} {valid_v1}").get("valid") is True)

        # I7 EVENT-SCOPED dedup ACROSS secrets — the rotation-replay wall. A sender broadcasts one candidate per active
        # secret; an on-path replayer can SPLIT that header and re-present only ANOTHER secret's candidate. The dedup must
        # key on the EVENT ID, not which secret matched: an event delivered under secret0 and re-verified under ONLY
        # secret1's signature is the SAME event -> a DUPLICATE. (Before the fix the slot embedded the matched-secret index,
        # so the split replay landed in a different slot and re-processed — this leg is the regression wall for that bug.)
        x0 = sign_v1(SECRETS[0], "xsec_1", 5000, "xsec-proof")
        x1 = sign_v1(SECRETS[1], "xsec_1", 5000, "xsec-proof")   # SAME id, the OTHER active secret only
        d0 = vrf("xsec_1", "xsec-proof", x0)
        check("I7a first delivery (secret0) is not a duplicate", d0.get("valid") is True and d0.get("duplicate") is False, str(d0))
        d1 = vrf("xsec_1", "xsec-proof", x1)
        check("I7b the SAME event under secret1 is a DUPLICATE (event-scoped exactly-once across rotation)",
              d1.get("valid") is True and d1.get("duplicate") is True, str(d1))

    print(f"WEBHOOKS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
