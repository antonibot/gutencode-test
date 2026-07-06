"""AI_TOOLS INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the BUILT
python app (cwd = <app>/python). Credited by EXIT CODE ONLY.

Proves:  I1 SAFE EXECUTION — a missing required arg is a contained ok:false RESULT (HTTP 200) for EVERY
            registered tool, discovered from the live listing (no tool can opt out of containment).
         I2 the BOUND holds — repeat (the only amplifying tool) with a hostile n never exceeds the cap.
         I3 the listing is honest — every listed tool invokes; an unlisted tool is 404.
         I4 determinism + codepoints — same args, same output; reverse works by codepoints (non-BMP proven).
         I5 strict input — malformed args/tool names are rejected.
         I6 deny-by-default — invoke is 401 without a valid bearer token, BEFORE any path/body validation
            (identity seam: any authenticated caller may invoke; an anonymous one never can).
         I7 the TYPED CONTRACT — the listing exposes each tool's description + input_schema, and an arg of the
            WRONG TYPE is a CONTAINED typed error (HTTP 200, never a 5xx) for EVERY tool, derived from the live
            listing. Integer args are STRICT and x3-safe (5.0 / "5" / true / null AND any magnitude beyond
            +/-(2**53-1) rejected; a bare safe integer accepted); a prototype-chain tool name is an honest 404;
            a lone surrogate in text is normalized to U+FFFD (never an uncontained 5xx); an extra arg is ignored."""
import os
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # enable the core test-session seam: `test:<subject>` resolves to <subject>

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def main():
    # ai_tools invoke is authenticated: any authenticated caller may invoke. Send every request as the inert
    # test subject 'alice' by default; the I6 anonymous probes deliberately drop the header to prove the 401.
    auth = {"Authorization": "Bearer test:alice"}
    with TestClient(app, raise_server_exceptions=False, headers=auth) as c, \
            TestClient(app, raise_server_exceptions=False) as anon:   # anon carries NO default token
        def invoke(tool, args):
            return c.post(f"/tools/{tool}/invoke", json={"args": args})

        # I6 — deny-by-default: invoke is 401 without a valid bearer token, and auth fires BEFORE validation
        check("I6a invoke no token -> 401",
              anon.post("/tools/upper/invoke", json={"args": {"text": "x"}}).status_code == 401)
        check("I6b forged token -> 401",
              anon.post("/tools/upper/invoke", json={"args": {"text": "x"}},
                        headers={"Authorization": "Bearer nosuchtoken"}).status_code == 401)
        check("I6c missing Bearer prefix -> 401",
              anon.post("/tools/upper/invoke", json={"args": {"text": "x"}},
                        headers={"Authorization": "test:alice"}).status_code == 401)
        check("I6d auth precedes validation: no token + otherwise-422 body -> 401",
              anon.post("/tools/upper/invoke", json={"args": "not-an-object"}).status_code == 401)

        listing = c.get("/tools").json()
        names = [t["name"] for t in listing]

        # I1 — containment holds for EVERY tool, derived from the live listing
        for t in listing:
            r = invoke(t["name"], {})
            check(f"I1 {t['name']}: missing required args -> contained ok:false (HTTP 200)",
                  r.status_code == 200 and r.json()["ok"] is False and r.json()["error"])

        # I2 — the repeat bound under hostile (but well-typed) inputs. repeat is the ONLY amplifying tool (upper/
        # reverse preserve length, wordcount reduces to a count); the cap is what makes "output can never explode" true.
        huge = invoke("repeat", {"text": "x", "n": 10**9}).json()
        check("I2a a huge (valid integer) n is capped at 100", huge["ok"] and len(huge["output"]) == 100)
        neg = invoke("repeat", {"text": "x", "n": -5}).json()
        check("I2b a negative (valid integer) n yields empty, never an error", neg["ok"] and neg["output"] == "")
        garbage = invoke("repeat", {"text": "x", "n": "lots"})
        check("I2c a non-integer n is a CONTAINED typed error, not a silent default",
              garbage.status_code == 200 and garbage.json()["ok"] is False
              and garbage.json()["error"] == "arg 'n' must be an integer")

        # I3 — the listing is honest
        check("I3a the listing is the sorted registry", names == sorted(names) and len(names) == 4)
        for t in names:
            check(f"I3b listed tool {t!r} invokes", invoke(t, {"text": "ok"}).json()["ok"] is True)
        check("I3c an unlisted tool is 404", invoke("sub_agent", {"text": "x"}).status_code == 404)

        # I4 — determinism + codepoint reverse (🔑 must survive reversal intact, not split into surrogates)
        a = invoke("reverse", {"text": "ab🔑中"}).json()
        b = invoke("reverse", {"text": "ab🔑中"}).json()
        check("I4a codepoint reverse keeps non-BMP chars whole", a["output"] == "中🔑ba", f"got {a['output']!r}")
        check("I4b deterministic", a == b)
        check("I4c wordcount splits on any whitespace",
              invoke("wordcount", {"text": "  a\tb\nc  "}).json()["output"] == "3")

        # I5 — strict input
        check("I5a non-object args -> 422", invoke("upper", "nope").status_code == 422)
        check("I5b array args -> 422", invoke("upper", [1]).status_code == 422)
        check("I5c control-char tool name -> 422", c.post("/tools/p%1Fq/invoke", json={"args": {}}).status_code == 422)

        # I7 — the TYPED CONTRACT + typed-arg containment, derived from the live listing (no tool can opt out)
        for t in listing:
            sch = t.get("input_schema", {})
            check(f"I7a {t['name']}: listing carries a description + a JSON-Schema input_schema",
                  isinstance(t.get("description"), str) and t["description"]
                  and sch.get("type") == "object" and isinstance(sch.get("properties"), dict)
                  and isinstance(sch.get("required"), list))
        rsch = next(t["input_schema"] for t in listing if t["name"] == "repeat")
        check("I7b repeat's schema declares text:string (required) + n:integer (optional)",
              rsch["properties"].get("text", {}).get("type") == "string"
              and rsch["properties"].get("n", {}).get("type") == "integer"
              and rsch["required"] == ["text"])
        # I7c — a wrong-type value for EVERY tool's required `text` is a contained typed error (HTTP 200, never a 5xx)
        for t in listing:
            for bad_text in (123, None, ["x"]):
                r = invoke(t["name"], {"text": bad_text})
                check(f"I7c {t['name']}: text={bad_text!r} -> contained typed error (HTTP 200)",
                      r.status_code == 200 and r.json()["ok"] is False
                      and r.json()["error"] == "arg 'text' must be a string")
        # I7d — the strict-int seam, the TYPE axis: 5.0 / "5" / true / null all rejected (never a 5xx). The 5.0 case
        # is the latent x3 divergence the typed contract closes for this axis (python kept 1, go/node read 5).
        for bad_n in (5.0, "5", True, None):
            r = invoke("repeat", {"text": "x", "n": bad_n})
            check(f"I7d repeat n={bad_n!r}: a non-integer n -> contained typed error (HTTP 200)",
                  r.status_code == 200 and r.json()["ok"] is False
                  and r.json()["error"] == "arg 'n' must be an integer")
        # I7e — the MAGNITUDE axis: a value beyond the shared safe-integer range (±(2**53-1)) is rejected uniformly
        # ×3 (python is arbitrary-precision, go's Atoi caps at int64, node loses float precision — so the contract
        # caps at the range all three represent EXACTLY, else they diverge). The boundary value itself is accepted.
        max_safe = 9007199254740991
        for big_n in (max_safe + 1, 2 ** 53, 2 ** 63, 99999999999999999999, -(2 ** 63), -(max_safe + 1)):
            r = invoke("repeat", {"text": "x", "n": big_n})
            check(f"I7e repeat n={big_n}: a magnitude past the safe range -> contained typed error (HTTP 200)",
                  r.status_code == 200 and r.json()["ok"] is False
                  and r.json()["error"] == "arg 'n' must be an integer")
        edge = invoke("repeat", {"text": "x", "n": max_safe}).json()   # the boundary IS in range -> accepted + clamped
        check("I7e2 repeat n=2**53-1 (the safe-range edge) is accepted + clamped to the cap",
              edge["ok"] and len(edge["output"]) == 100)
        good = invoke("repeat", {"text": "x", "n": 4}).json()
        check("I7f repeat n=4 (a bare safe integer) is accepted", good["ok"] and good["output"] == "xxxx")
        # I7g — an undeclared extra arg is IGNORED (lenient): a new optional arg never breaks an old caller
        extra = invoke("upper", {"text": "hi", "bogus": 1, "n": 99}).json()
        check("I7g undeclared extra args are ignored (lenient)", extra["ok"] and extra["output"] == "HI")
        # I7h — a prototype-chain tool name is an honest 404, NEVER a crash (the lookup is own-property only ×3)
        for proto in ("__proto__", "toString", "constructor", "valueOf", "hasOwnProperty"):
            check(f"I7h tool name {proto!r} -> 404 (own-property lookup, never a 5xx)",
                  invoke(proto, {"text": "x"}).status_code == 404)
        # I7i — a LONE SURROGATE in text is CONTAINED: normalized to U+FFFD (matches go's decoder), so the response
        # always serializes — never the uncontained 5xx an un-encodable surrogate would raise at serialization. Send
        # it as a RAW ASCII \uXXXX escape in the body, so the test client itself never has to encode a lone surrogate
        # (the app's json parser decodes the escape into one); then assert the OUTPUT carries U+FFFD, not the surrogate.
        hdr = {"content-type": "application/json"}
        sur = c.post("/tools/reverse/invoke", content='{"args":{"text":"ab\\ud800"}}', headers=hdr)
        check("I7i a lone surrogate in text is contained (HTTP 200) + normalized to U+FFFD",
              sur.status_code == 200 and sur.json()["ok"] is True
              and chr(0xFFFD) in sur.json()["output"] and chr(0xD800) not in sur.json()["output"])
        suru = c.post("/tools/upper/invoke", content='{"args":{"text":"x\\udfffy"}}', headers=hdr).json()
        check("I7i2 a lone surrogate survives a tool as U+FFFD (serializable)",
              suru["ok"] and chr(0xFFFD) in suru["output"])

    print(f"AI_TOOLS INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
