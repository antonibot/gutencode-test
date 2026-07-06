"""AI_PROVIDER INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the BUILT
python app (cwd = <app>/python). Credited by EXIT CODE ONLY.

Proves:  I1 BILLING CONSERVATION — after any mix of fresh calls and replays, GET usage equals the
            independently-tracked sum of exactly the BILLED (non-cached) completions.
         I2 a replay is never re-billed — identical model+prompt returns cached:true with the meter unmoved.
         I3 fallback — an unknown model degrades to the default (never a 5xx) and shares the default's cache.
         I4 cache-key honesty — same prompt under different KNOWN models are different completions; the
            digest-keyed cache cannot be confused by crafted prompt text.
         I5 determinism — output and token counts are pure functions of (model, prompt); tokens are utf-8
            BYTE lengths (unicode-proven).
         I6 strict input.
         I7 USAGE IS ADMIN-ONLY — GET /ai/usage is the GLOBAL spend meter, so it is gated by the core admin
            seam: no token -> 401, a valid non-admin -> 403, an admin -> 200 (authn -> authz BEFORE the read).
         I8 FAIL-LOUD PROVIDER SEAM — AI_PROVIDER=anthropic/openai WITHOUT the matching key env, or any unknown
            value, makes POST /ai/complete 501 with the exact detail naming what to set, NEVER silent fake
            output; the refusal is never billed and never cached (the CONSERVED meter does not move); GET
            /ai/usage keeps working under the keyless env (the failure is local to completions); the offline
            default ('fake'/unset) is unchanged.
         I9 THE SHIPPED ADAPTERS REACH — with AI_PROVIDER=anthropic|openai + a dummy key + the base URL pointed
            at a LOOPBACK stub speaking the provider's wire shape: the adapter sends the documented request
            (path, auth header, version pin, configured model, the prompt), the route returns the stub's text
            with the stub's REAL token usage billed into the conserved meter, a replay serves from cache WITHOUT
            a second upstream call, an upstream 500 maps to a SANITIZED 502 (never billed, never cached), and a
            hung upstream maps to 504 under AI_TIMEOUT_SECONDS. With the refusal-only build every one of these
            calls would 501 — the proof goes RED if the adapters are deleted (genuinely REACHING). Offline: the
            stub is 127.0.0.1 only; no real network is ever touched."""
import http.server
import json
import os
import re
import sys
import threading
import time

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

failures = []

# /ai/complete is an authenticated mutation: enable the test-session seam (Bearer test:<subject>, inert in
# prod) and send every request as the inert test subject 'alice' (a NON-admin). The meter stays a single global
# 'total' key for now (the per-subject meter is a FOLLOW-ON), so billing conservation holds against ONE caller's
# stream. GET /ai/usage is the GLOBAL spend meter -> ADMIN-ONLY, so it is read with the inert test admin 'root'.
os.environ["APP_TEST_SESSIONS"] = "1"
AUTH = {"Authorization": "Bearer test:alice"}     # an authenticated NON-admin caller (default for /ai/complete)
ADMIN = {"Authorization": "Bearer test:root"}     # the inert test admin — REQUIRED to read GET /ai/usage


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def main():
    with TestClient(app, raise_server_exceptions=False, headers=AUTH) as c:
        billed = {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0, "cost": 0}

        def complete(prompt, model=None):
            body = {"prompt": prompt} if model is None else {"prompt": prompt, "model": model}
            r = c.post("/ai/complete", json=body).json()
            if not r["cached"]:
                billed["requests"] += 1
                for k in ("prompt_tokens", "completion_tokens", "cost"):
                    billed[k] += r["usage"][k]
            return r

        def usage():  # GET /ai/usage is ADMIN-ONLY — always read the global meter as the inert test admin
            return c.get("/ai/usage", headers=ADMIN).json()

        # I1 + I2 — a mix of fresh and replayed calls; the meter must equal OUR ledger exactly
        complete("alpha")
        complete("alpha")                      # replay
        complete("beta", "smart")
        complete("beta", "smart")              # replay
        complete("gamma", "fast")
        complete("alpha")                      # replay again
        meter = usage()
        check("I1 the meter is CONSERVED (equals the sum of billed completions)", meter == billed,
              f"meter {meter} vs ledger {billed}")
        before = dict(meter)
        r = complete("alpha")
        check("I2a the replay is cached", r["cached"] is True)
        check("I2b ...and the meter did not move", usage() == before)

        # I3 — fallback shares the default's cache (same digest key)
        fb = complete("alpha", "model-that-does-not-exist")
        check("I3 unknown model falls back AND hits the default's cache",
              fb["model"] == "fake" and fb["cached"] is True)

        # I4 — cache-key honesty: models separate; crafted prompts can't collide keys
        a = complete("same prompt", "fast")
        b = complete("same prompt", "smart")
        check("I4a same prompt, different models -> different completions", a["output"] != b["output"])
        x = complete("fake:injected")          # a prompt that LOOKS like a joined key
        check("I4b a crafted prompt is its own cache entry, not a collision", x["cached"] is False)

        # I5 — determinism + byte-length tokens (unicode)
        u1 = complete("pässwörd-🔑")
        check("I5a unicode tokens are utf-8 BYTE length",
              u1["usage"]["prompt_tokens"] == len("pässwörd-🔑".encode("utf-8")))
        u2 = complete("pässwörd-🔑")
        check("I5b identical input, identical completion (cached)", u2["output"] == u1["output"] and u2["cached"])

        # I6 — strict input
        for bad in ({}, {"prompt": ""}, {"prompt": 7}, {"prompt": "x", "model": 7}):
            check(f"I6 invalid body {bad!r} -> 422", c.post("/ai/complete", json=bad).status_code == 422)

    # I7 — GET /ai/usage is ADMIN-ONLY (it is the GLOBAL spend meter): authn -> authz BEFORE the read. Use a fresh
    # client with NO default auth header so the no-token case is genuinely token-less (per-request headers MERGE over
    # client defaults in httpx, so a default Authorization can't be cleared with headers={}).
    with TestClient(app, raise_server_exceptions=False) as c:
        check("I7a no token -> 401", c.get("/ai/usage").status_code == 401)
        check("I7b malformed (non-Bearer) token -> 401",
              c.get("/ai/usage", headers={"Authorization": "test:root"}).status_code == 401)
        check("I7c authenticated NON-admin -> 403", c.get("/ai/usage", headers=AUTH).status_code == 403)
        check("I7d admin -> 200", c.get("/ai/usage", headers=ADMIN).status_code == 200)

    # I8 — FAIL-LOUD PROVIDER SEAM (the honesty contract): a real provider name WITHOUT its key env NEVER
    # silently serves fake output, and a refusal never touches the CONSERVED meter or the cache. AI_PROVIDER
    # and the key envs are read at CALL time in all three languages, so the flips below are per-request.
    # REACHING: with the gate removed, every refusal below comes back 200 '[fake] …' — I8a/b/e/g go RED.
    saved8 = {k: os.environ.get(k) for k in ("AI_PROVIDER", "ANTHROPIC_API_KEY", "OPENAI_API_KEY")}
    with TestClient(app, raise_server_exceptions=False) as c:
        meter_before = c.get("/ai/usage", headers=ADMIN).json()
        try:
            os.environ["AI_PROVIDER"] = "anthropic"
            os.environ.pop("ANTHROPIC_API_KEY", None)   # the keyless state under proof (the machine may set it)
            r = c.post("/ai/complete", json={"prompt": "wired probe"}, headers=AUTH)
            check("I8a real provider without its key -> 501 (never a silent fake 200)",
                  r.status_code == 501, f"{r.status_code} {r.text[:160]}")
            check("I8b the 501 detail NAMES the missing key env (byte-identical ×3)",
                  r.json().get("detail") == "provider 'anthropic' needs ANTHROPIC_API_KEY — see INTEROP.md",
                  r.text[:160])
            check("I8c no fake output leaks through the refusal", "[fake]" not in r.text)
            check("I8d GET /ai/usage keeps working under the keyless env (failure local to completions)",
                  c.get("/ai/usage", headers=ADMIN).status_code == 200)
            check("I8e the refusal was NEVER billed (the CONSERVED meter did not move)",
                  c.get("/ai/usage", headers=ADMIN).json() == meter_before)
            os.environ["AI_PROVIDER"] = "openai"
            os.environ.pop("OPENAI_API_KEY", None)
            ro = c.post("/ai/complete", json={"prompt": "wired probe"}, headers=AUTH)
            check("I8f the other provider refuses identically keyless; an unknown name keeps its own detail",
                  ro.status_code == 501
                  and ro.json().get("detail") == "provider 'openai' needs OPENAI_API_KEY — see INTEROP.md",
                  ro.text[:160])
            os.environ["AI_PROVIDER"] = "banana"
            ru = c.post("/ai/complete", json={"prompt": "wired probe"}, headers=AUTH)
            check("I8f2 an unknown provider string takes the SAME loud path with its own detail",
                  ru.status_code == 501
                  and ru.json().get("detail") == "unknown provider 'banana' — see INTEROP.md", ru.text[:160])
            os.environ["AI_PROVIDER"] = "fake"
            rf = c.post("/ai/complete", json={"prompt": "wired probe"}, headers=AUTH)
            check("I8g the explicit offline default still completes — and the refusals never seeded the cache",
                  rf.status_code == 200 and rf.json().get("cached") is False
                  and rf.json().get("output") == "[fake] WIRED PROBE", rf.text[:160])
        finally:
            for k, v in saved8.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    # I9 — THE SHIPPED ADAPTERS REACH (offline: loopback stubs speaking each provider's wire shape). Proves the
    # adapter sends the documented request, extracts text + REAL usage, bills the conserved meter, replays from
    # cache without re-calling upstream, and maps upstream failure to sanitized 502 / 504 — never billed, never
    # cached. With the refusal-only build every call below would 501: delete the adapters and this goes RED.
    DUMMY = "sk-dummy-XYZ"

    def stub_server(mode):
        calls = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("content-length") or 0))
                calls.append({"path": self.path,
                              "headers": {k.lower(): v for k, v in self.headers.items()},
                              "body": json.loads(raw or b"{}")})
                if mode == "hang":
                    time.sleep(6)   # far past the 1s AI_TIMEOUT_SECONDS the test sets
                if mode == "err":   # the body ECHOES the key value: the 502 detail must redact it
                    code, payload = 500, {"error": {"message": f"stub exploded {DUMMY}"}}
                elif mode == "openai":
                    code, payload = 200, {"choices": [{"message": {"role": "assistant", "content": "stub says hi"}}],
                                          "usage": {"prompt_tokens": 11, "completion_tokens": 13}}
                else:
                    code, payload = 200, {"content": [{"type": "text", "text": "stub says hi"}],
                                          "usage": {"input_tokens": 7, "output_tokens": 9}}
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):   # keep the proof output clean; never print request headers
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, calls

    ok_a, calls_a = stub_server("anthropic")
    ok_o, calls_o = stub_server("openai")
    err_s, _calls_e = stub_server("err")
    hang_s, _calls_h = stub_server("hang")
    ENV9 = ("AI_PROVIDER", "AI_MODEL", "AI_TIMEOUT_SECONDS", "AI_MAX_TOKENS",
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL")
    saved9 = {k: os.environ.get(k) for k in ENV9}
    with TestClient(app, raise_server_exceptions=False) as c:
        def meter():
            return c.get("/ai/usage", headers=ADMIN).json()

        try:
            for k in ENV9:
                os.environ.pop(k, None)   # a clean slate — the machine env must not steer the wired probes
            os.environ.update({"AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": DUMMY,
                               "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{ok_a.server_address[1]}"})
            m0 = meter()
            r = c.post("/ai/complete", json={"prompt": "stub ping"}, headers=AUTH)
            check("I9a wired anthropic: the gateway returns the STUB's text under the configured default model",
                  r.status_code == 200 and r.json().get("output") == "stub says hi"
                  and r.json().get("model") == "claude-sonnet-4-6" and r.json().get("cached") is False,
                  r.text[:200])
            check("I9b the STUB's real token usage is extracted (not the fake's byte-count formula)",
                  r.json().get("usage") == {"prompt_tokens": 7, "completion_tokens": 9, "cost": 0}, r.text[:200])
            m1 = meter()
            check("I9c the meter is CONSERVED over REAL billing (moved by exactly the stub's usage)",
                  m1 == {"requests": m0["requests"] + 1, "prompt_tokens": m0["prompt_tokens"] + 7,
                         "completion_tokens": m0["completion_tokens"] + 9, "cost": m0["cost"]},
                  f"{m0} -> {m1}")
            sent = calls_a[-1] if calls_a else {}
            hdr, body = sent.get("headers", {}), sent.get("body", {})
            check("I9d the adapter spoke the Messages wire shape (path + key header + version pin + model + prompt)",
                  sent.get("path") == "/v1/messages" and hdr.get("x-api-key") == DUMMY
                  and bool(re.fullmatch(r"20\d\d-\d\d-\d\d", hdr.get("anthropic-version", "")))
                  and body.get("model") == "claude-sonnet-4-6" and isinstance(body.get("max_tokens"), int)
                  and body.get("messages") == [{"role": "user", "content": "stub ping"}],
                  str({"path": sent.get("path"), "body": body})[:200])
            n_up = len(calls_a)
            r2 = c.post("/ai/complete", json={"prompt": "stub ping"}, headers=AUTH)
            check("I9e a replay serves from CACHE: no second upstream call, the meter unmoved",
                  r2.status_code == 200 and r2.json().get("cached") is True
                  and len(calls_a) == n_up and meter() == m1, r2.text[:160])

            os.environ.update({"AI_PROVIDER": "openai", "OPENAI_API_KEY": DUMMY,
                               "OPENAI_BASE_URL": f"http://127.0.0.1:{ok_o.server_address[1]}"})
            r3 = c.post("/ai/complete", json={"prompt": "oai ping"}, headers=AUTH)
            sent3 = calls_o[-1] if calls_o else {}
            check("I9f wired openai: chat-completions wire shape + Bearer auth + the stub's text and usage",
                  r3.status_code == 200 and r3.json().get("output") == "stub says hi"
                  and r3.json().get("model") == "gpt-4o"
                  and r3.json().get("usage") == {"prompt_tokens": 11, "completion_tokens": 13, "cost": 0}
                  and sent3.get("path") == "/v1/chat/completions"
                  and sent3.get("headers", {}).get("authorization") == f"Bearer {DUMMY}"
                  and sent3.get("body", {}).get("model") == "gpt-4o", r3.text[:200])

            os.environ.update({"AI_PROVIDER": "anthropic",
                               "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{err_s.server_address[1]}"})
            m2 = meter()
            r4 = c.post("/ai/complete", json={"prompt": "boom boom"}, headers=AUTH)
            check("I9g upstream 500 -> a LOUD 502 naming the status, with the key REDACTED from the snippet",
                  r4.status_code == 502
                  and r4.json().get("detail", "").startswith("provider 'anthropic' upstream error (HTTP 500)")
                  and DUMMY not in r4.text, r4.text[:200])
            check("I9h the failure was never billed", meter() == m2)
            os.environ["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{ok_a.server_address[1]}"
            r5 = c.post("/ai/complete", json={"prompt": "boom boom"}, headers=AUTH)
            check("I9i the failure was never cached (the same prompt is a fresh MISS once upstream recovers)",
                  r5.status_code == 200 and r5.json().get("cached") is False, r5.text[:160])

            os.environ.update({"AI_TIMEOUT_SECONDS": "1",
                               "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{hang_s.server_address[1]}"})
            m3 = meter()
            r6 = c.post("/ai/complete", json={"prompt": "slow slow"}, headers=AUTH)
            check("I9j a hung upstream -> 504 under the AI_TIMEOUT_SECONDS budget, never billed",
                  r6.status_code == 504
                  and r6.json().get("detail") == "provider 'anthropic' upstream timeout or network failure"
                  and meter() == m3, r6.text[:160])
        finally:
            for k, v in saved9.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            for srv in (ok_a, ok_o, err_s):
                srv.shutdown()   # the hang stub's worker is a daemon thread; leave it to die with the process

    print(f"AI_PROVIDER INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
