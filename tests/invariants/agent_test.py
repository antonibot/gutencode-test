"""AGENT INVARIANTS — correctness proofs for the agent runtime (run against the python
app, cwd=<app>/python; the runner sets DATABASE_PATH + APP_TEST_CLOCK). Credited by EXIT CODE ONLY.

Proves:  I1 the run loop ALWAYS terminates — a never-finalizing provider request stops at EXACTLY the budget.
         I2 the budget knob binds — AGENT_MAX_ITERATIONS=2 in a fresh process stops the same runaway at 2.
         I3 tools never execute input — a code-injection calc expression returns a graceful error, not effects.
         I4 unknown tool is a graceful observation, never a crash.
         I5 memory accumulates — message history grows across runs and starts with the user turn.
         I6 session ownership (cross-AGENT, one owner) — another agent's session id is 404, not a data leak.
         I7 deny-by-default — every route addressed by {agent_id} is 401 without a valid bearer token (incl. the
            messages READ, which is USER-SCOPED — the core identity seam).
         I8 USER-SCOPED / CROSS-OWNER-404 — alice creates an agent + session + messages; a DIFFERENT real subject
            bob (register/login, not just a test bearer) gets 404 on GET messages / run / create-session for alice's
            agent (byte-identical to a missing id — existence never leaks over the enumerable id), and alice's data
            is UNTOUCHED (her history still reads, her session count is unchanged). The owner-stamp is the TOKEN's: a
            smuggled `owner` in the create body cannot override it, and owner is never in the API response.
         I13 FAIL-LOUD PROVIDER SEAM — AI_PROVIDER=anthropic/openai WITHOUT the matching key env, or any
            unknown value, makes the run route 501 with the exact detail naming what to set, NEVER a silent
            fake completion; the refusal is problem+json, leaves no history trace, and provider-free routes
            keep working; the offline default ('fake' / unset) is unchanged.
         I14 THE SHIPPED ADAPTERS REACH — with AI_PROVIDER=anthropic|openai + a dummy key + the base URL
            pointed at a LOOPBACK stub speaking the provider's wire shape: the adapter sends the documented
            request (path, auth header, version pin, configured model, the system prompt, merged
            user/assistant-only turns), the run returns the stub's text as its output, an upstream 500 maps to
            a SANITIZED 502 (key never echoed), and a hung upstream maps to 504 under AI_TIMEOUT_SECONDS. With
            the refusal-only build every one of these calls would 501 — the proof goes RED if the adapters are
            deleted (genuinely REACHING). Offline: the stub is 127.0.0.1 only; no real network is touched.
         I15 THE USAGE-METERING WIRE (B5) — a run meters its provider-call usage into the llm_usage ledger, but only
            the real/armed path (the fake is free + unmetered by default: the default bar stays INERT). Proven against
            whatever app this runs in: with the meter present an ARMED run records exactly one event for the run's
            OWNER with the fake's counts (a15d), is EXACTLY-ONCE on replay (I15e), the seam FAILS-OPEN on an unpriced
            call recording nothing (I15f), and a FAILING sink does NOT break the run (I15g); with the meter absent an
            armed run still returns 200 (I15c); an UNARMED run records NOTHING (I15a/b, the inert proof)."""
import http.server
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

os.environ["APP_TEST_SESSIONS"] = "1"   # enable the core test-session seam: `test:<subject>` resolves to <subject>

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.core import store  # noqa: E402
from app_pkg.app import app  # noqa: E402

failures = []


def _boom(owner, call, now):   # a deliberately-failing usage sink (I15g): proves a meter failure can't break a run
    raise RuntimeError("simulated meter failure")


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def main():
    # NO default header on the client (httpx MERGES a per-request headers={} with client defaults, so a default
    # could never be dropped for the no-token checks). Authed calls pass H explicitly. Every route addressed by
    # {agent_id} — INCLUDING the messages READ (USER-SCOPED) — is threaded with a token.
    with TestClient(app, raise_server_exceptions=False) as c:
        H = {"Authorization": "Bearer test:alice"}   # the authenticated caller (every mutation needs a token)

        # I7 — deny-by-default: every {agent_id}-addressed route is 401 without a valid bearer token (no/forged token)
        check("I7a create no token -> 401",
              c.post("/agents/", json={"name": "x", "system_prompt": "s"}).status_code == 401)
        check("I7b create session no token -> 401", c.post("/agents/1/sessions").status_code == 401)
        check("I7c run no token -> 401",
              c.post("/agents/1/sessions/1/run", json={"input": "x"}).status_code == 401)
        check("I7d forged token -> 401",
              c.post("/agents/", json={"name": "x", "system_prompt": "s"},
                     headers={"Authorization": "Bearer nosuchtoken"}).status_code == 401)
        check("I7e messages READ no token -> 401 (the read is now USER-SCOPED, no longer public)",
              c.get("/agents/1/sessions/1/messages").status_code == 401)

        c.post("/agents/", json={"name": "a1", "system_prompt": "sp"}, headers=H)
        c.post("/agents/1/sessions", headers=H)

        # I1 — the runaway request stops at exactly the default budget (6), flagged terminated
        r = c.post("/agents/1/sessions/1/run", json={"input": "use forever x"}, headers=H).json()
        check("I1 runaway terminates at the budget", r["terminated"] is True and r["iterations"] == 6, str(r))

        # I3 — code injection through calc is parsed, never executed
        marker = os.path.join(tempfile.gettempdir(), "agent_inv_pwned.txt")
        if os.path.exists(marker):
            os.remove(marker)
        evil = f"__import__('pathlib').Path(r'{marker}').write_text('pwned')"
        r = c.post("/agents/1/sessions/1/run", json={"input": f"use calc {evil}"}, headers=H).json()
        check("I3a injection returns a graceful error", "error: invalid expression" in r["output"], r["output"])
        check("I3b injection had NO side effect", not os.path.exists(marker))

        # I4 — unknown tool: graceful observation, run completes
        r = c.post("/agents/1/sessions/1/run", json={"input": "use nope x"}, headers=H)
        check("I4 unknown tool never crashes", r.status_code == 200 and "not found" in r.json()["output"])

        # I5 — memory accumulates and starts with the user turn (the GET read is USER-SCOPED — alice's token threaded)
        before = len(c.get("/agents/1/sessions/1/messages", headers=H).json())
        c.post("/agents/1/sessions/1/run", json={"input": "hello"}, headers=H)
        msgs = c.get("/agents/1/sessions/1/messages", headers=H).json()
        check("I5 memory grows per run", len(msgs) >= before + 2, f"{before} -> {len(msgs)}")
        check("I5 first turn is the user's", msgs[0]["role"] == "user")

        # I6 — another agent (SAME owner) cannot read/run this session (the session<->agent binding, not ownership)
        c.post("/agents/", json={"name": "a2", "system_prompt": "sp"}, headers=H)
        r = c.post("/agents/2/sessions/1/run", json={"input": "x"}, headers=H)
        check("I6 cross-agent session is 404", r.status_code == 404, str(r.status_code))

        # I8 — USER-SCOPED / cross-OWNER-404: bob is a DIFFERENT real subject (register/login, not just a test
        # bearer). He cannot GET messages / run / create-session on alice's agent — each is 404, byte-identical to a
        # missing id — and alice's data survives intact. The owner-stamp is the TOKEN's, never the body's.
        def token_for(u):
            c.post("/auth/register", json={"email": u, "password": f"pw-{u}-1234"})
            return c.post("/auth/login", json={"email": u, "password": f"pw-{u}-1234"}).json()["access_token"]

        def Hb(t):
            return {"Authorization": f"Bearer {t}"}

        tb = token_for("bob_owner")   # a real, distinct session subject
        a_msgs_before = c.get("/agents/1/sessions/1/messages", headers=H).json()   # snapshot BEFORE bob's attempts
        missing = c.get("/agents/999/sessions/1/messages", headers=H)             # alice's own missing-id baseline
        x_msgs = c.get("/agents/1/sessions/1/messages", headers=Hb(tb))
        x_run = c.post("/agents/1/sessions/1/run", json={"input": "x"}, headers=Hb(tb))
        x_sess = c.post("/agents/1/sessions", headers=Hb(tb))
        check("I8a cross-owner GET messages is 404 (never the history)", x_msgs.status_code == 404)
        check("I8b cross-owner RUN is 404", x_run.status_code == 404)
        check("I8c cross-owner CREATE-SESSION is 404", x_sess.status_code == 404)
        check("I8d cross-owner 404 == missing 404 (existence does not leak over the enumerable id)",
              x_msgs.json() == missing.json())
        a_msgs_after = c.get("/agents/1/sessions/1/messages", headers=H)
        check("I8e alice's history is UNTOUCHED — still reads, identical to the pre-bob snapshot",
              a_msgs_after.status_code == 200 and a_msgs_after.json() == a_msgs_before)
        check("I8f bob never created a session under alice's agent (his attempt 404'd, not a stored session)",
              c.get("/agents/1/sessions/2/messages", headers=H).status_code == 404)
        # the owner-stamp is the TOKEN's: a smuggled body owner cannot win, and owner is never in the response
        smug = c.post("/agents/", json={"name": "spoof", "system_prompt": "s", "owner": "bob_owner"}, headers=H)
        check("I8g create response never carries the owner (internal, like api_keys' secret_hash)",
              "owner" not in smug.json())
        srec = store.get("agent_agents", str(smug.json()["id"]))
        check("I8h smuggled body owner ignored (the record's owner is the token's subject)",
              srec.get("owner") == "alice")
        check("I8i bob cannot reach the smuggled-owner agent (it is alice's)",
              c.post(f"/agents/{smug.json()['id']}/sessions", headers=Hb(tb)).status_code == 404)

        # I11 — a LONE SURROGATE in the run input is CONTAINED (never an uncontained 5xx). The JSON escape \ud800
        # decodes to a lone surrogate server-side; without sanitization the RESPONSE UTF-8 encode raises AFTER the
        # handler returns (the lone-surrogate crash class). The central well_formed.make_well_formed -> U+FFFD keeps
        # /run AND GET /messages serializable (200), and no lone surrogate is ever stored. (Go is identity — its
        # strings are valid UTF-8; node uses toWellFormed; the python path is proven here.)
        rs = c.post("/agents/1/sessions/1/run", content=b'{"input":"lone \\ud800 surrogate"}',
                    headers={**H, "Content-Type": "application/json"})
        check("I11a lone-surrogate run is CONTAINED (200, not an uncontained 5xx)", rs.status_code == 200, str(rs.status_code))
        gm = c.get("/agents/1/sessions/1/messages", headers=H)
        check("I11b GET messages stays serializable after a lone-surrogate input (200)", gm.status_code == 200, str(gm.status_code))
        contents = "".join(m["content"] for m in gm.json())
        check("I11c the lone surrogate was replaced by U+FFFD (none stored, the replacement present)",
              "\ud800" not in contents and "�" in contents)

        # I10 — a giant message is MIDDLE-truncated to AGENT_MAX_MSG_CHARS code points, MULTI-BYTE-safe. A 5000-codepoint
        # CJK input (default cap 4000) must store <= 4000 code points, keep head+marker+tail, and NOT corrupt a
        # multibyte char (a byte-slice bug in go/node would split a 3-byte CJK char or over-count by bytes).
        big = "好" * 5000
        c.post("/agents/1/sessions/1/run", json={"input": big}, headers=H)
        last_user = [m for m in c.get("/agents/1/sessions/1/messages", headers=H).json()
                     if m["role"] == "user"][-1]["content"]
        check("I10a a giant message is truncated to <= AGENT_MAX_MSG_CHARS code points",
              len(last_user) <= 4000, str(len(last_user)))
        check("I10b middle-truncated — the marker is present (head + marker + tail)", "…[truncated]…" in last_user)
        check("I10c multibyte intact (only CJK + marker chars, no corruption / replacement)",
              set(last_user) <= set("好") | set("…[truncated]…"))

        # I13 — FAIL-LOUD PROVIDER SEAM (the honesty contract): a real provider name WITHOUT its key env NEVER
        # silently serves fake output. AI_PROVIDER + the key envs are read at CALL time in all three languages,
        # so the flips below are per-request: a keyless real name -> 501 problem+json NAMING the missing key
        # env; an unknown string -> the same loud 501 with the 'unknown provider' detail; the refusal leaves NO
        # trace in the session history (refused before the loop appends the user turn) and every provider-free
        # route keeps working; restoring the default serves the offline fake again. REACHING: with the factory
        # guard removed, every refusal below comes back 200 '[fake] …' — I13a/b/e/f go RED.
        hist_before = c.get("/agents/1/sessions/1/messages", headers=H).json()
        _prev13 = {k: os.environ.get(k) for k in ("AI_PROVIDER", "ANTHROPIC_API_KEY", "OPENAI_API_KEY")}
        try:
            os.environ["AI_PROVIDER"] = "anthropic"
            os.environ.pop("ANTHROPIC_API_KEY", None)   # the keyless state under proof (the machine may set it)
            rl = c.post("/agents/1/sessions/1/run", json={"input": "hello"}, headers=H)
            check("I13a real provider without its key -> 501 (never a silent fake 200)",
                  rl.status_code == 501, f"{rl.status_code} {rl.text[:160]}")
            check("I13b the 501 detail NAMES the missing key env (byte-identical ×3)",
                  rl.json().get("detail") == "provider 'anthropic' needs ANTHROPIC_API_KEY — see INTEROP.md",
                  rl.text[:160])
            check("I13c the refusal is the ONE problem+json envelope",
                  "problem+json" in (rl.headers.get("content-type") or ""), rl.headers.get("content-type"))
            check("I13d no fake output leaks through the refusal", "[fake]" not in rl.text)
            check("I13e provider-free routes keep working under the keyless env (failure is LOCAL to the run)",
                  c.get("/agents/1/sessions/1/messages", headers=H).status_code == 200)
            os.environ["AI_PROVIDER"] = "openai"
            os.environ.pop("OPENAI_API_KEY", None)
            ro = c.post("/agents/1/sessions/1/run", json={"input": "hello"}, headers=H)
            check("I13f the other provider refuses identically keyless, naming ITS key env",
                  ro.status_code == 501
                  and ro.json().get("detail") == "provider 'openai' needs OPENAI_API_KEY — see INTEROP.md",
                  ro.text[:160])
            os.environ["AI_PROVIDER"] = "banana"
            ru = c.post("/agents/1/sessions/1/run", json={"input": "hello"}, headers=H)
            check("I13g an unknown provider string takes the SAME loud path with its own detail",
                  ru.status_code == 501
                  and ru.json().get("detail") == "unknown provider 'banana' — see INTEROP.md", ru.text[:160])
            check("I13h a refused run leaves NO trace in the session history",
                  c.get("/agents/1/sessions/1/messages", headers=H).json() == hist_before)
            os.environ["AI_PROVIDER"] = "fake"
            rf = c.post("/agents/1/sessions/1/run", json={"input": "hello"}, headers=H)
            check("I13i the explicit offline default still runs the whole stack (name unchanged)",
                  rf.status_code == 200 and rf.json().get("output") == "[fake] hello", rf.text[:160])
        finally:
            for k, v in _prev13.items():   # restore: the later fresh-process probes inherit os.environ
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        # I14 — THE SHIPPED ADAPTERS REACH (offline: loopback stubs speaking each provider's wire shape).
        # Proves the adapter sends the documented request out of the REAL run route, the stub's text comes
        # back as the run output, and upstream failure maps to sanitized 502 / 504. With the refusal-only
        # build every call below would 501: delete the adapters and this goes RED.
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
                        code, payload = 200, {"choices": [{"message": {"role": "assistant",
                                                                       "content": "stub says hi"}}],
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
        err_s, _ce = stub_server("err")
        hang_s, _ch = stub_server("hang")
        ENV14 = ("AI_PROVIDER", "AI_MODEL", "AI_TIMEOUT_SECONDS", "AI_MAX_TOKENS",
                 "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL")
        saved14 = {k: os.environ.get(k) for k in ENV14}
        try:
            for k in ENV14:
                os.environ.pop(k, None)   # a clean slate — the machine env must not steer the wired probes
            os.environ.update({"AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": DUMMY,
                               "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{ok_a.server_address[1]}"})
            r = c.post("/agents/1/sessions/1/run", json={"input": "hello stub"}, headers=H)
            check("I14a wired anthropic: the run returns the STUB's answer in one iteration (a real round-trip)",
                  r.status_code == 200 and r.json().get("output") == "stub says hi"
                  and r.json().get("iterations") == 1 and r.json().get("terminated") is False, r.text[:200])
            sent = calls_a[-1] if calls_a else {}
            hdr, b = sent.get("headers", {}), sent.get("body", {})
            roles = [t.get("role") for t in b.get("messages", [])]
            check("I14b the adapter spoke the Messages wire shape (path + key header + version pin)",
                  sent.get("path") == "/v1/messages" and hdr.get("x-api-key") == DUMMY
                  and bool(re.fullmatch(r"20\d\d-\d\d-\d\d", hdr.get("anthropic-version", ""))),
                  str(sent.get("path")))
            check("I14c the body carries the default model, a bounded max_tokens, the agent's system prompt, "
                  "and merged user/assistant-only alternating turns ending in the run input",
                  b.get("model") == "claude-sonnet-4-6" and isinstance(b.get("max_tokens"), int)
                  and b.get("max_tokens") >= 1 and b.get("system") == "sp"
                  and set(roles) <= {"user", "assistant"}
                  and all(r1 != r2 for r1, r2 in zip(roles, roles[1:]))
                  and (b.get("messages") or [{}])[-1].get("role") == "user"
                  and (b.get("messages") or [{}])[-1].get("content", "").endswith("hello stub"),
                  str(b)[:200])
            os.environ["AI_MODEL"] = "my-tuned-model"
            c.post("/agents/1/sessions/1/run", json={"input": "hello again"}, headers=H)
            check("I14d AI_MODEL overrides the model per call (env read at CALL time)",
                  bool(calls_a) and calls_a[-1]["body"].get("model") == "my-tuned-model")
            os.environ.pop("AI_MODEL", None)

            os.environ.update({"AI_PROVIDER": "openai", "OPENAI_API_KEY": DUMMY,
                               "OPENAI_BASE_URL": f"http://127.0.0.1:{ok_o.server_address[1]}"})
            r = c.post("/agents/1/sessions/1/run", json={"input": "hi oai"}, headers=H)
            sent = calls_o[-1] if calls_o else {}
            check("I14e wired openai: chat-completions wire shape + Bearer auth + system-first turns + the "
                  "stub's answer as the run output",
                  r.status_code == 200 and r.json().get("output") == "stub says hi"
                  and sent.get("path") == "/v1/chat/completions"
                  and sent.get("headers", {}).get("authorization") == f"Bearer {DUMMY}"
                  and sent.get("body", {}).get("model") == "gpt-4o"
                  and (sent.get("body", {}).get("messages") or [{}])[0].get("role") == "system", r.text[:200])

            os.environ.update({"AI_PROVIDER": "anthropic",
                               "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{err_s.server_address[1]}"})
            r = c.post("/agents/1/sessions/1/run", json={"input": "boom"}, headers=H)
            check("I14f upstream 500 -> a LOUD 502 problem+json naming the upstream status",
                  r.status_code == 502
                  and r.json().get("detail", "").startswith("provider 'anthropic' upstream error (HTTP 500)"),
                  r.text[:200])
            check("I14g the 502 detail is SANITIZED — the key value never echoes", DUMMY not in r.text)
            msgs_after_fail = c.get("/agents/1/sessions/1/messages", headers=H).json()
            check("I14h the failed run kept the received user turn but appended NO fabricated assistant turn",
                  bool(msgs_after_fail) and msgs_after_fail[-1].get("role") == "user"
                  and msgs_after_fail[-1].get("content") == "boom", str(msgs_after_fail[-1:])[:120])
            os.environ.update({"AI_TIMEOUT_SECONDS": "1",
                               "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{hang_s.server_address[1]}"})
            r = c.post("/agents/1/sessions/1/run", json={"input": "slow"}, headers=H)
            check("I14i a hung upstream -> 504 under the AI_TIMEOUT_SECONDS budget",
                  r.status_code == 504
                  and r.json().get("detail") == "provider 'anthropic' upstream timeout or network failure",
                  r.text[:160])
        finally:
            for k, v in saved14.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            for srv in (ok_a, ok_o, err_s):
                srv.shutdown()   # the hang stub's worker is a daemon thread; leave it to die with the process

        # I15 — THE USAGE-METERING WIRE (B5). A run meters its provider-call usage into the llm_usage ledger, but
        # ONLY the real/armed path (the fake is free + unmetered by default, so the default bar stays INERT). Proven
        # against WHATEVER app this runs in: with the meter domain present (the full bar) an armed run RECORDS one
        # event for the run's owner with the fake's counts, is exactly-once on replay, and a failing sink does NOT
        # break the run; with the meter ABSENT (the --domain agent build) an armed run STILL returns 200 (the no-sink
        # wire is a no-op — the availability property). Default (unarmed fake) records NOTHING (the inert proof).
        meter_present = c.get("/llm_usage/summary", headers=H).status_code == 200

        def _msum():   # alice's metered input_tokens, or None when the meter domain is absent from this build
            r = c.get("/llm_usage/summary", headers=H)
            return r.json().get("input_tokens", 0) if r.status_code == 200 else None

        _prev15 = {k: os.environ.get(k) for k in ("AI_PROVIDER", "AI_USAGE_METER_FAKE")}
        try:
            os.environ.pop("AI_PROVIDER", None)   # the offline fake provider
            ar = c.post("/agents/", json={"name": "meter", "system_prompt": "s"}, headers=H).json()
            aid = ar["id"]
            sid = c.post(f"/agents/{aid}/sessions", headers=H).json()["id"]
            runp = f"/agents/{aid}/sessions/{sid}/run"

            # I15a — DEFAULT INERT: an UNARMED fake run succeeds AND records nothing (the bar stays uncorrupted)
            os.environ.pop("AI_USAGE_METER_FAKE", None)
            before_inert = _msum()
            r_inert = c.post(runp, json={"input": "hello"}, headers=H)
            check("I15a an unarmed fake run still succeeds (200)", r_inert.status_code == 200, str(r_inert.status_code))
            if meter_present:
                check("I15b DEFAULT INERT — an unarmed fake run records NO usage event",
                      _msum() == before_inert, f"{before_inert} -> {_msum()}")

            # I15c — ARMED: the wire FIRES, recording exactly the fake's counts for the run's owner (alice)
            os.environ["AI_USAGE_METER_FAKE"] = "1"
            before_armed = _msum()
            r_armed = c.post(runp, json={"input": "hello"}, headers=H)
            check("I15c an armed run STILL returns 200 (a run never depends on the meter)",
                  r_armed.status_code == 200, str(r_armed.status_code))
            if meter_present:
                check("I15d ARMED run RECORDS the usage (alice's meter summary rose by the fake's input_tokens)",
                      _msum() == before_armed + 3, f"{before_armed} -> {_msum()}")

                import app_pkg.core.usage as _umod   # the core usage seam (reach into it to prove the seam's contract)
                # I15e — EXACTLY-ONCE: replaying the SAME identifier through the seam records ONE event, not two
                fixed = {"identifier": "agent:invariant:once", "provider": "fake", "model": "fake",
                         "input_tokens": 7, "output_tokens": 0, "cache_read_input_tokens": 0,
                         "cache_creation_input_tokens": 0, "reasoning_tokens": 0}
                b_once = _msum()
                s1 = _umod.usage_record("alice", fixed, 1000)
                s2 = _umod.usage_record("alice", fixed, 1000)   # a byte-identical replay
                check("I15e exactly-once — a replayed identifier records ONE event (the seam dedups)",
                      s1 == "recorded" and s2 == "recorded" and _msum() == b_once + 7, f"{s1}/{s2} {b_once}->{_msum()}")

                # I15f — FAIL-OPEN at the seam: an UNPRICED (provider,model) returns "failed:…" and records NOTHING
                b_bad = _msum()
                bad = {**fixed, "identifier": "agent:invariant:unpriced", "provider": "nonesuch", "model": "nonesuch"}
                s_bad = _umod.usage_record("alice", bad, 1000)
                check("I15f fail-open — an unpriced call through the seam is 'failed:…' and records NO event",
                      s_bad.startswith("failed") and _msum() == b_bad, f"{s_bad} {b_bad}->{_msum()}")

                # I15g — FAILURE PATH: a THROWING sink does NOT break the run (still 200, the error is contained)
                _saved_sink = _umod._sink
                try:
                    _umod._sink = _boom
                    r_fail = c.post(runp, json={"input": "hello"}, headers=H)
                    check("I15g a FAILING meter sink does NOT break the run (still 200; the error is contained)",
                          r_fail.status_code == 200, str(r_fail.status_code))
                finally:
                    _umod._sink = _saved_sink
        finally:
            for k, v in _prev15.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    # I2 — the budget knob binds: a FRESH process with AGENT_MAX_ITERATIONS=2 stops the runaway at 2
    probe = (
        "import json, sys; sys.path.insert(0, '.')\n"
        "from starlette.testclient import TestClient\n"
        "from app_pkg.app import app\n"
        "H = {'Authorization': 'Bearer test:alice'}  # the authed caller (APP_TEST_SESSIONS=1 in env below)\n"
        "with TestClient(app, raise_server_exceptions=False, headers=H) as c:\n"
        "    c.post('/agents/', json={'name': 'b', 'system_prompt': 's'})\n"
        "    c.post('/agents/1/sessions')\n"
        "    r = c.post('/agents/1/sessions/1/run', json={'input': 'use forever x'}).json()\n"
        "    print(json.dumps(r))\n"
    )
    env = {**os.environ, "AGENT_MAX_ITERATIONS": "2",
           "DATABASE_PATH": os.path.join(tempfile.mkdtemp(prefix="agent_inv_"), "d.db")}
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, env=env, timeout=120)
    line = [ln for ln in (out.stdout or "").splitlines() if ln.strip().startswith("{")]
    r2 = json.loads(line[-1]) if line else {}
    check("I2 AGENT_MAX_ITERATIONS binds the loop", r2.get("terminated") is True and r2.get("iterations") == 2,
          f"rc={out.returncode} {r2 or out.stderr[-200:]}")

    # I9 — the per-session history is RING-BUFFER capped (drop-oldest), AND the cap (>= budget) never breaks the loop.
    # A FRESH process with AGENT_HISTORY_MAX=8: (a) the runaway STILL terminates at the budget (the cap doesn't evict
    # the run's own user turn — the R3 coupling); (b) driving many runs leaves the stored history bounded at exactly 8,
    # never growing unbounded (the O(n^2)/OOM/cost soft-DoS is closed).
    probe9 = (
        "import json, sys; sys.path.insert(0, '.')\n"
        "from starlette.testclient import TestClient\n"
        "from app_pkg.app import app\n"
        "H = {'Authorization': 'Bearer test:alice'}\n"
        "with TestClient(app, raise_server_exceptions=False, headers=H) as c:\n"
        "    c.post('/agents/', json={'name': 'b', 'system_prompt': 's'})\n"
        "    c.post('/agents/1/sessions')\n"
        "    rr = c.post('/agents/1/sessions/1/run', json={'input': 'use forever x'}).json()\n"  # 1 user + 6 tool + 1 assistant = 8 == cap
        "    for _ in range(10):\n"
        "        c.post('/agents/1/sessions/1/run', json={'input': 'hello'})\n"  # 2 each -> way over the cap
        "    n = len(c.get('/agents/1/sessions/1/messages').json())\n"
        "    print(json.dumps({'runaway': rr, 'stored': n}))\n"
    )
    env9 = {**os.environ, "AGENT_HISTORY_MAX": "8",
            "DATABASE_PATH": os.path.join(tempfile.mkdtemp(prefix="agent_inv9_"), "d.db")}
    out9 = subprocess.run([sys.executable, "-c", probe9], capture_output=True, text=True, env=env9, timeout=120)
    line9 = [ln for ln in (out9.stdout or "").splitlines() if ln.strip().startswith("{")]
    r9 = json.loads(line9[-1]) if line9 else {}
    check("I9a the cap (>= budget) does NOT break the runaway — still terminates at the budget",
          r9.get("runaway", {}).get("terminated") is True and r9.get("runaway", {}).get("iterations") == 6,
          f"rc={out9.returncode} {r9 or out9.stderr[-200:]}")
    check("I9b the stored history is RING-BUFFER capped at AGENT_HISTORY_MAX (bounded, not unbounded)",
          r9.get("stored") == 8, f"stored={r9.get('stored')}")

    # I12 — a MALFORMED integer env knob falls back to the DEFAULT without crashing — the env parse is UNIFORM ×3
    # (python int(strip) / go Atoi(TrimSpace) / node /^[+-]?\d+$/): never a boot crash (the python int() crash), never a
    # lenient prefix (node parseInt('3.9')=3 / go-vs-node drift). 'AGENT_MAX_ITERATIONS=3.9' -> default 6, app boots.
    probe12 = (
        "import json, sys; sys.path.insert(0, '.')\n"
        "from starlette.testclient import TestClient\n"
        "from app_pkg.app import app\n"   # <- this import would CRASH under the old python int(env) on a malformed value
        "H = {'Authorization': 'Bearer test:alice'}\n"
        "with TestClient(app, raise_server_exceptions=False, headers=H) as c:\n"
        "    c.post('/agents/', json={'name': 'b', 'system_prompt': 's'})\n"
        "    c.post('/agents/1/sessions')\n"
        "    r = c.post('/agents/1/sessions/1/run', json={'input': 'use forever x'}).json()\n"
        "    print(json.dumps(r))\n"
    )
    env12 = {**os.environ, "AGENT_MAX_ITERATIONS": "3.9",
             "DATABASE_PATH": os.path.join(tempfile.mkdtemp(prefix="agent_inv12_"), "d.db")}
    out12 = subprocess.run([sys.executable, "-c", probe12], capture_output=True, text=True, env=env12, timeout=120)
    line12 = [ln for ln in (out12.stdout or "").splitlines() if ln.strip().startswith("{")]
    r12 = json.loads(line12[-1]) if line12 else {}
    check("I12 a malformed int env knob -> the DEFAULT, app BOOTS (no crash, no lenient prefix)",
          out12.returncode == 0 and r12.get("terminated") is True and r12.get("iterations") == 6,
          f"rc={out12.returncode} {r12 or out12.stderr[-200:]}")

    # I12b — an OUT-OF-SAFE-RANGE env knob ALSO falls to the default ×3. 9223372036854775808 (int64max+1) is the
    # value that DIVERGED before the clamp: Go's Atoi rejects it (>int64) -> default 6, but python int() (unbounded)
    # and node parseInt (float-rounds past 2**53) would accept a ~quintillion-iteration "bounded" loop — breaking the
    # headline terminate guarantee in 2 of 3 langs from ONE .env. The shared 2**53-1 clamp makes all three default.
    env12b = {**os.environ, "AGENT_MAX_ITERATIONS": "9223372036854775808",
              "DATABASE_PATH": os.path.join(tempfile.mkdtemp(prefix="agent_inv12b_"), "d.db")}
    out12b = subprocess.run([sys.executable, "-c", probe12], capture_output=True, text=True, env=env12b, timeout=120)
    line12b = [ln for ln in (out12b.stdout or "").splitlines() if ln.strip().startswith("{")]
    r12b = json.loads(line12b[-1]) if line12b else {}
    check("I12b an out-of-safe-range int env knob -> the DEFAULT (the loop bound can't be set absurd)",
          out12b.returncode == 0 and r12b.get("terminated") is True and r12b.get("iterations") == 6,
          f"rc={out12b.returncode} {r12b or out12b.stderr[-200:]}")

    # I3c — calc DIVISION/MODULO by zero is a graceful 'error' observation, NEVER an uncontained crash and NEVER a
    # divergent observation. 1/0 was +Inf (go) / Infinity (node) / 'error' (python) before the fix; 1%0 PANICS in Go
    # (int64 % 0). The contract pins ONE observation ×3 — the python arm is proven here; go/node by the ×3 build + tests.
    for expr in ("1/0", "1%0"):
        rz = c.post("/agents/1/sessions/1/run", json={"input": f"use calc {expr}"}, headers=H).json()
        check(f"I3c calc {expr} -> graceful 'error' (no crash, no Inf/NaN observation)",
              "error: invalid expression" in rz.get("output", ""), rz.get("output"))

    print(f"AGENT INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
