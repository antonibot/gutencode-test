#!/usr/bin/env python3
"""verify.py — the offline verifier shipped with this codebase. No network, no external services.

  python verify.py            two reports: BASELINE (is the shipped baseline intact?) + CODE (do the apps pass?)
  python verify.py --strict   modified baseline files FAIL instead of warning

What it checks:
  baseline/manifest    every file in .gutencode/manifest.json exists; hashes compared (drift -> WARN, or FAIL
                       under --strict; acknowledge intentional edits in .gutencode/accepted.json). New files you
                       added are listed as CUSTOM (info). PROTECTED files (this verifier, the contract) FAIL on
                       any modification — the verification layer itself can never be weakened in silence.
                       Deleted a language tree on purpose? Acknowledge it in accepted.json — {"files": [...],
                       "removed_languages": ["go","node"]} — and every check for those languages becomes a loud
                       SKIP (see SINGLE_LANGUAGE.md). An unacknowledged missing tree stays a FAIL.
  code/tests-*         each language's own test suite (python -m pytest · go test ./... · node --test).
                       A missing toolchain is a loud SKIP with an install hint, never silence.
  code/invariants      the correctness proofs in tests/invariants/ (credited by exit code).
  code/routes-*        the live route tables still cover everything .gutencode/contract.json declares.
  code/parity          routes present in some-but-not-all languages (the three apps are a contract) -> WARN.
  code/error-shape     404 unknown · 405 wrong-method · 413 oversize · 422 bad-body — the SAME problem+json envelope in every
                       language (probed against the live apps).
  code/durability      per store-backed domain x language: seed state -> RESTART the process -> state must
                       survive (the contract's persistence cases, run against a temp database).
  code/boundaries      domain modules may use core/ and parts/ but never import a SIBLING domain (architecture).
  code/primitives      security primitives (HMAC constructor, db open, password hashing) appear exactly once
                       per language — duplicated crypto is how subtle bugs are born.

Exit code: 0 = green (warnings allowed unless --strict) · 1 = something red. Every section prints; nothing is
skipped silently."""
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

# print UTF-8 regardless of the console codepage, so the report's separators (·, —) don't mojibake to '�' on a
# legacy Windows terminal (cp1252). Best-effort — a stream without reconfigure() is left as-is.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.join(HERE, ".gutencode")
STRICT = "--strict" in sys.argv
PROTECTED = {"verify.py", "check-baseline.js", "check-baseline.go"}   # the verification layer (+ the contract,
# pinned via manifest.contract_sha256) — modifying any of these is never acknowledgeable

GREEN, RED, YELLOW, DIM = "[ OK ]", "[FAIL]", "[WARN]", "[SKIP]"
failures, warnings = [], []


def say(tag, check, detail=""):
    print(f"  {tag} {check:<22} {detail}")
    if tag == RED:
        failures.append(check)
    if tag == YELLOW:
        warnings.append(check)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, cwd, env=None, timeout=600):
    e = {**os.environ, **(env or {})}
    if not os.path.isdir(cwd):            # a deleted tree must yield a reported failure, never a traceback
        return -127, f"{cmd[0]}: cannot run — directory missing: {os.path.relpath(cwd, HERE)}"
    try:
        r = subprocess.run(cmd, cwd=cwd, env=e, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return -127, f"{cmd[0]}: not found"
    except OSError as exc:                # any other launch failure: report it, never crash the verifier
        return -127, f"{cmd[0]}: could not start — {exc}"


def tail(s, n=400):
    s = (s or "").strip()
    return ("…" + s[-n:]) if len(s) > n else s


def fail_tail(s, keep=15):
    """The failure-relevant tail of a suite's output: the LAST lines that name the actual error (FAILED /
    AssertionError / panic / not ok / assertion detail) — so the printed reason is the real failure, never an
    unrelated warning that happens to sit at the end of the stream. Falls back to the plain tail."""
    lines = (s or "").strip().splitlines()
    pat = re.compile(r"FAILED|FAIL\b|AssertionError|Traceback|panic:|not ok \d|Error\b|\d+ failed|^\s*E\s|\.go:\d+:")
    hits = [ln.strip()[:300] for ln in lines if ln.strip() and pat.findall(ln)]
    if not hits:
        return tail(s)
    joined = "\n".join(hits[-keep:])
    return joined if len(joined) <= 1500 else "…" + joined[-1500:]


def norm(path):
    return re.sub(r"\{[^}]+\}", "{}", path.split("?")[0])


def current_deps(lang):
    """The dependency surface actually shipped now (compared to the contract allowlist by code/deps)."""
    if lang == "python":
        req = os.path.join(HERE, "python", "requirements.txt")
        return sorted(l.split("#")[0].strip() for l in open(req, encoding="utf-8")
                      if l.strip() and not l.lstrip().startswith("#")) if os.path.exists(req) else []
    if lang == "go":
        gomod = os.path.join(HERE, "go", "go.mod")
        return sorted(set(re.findall(r"^\s*([\w.\-]+\.[\w.\-]+/[\w.\-/]+)\s+v",
                                     open(gomod, encoding="utf-8").read(), re.M))) if os.path.exists(gomod) else []
    if lang == "node":
        pkg = os.path.join(HERE, "node", "package.json")
        return sorted(json.load(open(pkg, encoding="utf-8")).get("dependencies", {})) if os.path.exists(pkg) else []
    return []


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_listening(port, proc, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False, f"process exited rc={proc.returncode} before listening"
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True, "listening"
        except OSError:
            time.sleep(0.1)
    return False, f"no listener on :{port} within {timeout}s"


def stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)
    errf = getattr(proc, "_verify_errfile", None)   # the boot() stderr-capture file, if any — close + remove it
    if errf is not None:
        try:
            errf.close()
            os.unlink(errf.name)
        except OSError:
            pass


def pg_reset(url):
    # Isolate each language's Postgres durability run: wipe the schema so every language SEEDS A FRESH DB — the direct
    # analogue of the per-language SQLite temp file the SQLite durability check uses. Without this, all three languages
    # share one Postgres DB and the second language inherits the first's rows (a seed that expects id=1 sees id=2).
    # Uses psycopg (the same optional driver the python arm already needs); returns False if it isn't importable, so the
    # caller degrades to a single language rather than silently colliding. Safe on a TEST DSN (the check's own contract).
    try:
        import psycopg
    except Exception:
        return False
    try:
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
            conn.execute("CREATE SCHEMA public")
        return True
    except Exception:
        return False


def _urlopen(req, attempts=6, backoff=0.25):
    """urlopen, RETRYING only transient connection-level failures. A freshly booted/restarted server can accept the
    TCP port (wait_listening is satisfied) a beat before it serves HTTP, so under load the first request is forcibly
    reset (Windows WinError 10054 / ConnectionResetError / RemoteDisconnected / ConnectionRefused). A reset means the
    request was dropped before it ran, so re-sending is safe (no double-apply). An HTTPError is a REAL response
    (4xx/5xx) — re-raised at once, never retried. Raises the last connection error only if every attempt is reset."""
    import urllib.error
    import urllib.request
    for i in range(attempts):
        try:
            return urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError:
            raise                       # a real response — the caller reads e.code/e.read(); not a transient failure
        except Exception:               # URLError(OSError) / ConnectionReset / RemoteDisconnected — the boot/restart race
            if i == attempts - 1:
                raise
            time.sleep(backoff * (i + 1))


def http_case(base, case):
    """Run one contract case {method,path,json?,headers?,status,expect?} against a live server -> (ok, detail)."""
    import urllib.error
    import urllib.request
    body = json.dumps(case["json"], separators=(",", ":")).encode() if "json" in case else None
    headers = {"Content-Type": "application/json"} if body else {}
    headers.update(case.get("headers") or {})
    req = urllib.request.Request(base + case["path"], data=body, method=case["method"], headers=headers)
    try:
        resp = _urlopen(req)
        status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except Exception as e:
        return False, f"{case['method']} {case['path']}: request failed — {e}"
    where = f"{case['method']} {case['path']}"
    if status != case["status"]:
        return False, f"{where}: status {status}, want {case['status']}"
    if case.get("expect") is not None:
        try:
            got = json.loads(raw)
        except json.JSONDecodeError:
            return False, f"{where}: body is not JSON"
        for k, v in case["expect"].items():
            if k not in got or got[k] != v:
                return False, f"{where}: body[{k!r}] = {got.get(k)!r}, want {v!r}"
    return True, f"{where}: ok"


def http_shape(base, method, path, body=None):
    """(status, media-type, sorted body keys) for an error probe."""
    import urllib.error
    import urllib.request
    req = urllib.request.Request(base + path, data=body, method=method,
                                 headers={"Content-Type": "application/json"} if body else {})
    try:
        r = _urlopen(req)
        status, ctype, raw = r.status, r.headers.get("content-type", ""), r.read()
    except urllib.error.HTTPError as e:
        status, ctype, raw = e.code, e.headers.get("content-type", ""), e.read()
    except Exception as e:
        return ["<probe failed: " + str(e) + ">"]
    try:
        keys = sorted(json.loads(raw))
    except json.JSONDecodeError:
        keys = ["<NOT JSON: " + raw[:50].decode(errors="replace") + ">"]
    return [status, ctype.split(";")[0], keys]


# in-process python arms (TestClient — works without a port; needs the python deps)
PY_CASES = (
    "import json, os, sys\n"
    "os.environ['LOG_LEVEL'] = 'silent'\n"   # keep app access-logs off stdout/stderr so they can't collide with parsing
    "sys.path.insert(0, '.')\n"
    "from starlette.testclient import TestClient\n"
    "from app_pkg.app import app\n"
    "cases = json.loads(sys.argv[1])\n"
    "with TestClient(app, raise_server_exceptions=False) as c:\n"
    "    for case in cases:\n"
    "        body = json.dumps(case['json'], separators=(',', ':')) if 'json' in case else None\n"
    "        headers = {'Content-Type': 'application/json'} if body else {}\n"
    "        headers.update(case.get('headers') or {})\n"
    "        r = c.request(case['method'], case['path'], content=body, headers=headers)\n"
    "        ok = r.status_code == case['status']\n"
    "        got = None\n"
    "        if ok and case.get('expect') is not None:\n"
    "            got = r.json()\n"
    "            ok = all(k in got and got[k] == v for k, v in case['expect'].items())\n"
    "        if not ok:\n"
    "            print(f\"CASE FAIL: {case['method']} {case['path']} -> {r.status_code} {r.text[:120]}\")\n"
    "            sys.exit(1)\n"
    "print('CASES OK')\n"
)
PY_SHAPE = (
    "import json, os, sys\n"
    "os.environ['LOG_LEVEL'] = 'silent'\n"   # keep app access-logs off stdout/stderr so they can't collide with parsing
    "sys.path.insert(0, '.')\n"
    "from starlette.testclient import TestClient\n"
    "from app_pkg.app import app\n"
    "post_path = sys.argv[1].split('?')[0]\n"
    "wrong_method = sys.argv[2] if len(sys.argv) > 2 else 'GET'\n"
    "out = {}\n"
    "def shape(r):\n"
    "    try: keys = sorted(r.json())\n"
    "    except Exception: keys = ['<NOT JSON>']\n"
    "    return [r.status_code, (r.headers.get('content-type') or '').split(';')[0], keys]\n"
    "with TestClient(app, raise_server_exceptions=False) as c:\n"
    "    out['404'] = shape(c.get('/__verify_nope__'))\n"
    "    if post_path:\n"
    "        big = b'{\"x\":\"' + b'a'*(1<<21) + b'\"}'\n"   # VALID JSON, >1 MiB so go reaches the byte cap (else 422)
    "        out['405'] = shape(c.request(wrong_method, post_path))\n"
    "        out['413'] = shape(c.request('POST', post_path, content=big, headers={'Content-Type': 'application/json'}))\n"
    "        out['422'] = shape(c.post(post_path, content=b'{not json', headers={'Content-Type': 'application/json'}))\n"
    "    else:\n"
    "        out['405'] = out['413'] = out['422'] = out['404']\n"
    "print(json.dumps(out))\n"
)


def main():
    if not os.path.isdir(PACK):
        print(f"{RED} .gutencode/ missing — this tree is not a verifiable export")
        return 1
    # An ambient DATABASE_URL (a CI job's env, or a dev's shell pointing at Supabase) must NOT hijack the functional
    # suites. Every suite/boot below inherits os.environ, but they are SQLite-by-design: the invariant proofs and the
    # durability seed each open an ISOLATED per-test SQLite file and would COLLIDE on one shared Postgres, and a go
    # binary built without `-tags postgres` PANICS the moment it sees DATABASE_URL. So capture it once and REMOVE it
    # from the environment here; only the dedicated code/durability-pg probe (which builds its own pgenv) uses it.
    pg_url_ambient = os.environ.pop("DATABASE_URL", "")
    manifest = json.load(open(os.path.join(PACK, "manifest.json"), encoding="utf-8"))
    contract_path = os.path.join(PACK, "contract.json")
    contract = json.load(open(contract_path, encoding="utf-8"))
    accepted, removed = set(), []
    acc_path = os.path.join(PACK, "accepted.json")
    if os.path.exists(acc_path):
        acc = json.load(open(acc_path, encoding="utf-8-sig"))   # utf-8-sig: tolerate an editor-added BOM on this hand-edited file
        # accepted.json is a plain LIST of acknowledged file paths, or an OBJECT for single-language use:
        #   {"files": ["path", ...], "removed_languages": ["go", "node"]}
        # A language in removed_languages is acknowledged as deleted: its baseline files are no longer expected
        # and every check for it reports a loud SKIP (see SINGLE_LANGUAGE.md). PROTECTED files and the remaining
        # languages' checks are unaffected.
        if isinstance(acc, dict):
            accepted = set(acc.get("files") or [])
            removed = [l for l in (acc.get("removed_languages") or []) if l in contract["languages"]]
        else:
            accepted = set(acc)
    langs = [l for l in contract["languages"] if l not in removed]
    # customer-declared route extensions — the route-check counterpart of accepted.json. Each entry is
    # {"method","path"} with an optional "lang" (an endpoint you added in ONE runtime only); no "lang" ⇒ all.
    # A route in NEITHER the contract NOR this list is still reported UNDECLARED, so a back-door endpoint can
    # never hide. An absent file ⇒ none (inert), exactly like an empty accepted.json.
    extensions = []
    ext_path = os.path.join(PACK, "extensions.json")
    if os.path.exists(ext_path):
        extensions = json.load(open(ext_path, encoding="utf-8-sig"))   # utf-8-sig: tolerate an editor-added BOM on this hand-edited file
    ext_global, ext_lang = set(), {}
    for e in extensions:
        k = (e["method"], norm(e["path"]))
        (ext_lang.setdefault(e["lang"], set()) if e.get("lang") else ext_global).add(k)
    ext_any = set(ext_global)
    for s in ext_lang.values():
        ext_any |= s

    # ── REPORT 1 · BASELINE ──────────────────────────────────────────────────────────────────────────────────
    print(f"==== {contract['app']} · REPORT 1 · BASELINE (the printed baseline vs this tree) ====")
    missing, drifted, acked, protected_hits = [], [], [], []
    removed_files = {l: 0 for l in removed}
    for rel, want in sorted(manifest["files"].items()):
        top = rel.split("/", 1)[0]
        if top in removed_files:              # a tree the owner removed and acknowledged — not "missing"
            removed_files[top] += 1
            continue
        p = os.path.join(HERE, rel)
        if not os.path.exists(p):
            (protected_hits if rel in PROTECTED else missing).append(rel)
        elif sha256(p) != want:
            if rel in PROTECTED:
                protected_hits.append(rel)
            elif rel in accepted:
                acked.append(rel)
            else:
                drifted.append(rel)
    if manifest.get("contract_sha256") and sha256(contract_path) != manifest["contract_sha256"]:
        protected_hits.append(".gutencode/contract.json")
    listed = set(manifest["files"])
    custom = []
    skip_dirs = {".git", ".gutencode", "__pycache__", "node_modules", ".pytest_cache", ".venv", "venv"}
    for base, dirs, files in os.walk(HERE):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            rel = os.path.relpath(os.path.join(base, f), HERE).replace(os.sep, "/")
            if rel not in listed and not rel.endswith((".pyc", ".db", ".exe", ".db-journal")):
                custom.append(rel)
    if protected_hits:
        say(RED, "baseline/protected",
            f"the VERIFICATION LAYER was modified: {protected_hits} — this is never acknowledgeable; restore it "
            f"(re-download or git checkout) before trusting any result")
    if missing:
        say(RED, "baseline/complete", f"{len(missing)} baseline file(s) MISSING, e.g. {missing[:3]}"
            + ("" if removed else " — deleted a whole language tree on purpose? acknowledge it in "
                                  ".gutencode/accepted.json (\"removed_languages\", see SINGLE_LANGUAGE.md)"))
    else:
        say(GREEN, "baseline/complete", f"{len(listed) - sum(removed_files.values())} files present")
    for l in removed:
        say(GREEN, "baseline/removed", f"{l}/ removed by owner (acknowledged) — {removed_files[l]} baseline "
                                       f"file(s) not expected")
    if drifted:
        say(RED if STRICT else YELLOW, "baseline/drift",
            f"{len(drifted)} baseline file(s) modified: {drifted[:5]}"
            + (" — acknowledge intentional edits in .gutencode/accepted.json" if not STRICT else ""))
    else:
        say(GREEN, "baseline/drift", "no unacknowledged modifications")
    if acked:
        say(DIM, "baseline/accepted", f"{len(acked)} acknowledged edit(s): {acked[:5]}")
    say(DIM, "baseline/custom", f"{len(custom)} file(s) you added" + (f", e.g. {custom[:3]}" if custom else ""))

    # ── REPORT 2 · CODE ──────────────────────────────────────────────────────────────────────────────────────
    print(f"\n==== {contract['app']} · REPORT 2 · CODE (do the apps still pass their contract?) ====")
    suites = {
        "python": ([sys.executable, "-m", "pytest", "-q"], "python", "pip install -r python/requirements.txt"),
        "go": (["go", "test", "./..."], "go", "install Go: https://go.dev/dl"),
        "node": (["node", "--test"], "node", "install Node 22+: https://nodejs.org"),
    }
    deps_ok = {}
    for lang in removed:              # acknowledged single-language mode — every skip is printed, never silent
        say(DIM, f"code/tests-{lang}", f"{lang}/ removed by owner — suite, routes, error-shape and durability "
                                       f"probes for {lang} are OFF (acknowledged in accepted.json)")
    for lang in langs:
        cmd, sub, hint = suites[lang]
        d = os.path.join(HERE, sub)
        if lang != "python" and shutil.which(cmd[0]) is None:
            say(DIM, f"code/tests-{lang}", f"toolchain not installed — {hint}")
            deps_ok[lang] = False
            continue
        rc, out = run(cmd, cwd=d, env={"APP_TEST_CLOCK": "1", "APP_TEST_SESSIONS": "1"})
        if rc == 0:
            say(GREEN, f"code/tests-{lang}", "suite green")
            deps_ok[lang] = True
        elif "No module named" in out:
            say(DIM, f"code/tests-{lang}", f"python deps missing — {hint}")
            deps_ok[lang] = False
        elif "directory missing" in out:
            say(RED, f"code/tests-{lang}", f"{tail(out)} — the {lang}/ tree is gone but not acknowledged "
                                           f"(\"removed_languages\" in .gutencode/accepted.json)")
            deps_ok[lang] = False
        else:
            say(RED, f"code/tests-{lang}", fail_tail(out))
            deps_ok[lang] = True

    inv_dir = os.path.join(HERE, "tests", "invariants")
    inv_files = sorted(f for f in os.listdir(inv_dir)) if os.path.isdir(inv_dir) else []
    if not inv_files:
        say(RED, "code/invariants", "tests/invariants/ is missing or empty — the correctness proofs were removed")
    elif "python" in removed:
        say(DIM, "code/invariants", "python/ removed by owner — the invariant proofs are python-driven; skipped")
    elif deps_ok.get("python") is False:
        say(DIM, "code/invariants", "python deps missing (see code/tests-python)")
    else:
        bad = 0
        for f in inv_files:
            dbdir = tempfile.mkdtemp(prefix="verify_inv_")
            rc, out = run([sys.executable, os.path.join(inv_dir, f)], cwd=os.path.join(HERE, "python"),
                          env={"DATABASE_PATH": os.path.join(dbdir, "d.db"), "APP_TEST_CLOCK": "1", "APP_TEST_SESSIONS": "1"})
            if rc != 0:
                bad += 1
                say(RED, "code/invariants", f"{f} exit {rc}: {tail(out, 300)}")
        if not bad:
            say(GREEN, "code/invariants", f"{len(inv_files)} proof(s) green")

    # routes: the contract set must be present per language; live sets kept for the parity check
    want = {(r["method"], norm(r["path"])) for info in contract["domains"].values() for r in info["routes"]}
    wiring = contract.get("wiring", {})
    live = {}
    if "go" in langs:
        wf = os.path.join(HERE, wiring.get("go", "").replace("/", os.sep))
        if "go" not in wiring:
            say(RED, "code/routes-go", "contract.json has no wiring entry for go — cannot locate the route table")
        elif not os.path.isfile(wf):          # a missing tree is a reported failure, never a traceback
            say(RED, "code/routes-go", f"{wiring['go']} missing — the go/ tree is not on disk (deleted a "
                                       f"language? acknowledge it: \"removed_languages\" in accepted.json)")
        else:
            src = open(wf, encoding="utf-8").read()
            live["go"] = {(m.group(1), norm(m.group(2))) for m in re.finditer(r'mux\.HandleFunc\("(\w+) ([^"]+)"', src)}
    if "node" in langs:
        wf = os.path.join(HERE, wiring.get("node", "").replace("/", os.sep))
        if "node" not in wiring:
            say(RED, "code/routes-node", "contract.json has no wiring entry for node — cannot locate the route table")
        elif not os.path.isfile(wf):          # a missing tree is a reported failure, never a traceback
            say(RED, "code/routes-node", f"{wiring['node']} missing — the node/ tree is not on disk (deleted a "
                                         f"language? acknowledge it: \"removed_languages\" in accepted.json)")
        else:
            src = open(wf, encoding="utf-8").read()
            live["node"] = {(m.group(1), norm(m.group(2))) for m in re.finditer(r'\["(\w+)", "([^"]+)"', src)}
    if "python" in langs:
        if deps_ok.get("python") is False:
            say(DIM, "code/routes-python", "python deps missing (see code/tests-python)")
        else:
            probe = ("import json,sys; sys.path.insert(0,'.');\n"
                     "from app_pkg.app import app\n"
                     "print(json.dumps(sorted([m,r.path] for r in app.routes if type(r).__name__=='APIRoute'"
                     " for m in r.methods if m!='HEAD')))")
            rc, out = run([sys.executable, "-c", probe], cwd=os.path.join(HERE, "python"))
            if rc != 0:
                say(RED, "code/routes-python", tail(out))
            else:
                line = [ln for ln in out.splitlines() if ln.strip().startswith("[")]
                live["python"] = {(m, norm(p)) for m, p in json.loads(line[-1])} if line else set()
    for lang, got in sorted(live.items()):
        declared = ext_global | ext_lang.get(lang, set())   # routes YOU added, declared in extensions.json
        miss = want - got     # a contract route the app no longer serves
        extra = (got - want) - declared    # a route in NEITHER the contract NOR your extensions.json (a back-door
        if miss or extra:     # endpoint) — checked BOTH directions: the apps must expose EXACTLY the contract set
            bits = []
            if miss:
                bits.append(f"{len(miss)} contract route(s) MISSING: {sorted(miss)[:4]}")
            if extra:
                bits.append(f"{len(extra)} UNDECLARED route(s) — not in contract.json or .gutencode/extensions.json"
                            f": {sorted(extra)[:4]} (declare routes you added there)")
            say(RED, f"code/routes-{lang}", " · ".join(bits))
        else:
            say(GREEN, f"code/routes-{lang}", f"{len(want)} contract routes present, none undeclared")

    # parity: routes added in some-but-not-all languages (the three apps are a contract — AGENT.md rule 4). A route
    # you DECLARED in extensions.json is an intentional addition, so it is exempt from the asymmetry warning.
    if len(live) >= 2:
        extras = {lang: got - want for lang, got in live.items()}
        union = set().union(*extras.values())
        asym = sorted(r for r in union if any(r not in e for e in extras.values()))
        asym = [r for r in asym if r not in ext_any]
        if asym:
            where = {f"{m} {p}": [lang for lang, e in sorted(extras.items()) if (m, p) in e] for m, p in asym}
            say(YELLOW, "code/parity", f"{len(asym)} route(s) exist in SOME languages only: {where} — land changes "
                                       f"in all three or document the asymmetry")
        else:
            say(GREEN, "code/parity", f"all {len(live)} languages expose the same route set")
    elif removed:
        say(DIM, "code/parity", f"cross-language parity is OFF — {', '.join(l + '/' for l in removed)} removed "
                                f"by owner; {len(live)} language(s) left is not enough to compare")

    # live probes (error-shape + durability) need a bootable app per language
    tooldir = tempfile.mkdtemp(prefix="verify_boot_")
    go_exe = None
    if "go" in langs and deps_ok.get("go"):
        target = contract.get("build_targets", {}).get("go", "./cmd/server")
        go_exe = os.path.join(tooldir, "app.exe")
        rc, out = run(["go", "build", "-o", go_exe, target], cwd=os.path.join(HERE, "go"))
        if rc != 0:
            say(RED, "code/error-shape", f"go build failed: {tail(out)}")
            go_exe = None

    def boot(lang, env):
        if lang == "node" and not os.path.isdir(os.path.join(HERE, "node")):
            return None, "node/ directory missing"     # a reported boot failure, never a traceback
        port = free_port()
        # Pin the test server to LOOPBACK regardless of any ambient HOST (the verifier only ever connects via
        # 127.0.0.1) — so it never opens a network listener (no desktop-firewall prompt, no exposure during verify).
        # The server's stdout/stderr go to DEVNULL: the verifier never reads them, and DRAINING them (vs an undrained
        # PIPE) is what guarantees a chatty app can NEVER fill the ~64 KB OS pipe buffer and block mid-probe — the
        # root fix, not relying on LOG_LEVEL=silent (which we still pass as defense-in-depth / clean logs).
        e = {**env, "PORT": str(port), "HOST": "127.0.0.1", "APP_TEST_CLOCK": "1", "APP_TEST_SESSIONS": "1", "LOG_LEVEL": "silent"}
        # stderr → a temp FILE, not DEVNULL and not a PIPE. A file (like DEVNULL) can never fill and block a chatty
        # app the way an undrained PIPE would — but unlike DEVNULL it retains WHY a server that dies before listening
        # died. That reason must reach the classifier: a go binary built without `-tags postgres` panics on a Postgres
        # DATABASE_URL, and that is a driver-absent SKIP, not a durability failure. stop() closes + removes the file.
        errf = open(os.path.join(tooldir, f"boot_{lang}_{port}.err"), "w+b")
        if lang == "node":
            proc = subprocess.Popen(["node", "server.js"], cwd=os.path.join(HERE, "node"),
                                    env={**os.environ, **e}, stdout=subprocess.DEVNULL, stderr=errf)
        else:
            proc = subprocess.Popen([go_exe], env={**os.environ, **e},
                                    stdout=subprocess.DEVNULL, stderr=errf)
        proc._verify_errfile = errf   # stop() closes + unlinks it once the session ends
        up, why = wait_listening(port, proc)
        if not up:
            try:                              # the process already exited (wait_listening saw poll()!=None) → stderr is flushed
                errf.flush(); errf.seek(0)
                err_out = errf.read().decode("utf-8", "replace").strip()
            except Exception:
                err_out = ""
            stop(proc)
            # the HEAD of stderr, not the tail: a go panic / node startup error leads with the REASON (e.g. "…built
            # WITHOUT the Postgres backend. Rebuild with -tags postgres"), which the durability-pg classifier reads to
            # tell a driver-absent SKIP from a real failure; the stack trace at the tail would bury that reason.
            return None, f"{why}: {err_out[:300]}" if err_out else why
        base = f"http://127.0.0.1:{port}"
        # CONFIRM HTTP-readiness, not just an open TCP port: a freshly booted server can accept the port a beat
        # before it serves HTTP, so under load the first real probe could be reset. One throwaway request (a 404 IS
        # a served response) through the retrying _urlopen blocks until the server actually answers. [#25]
        import urllib.error
        import urllib.request
        ready = time.time() + 15
        while time.time() < ready:
            try:
                urllib.request.urlopen(urllib.request.Request(base + "/__verify_nope__", method="GET"), timeout=5)
                break                    # a served response means HTTP is up — ready
            except urllib.error.HTTPError:
                break                    # a 4xx IS a served response — ready
            except Exception:
                time.sleep(0.25)         # port open but HTTP not serving yet (the race) — keep polling, up to 15s
        return proc, base

    # code/error-shape — every language's 404 + 422 must be the SAME problem+json envelope
    post_case = next((c for c in contract.get("tests", []) if c["method"] == "POST" and "json" in c), None)
    post_path = post_case["path"].split("?")[0] if post_case else ""
    # the 405 probe needs a method NOT declared on post_path: a REST collection legitimately exposes GET next to
    # POST on the same path, so derive the wrong method from the contract routes to keep the probe a true 405.
    declared = {r["method"] for info in contract.get("domains", {}).values() for r in info["routes"]
                if norm(r["path"]) == norm(post_path)}
    wrong_method = next((m for m in ("GET", "DELETE", "PUT", "PATCH") if m not in declared), "GET")
    shapes = {}
    if "python" in langs and deps_ok.get("python"):
        rc, out = run([sys.executable, "-c", PY_SHAPE, post_path, wrong_method], cwd=os.path.join(HERE, "python"))
        line = [ln for ln in out.splitlines() if ln.strip().startswith("{")]
        if rc == 0 and line:
            shapes["python"] = json.loads(line[-1])
        else:
            say(RED, "code/error-shape", f"python probe failed: {tail(out)}")
    for lang in [x for x in ("go", "node") if x in langs]:
        if (lang == "go" and not go_exe) or (lang == "node" and not deps_ok.get("node")):
            continue
        proc, base = boot(lang, {"DATABASE_PATH": os.path.join(tooldir, f"shape_{lang}.db")})
        if proc is None:
            say(RED, "code/error-shape", f"{lang}: {base}")
            continue
        try:
            sh = {"404": http_shape(base, "GET", "/__verify_nope__")}
            if post_path:
                big = b'{"x":"' + b"a" * (1 << 21) + b'"}'   # VALID JSON, >1 MiB so go reaches the byte cap
                sh["405"] = http_shape(base, wrong_method, post_path)
                sh["413"] = http_shape(base, "POST", post_path, big)
                sh["422"] = http_shape(base, "POST", post_path, b"{not json")
            else:
                sh["405"] = sh["413"] = sh["422"] = sh["404"]
            shapes[lang] = sh
        finally:
            stop(proc)
    if shapes:
        media = contract.get("conventions", {}).get("error_media", "application/problem+json")
        want = {"404": 404, "405": 405, "413": 413, "422": 422} if post_path else {"404": 404}
        bad = []
        ref_lang = sorted(shapes)[0]
        for lang, s in sorted(shapes.items()):
            if s["404"][1:2] != [media]:
                bad.append(f"{lang} 404 media {s['404'][1]} != {media}")
            for code, st in want.items():       # the code must be RIGHT, not just identical across languages
                if s[code][0] != st:
                    bad.append(f"{lang} {code} status {s[code][0]} != {st}")
            if s != shapes[ref_lang]:
                bad.append(f"{lang} {s} != {ref_lang} {shapes[ref_lang]}")
        if bad:
            say(RED, "code/error-shape", "; ".join(bad[:3]))
        else:
            say(GREEN, "code/error-shape", f"404·405·413·422 envelope identical across {len(shapes)} language(s): {shapes[ref_lang]['404']}")
    elif langs:
        say(DIM, "code/error-shape", "no language probe could run (toolchains/deps missing)")

    # code/durability — BATCHED: one boot-cycle per language. Seed ALL store-backed domains into one database,
    # RESTART the process once, then check ALL. Cost is ~2 boots/language regardless of domain count (domains use
    # distinct store namespaces, so their probes don't interact). A failed case names its domain via the path.
    pers = contract.get("persistence", {})
    if not pers:
        say(DIM, "code/durability", "no persistence contracts shipped")
    else:
        seed = [c for d in sorted(pers) for c in pers[d]["seed"]]
        check = [c for d in sorted(pers) for c in pers[d]["check"]]
        ran, lost = 0, 0
        for lang in langs:
            if (lang == "python" and not deps_ok.get("python")) or (lang == "go" and not go_exe) \
                    or (lang == "node" and not deps_ok.get("node")):
                continue
            ran += 1
            dbp = os.path.join(tempfile.mkdtemp(prefix="verify_dur_"), "d.db")
            ok, why = True, ""
            if lang == "python":
                for phase, cases in (("seed", seed), ("check", check)):
                    rc, out = run([sys.executable, "-c", PY_CASES, json.dumps(cases)],
                                  cwd=os.path.join(HERE, "python"), env={"DATABASE_PATH": dbp, "APP_TEST_CLOCK": "1", "APP_TEST_SESSIONS": "1"})
                    if rc != 0:
                        ok, why = False, f"{phase}: {tail(out, 200)}"
                        break
            else:
                for phase, cases in (("seed", seed), ("check", check)):
                    proc, base = boot(lang, {"DATABASE_PATH": dbp})
                    if proc is None:
                        ok, why = False, f"{phase}: {base}"
                        break
                    try:
                        for case in cases:
                            cok, detail = http_case(base, case)
                            if not cok:
                                ok, why = False, f"{phase}: {detail}"
                                break
                    finally:
                        stop(proc)
                    if not ok:
                        break
            if not ok:
                lost += 1
                say(RED, "code/durability", f"[{lang}] state did NOT survive a restart — {why}")
        if ran and not lost:
            say(GREEN, "code/durability", f"{len(pers)} store-backed domains survive restart in {ran} language(s)")
        elif not ran:
            say(DIM, "code/durability", "no language could run the probes (toolchains/deps missing)")

        # code/durability-pg — OPT-IN Postgres proof: set DATABASE_URL=postgres://… (Supabase or any) to prove the
        # SAME seed -> RESTART -> check survives on YOUR Postgres. Writes test data to the configured DB (use a test
        # DSN). Unset = SKIP (the check above used SQLite). Each backend needs its optional driver: python psycopg,
        # go a `-tags postgres` build (+ pgx), node the `pg` package (npm install pg).
        pg_url = pg_url_ambient   # captured + popped at the top of main() so it never leaked into the SQLite suites
        if not (pg_url.startswith("postgres://") or pg_url.startswith("postgresql://")):
            say(DIM, "code/durability-pg", "set DATABASE_URL=postgres://… to also verify Postgres durability (above used SQLite)")
        elif not pers:
            say(DIM, "code/durability-pg", "no persistence contracts shipped")
        else:
            pgenv = {"DATABASE_URL": pg_url, "SECURE_DELETE_ACK": "1", "APP_TEST_CLOCK": "1", "APP_TEST_SESSIONS": "1"}
            absent = ("psycopg", "postgres backend", "pgx", "tags postgres")   # driver-not-available, not a durability failure
            # Each language must seed a FRESH schema (the SQLite arm gets a fresh temp file per language; on one shared
            # Postgres we wipe between languages instead). If psycopg isn't importable we can't wipe, so we run only the
            # first language rather than let the second inherit the first's rows.
            can_reset = pg_reset(pg_url)
            pran, plost, did_one = 0, 0, False
            for lang in langs:
                if lang == "node":
                    # node supports Postgres via the OPTIONAL `pg` package; if it isn't installed this is a
                    # driver-not-available SKIP (YELLOW), not a durability failure (mirrors python's psycopg / go's pgx).
                    chk, _co = run(["node", "-e", "import('pg').then(()=>process.exit(0)).catch(()=>process.exit(3))"],
                                   cwd=os.path.join(HERE, "node"))
                    if chk != 0:
                        say(YELLOW, "code/durability-pg", "[node] Postgres driver not available — npm install pg")
                        continue
                if (lang == "python" and not deps_ok.get("python")) or (lang == "go" and not go_exe) \
                        or (lang == "node" and not deps_ok.get("node")):
                    continue
                if not can_reset and did_one:
                    say(YELLOW, "code/durability-pg", f"[{lang}] skipped — install psycopg[binary] to isolate more than "
                                                      f"one language on a single Postgres DB")
                    continue
                if can_reset:
                    pg_reset(pg_url)      # fresh schema before THIS language's seed; preserved across its restart -> check
                did_one = True
                ok, why = True, ""
                if lang == "python":
                    for phase, cases in (("seed", seed), ("check", check)):
                        rc, out = run([sys.executable, "-c", PY_CASES, json.dumps(cases)], cwd=os.path.join(HERE, "python"), env=pgenv)
                        if rc != 0:
                            ok, why = False, f"{phase}: {tail(out, 300)}"
                            break
                else:
                    for phase, cases in (("seed", seed), ("check", check)):
                        proc, base = boot(lang, pgenv)
                        if proc is None:
                            ok, why = False, f"{phase}: {base}"
                            break
                        try:
                            for case in cases:
                                cok, detail = http_case(base, case)
                                if not cok:
                                    ok, why = False, f"{phase}: {detail}"
                                    break
                        finally:
                            stop(proc)
                        if not ok:
                            break
                if ok:
                    pran += 1
                elif any(a in why.lower() for a in absent):
                    hint = "pip install 'psycopg[binary]'" if lang == "python" else "rebuild: go build -tags postgres (and go get github.com/jackc/pgx/v5)"
                    say(YELLOW, "code/durability-pg", f"[{lang}] Postgres driver not available — {hint}")
                else:
                    plost += 1
                    say(RED, "code/durability-pg", f"[{lang}] Postgres durability FAILED — {why}")
            if pran and not plost:
                say(GREEN, "code/durability-pg", f"survives restart on YOUR Postgres in {pran} language(s)")
            elif not plost:
                say(DIM, "code/durability-pg", "no language could verify Postgres (drivers not installed / not built with -tags postgres)")

    # code/boundaries — a domain module may use core/parts, never a SIBLING domain. Domain-aware: the OWNING
    # domain comes from the path; only imports that resolve to a DIFFERENT known domain are violations (so
    # package-internal imports like `from .ports import` / `./providers.js` stay legal).
    domain_set = set(contract["domains"])
    rules = {"python": [r"app_pkg\.domains\.(\w+)", r"from\s+\.\.(?!\.)(\w+)", r"from\s+\.(?!\.)(\w+)"],
             "go": [r'"[\w./]+/internal/domains/(\w+)"'],
             "node": [r"from\s+'\.\./(\w+)", r"from\s+'\./(\w+)\.js'"]}
    hits, scanned = [], 0
    for lang, ddir in contract.get("layout_dirs", {}).items():
        d = os.path.join(HERE, ddir.replace("/", os.sep))
        if not os.path.isdir(d):
            continue
        for base, dirs, files in os.walk(d):
            for f in files:
                if not f.endswith((".py", ".go", ".js")) or "__init__" in f:
                    continue
                fp = os.path.join(base, f)
                rel_in = os.path.relpath(fp, d).replace(os.sep, "/")
                own = rel_in.split("/")[0]
                own = os.path.splitext(own)[0]
                scanned += 1
                text = open(fp, encoding="utf-8", errors="replace").read()
                for pat in rules.get(lang, []):
                    bad = [g for g in re.findall(pat, text) if g in domain_set and g != own]
                    if bad:
                        hits.append(f"{ddir}/{rel_in}: references domain(s) {sorted(set(bad))}")
                        break
    if hits:
        say(RED, "code/boundaries", f"domain modules importing sibling domains: {hits[:4]} — share via core/ or "
                                    f"parts/, never couple domains directly")
    else:
        say(GREEN, "code/boundaries", f"{scanned} domain module(s): no cross-domain imports")

    # code/primitives — security primitives exactly once per language
    # sqlite-open and postgres-open are DISTINCT primitives (the store driver split) — each must appear at most once
    # per language; every runtime ships both a SQLite and a Postgres driver.
    probes = {"python": [r"hmac\.new\(", r"sqlite3\.connect\(", r"psycopg\.connect\(", r"pbkdf2_hmac\("],
              "go": [r"hmac\.New\(", r'sql\.Open\(\s*"sqlite"', r'sql\.Open\(\s*"pgx"', r"pbkdf2\.Key"],
              "node": [r"createHmac\(", r"new DatabaseSync\(", r"new pg\.Pool\(", r"pbkdf2Sync\("]}
    dupes = []
    for lang in langs:
        d = os.path.join(HERE, lang)
        srcs = []
        for base, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if x not in skip_dirs]
            srcs += [os.path.join(base, f) for f in files
                     if f.endswith((".py", ".go", ".js")) and "test" not in f.lower()]
        for pat in probes[lang]:
            n = sum(len(re.findall(pat, open(p, encoding="utf-8", errors="replace").read())) for p in srcs)
            if n > 1:
                dupes.append(f"{lang}: {pat} ×{n}")
    say(RED if dupes else GREEN, "code/primitives",
        ("; ".join(dupes) + " — security primitives must exist exactly once; reuse the shipped helper") if dupes
        else "each security primitive appears exactly once per language")

    # code/deps — the shipped dependency surface must not have GROWN beyond what was printed (the counter to the
    # hallucinated-package / slopsquatting evidence: node ships zero deps, go is modernc-only, python is pinned).
    allow = contract.get("deps", {})
    if not allow:
        say(DIM, "code/deps", "no dependency allowlist shipped")
    else:
        grew = []
        for lang in langs:
            cur = current_deps(lang)
            extra = sorted(set(cur) - set(allow.get(lang, [])))
            if extra:
                grew.append(f"{lang}: +{extra}")
        if grew:
            say(YELLOW, "code/deps", "; ".join(grew) + " — new dependencies were added (a supply-chain surface); "
                                     "intended? pin them and re-baseline")
        else:
            tot = sum(len(allow.get(l, [])) for l in langs)
            note = "; node zero-dep, go modernc-only" if len(langs) > 1 else ""
            say(GREEN, "code/deps", f"dependency surface unchanged ({tot} pinned across {len(langs)} language(s)"
                                    f"{note})")

    shutil.rmtree(tooldir, ignore_errors=True)
    verdict = not failures and not (STRICT and warnings)
    print(f"\n==== VERIFY: {'GREEN' if verdict else 'RED'}"
          + (f" · {len(warnings)} warning(s)" if warnings and verdict else "") + " ====")
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
