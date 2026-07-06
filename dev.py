#!/usr/bin/env python3
"""One command to a running backend.

    python dev.py              serve the first runtime this machine can run (python -> go -> node)
    python dev.py go           force one runtime (python | go | node)
    python dev.py verify       run the offline proof (same as: python verify.py)
    python dev.py seed         fill a RUNNING server with demo data (same as: python scripts/seed.py)
    python dev.py --port 9000  serve on another port (the PORT environment variable works too)

Whichever runtime it picks, the app answers on ONE port (default 8080 — the same port the README per-language quickstart blocks, the
Dockerfiles and docker-compose use), so README, TOUR.md, requests.http and scripts/seed.py all talk to the
same base URL. This file only orchestrates, it changes nothing.
The serve commands come from .gutencode/contract.json, the shipped machine map of this repo.
"""
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIMES = ("python", "go", "node")
# fallbacks for a tree whose contract predates the serve hints -- same commands the README shows
FALLBACK_SERVE = {"python": "uvicorn app_pkg.app:app", "go": "go run ./cmd/server", "node": "npm start"}


def _contract():
    try:
        with open(os.path.join(HERE, ".gutencode", "contract.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _lang_dir(contract, lang):
    wiring = (contract.get("wiring") or {}).get(lang) or ""
    top = wiring.split("/", 1)[0] if "/" in wiring else lang
    return os.path.join(HERE, top)


def _available(lang):
    """(usable?, human reason) -- a runtime is usable when its toolchain answers on this machine."""
    if lang == "python":
        import importlib.util
        ok = importlib.util.find_spec("uvicorn") is not None
        return ok, "ready" if ok else "deps missing -- run: pip install -r python/requirements.txt"
    tool = {"go": "go", "node": "npm"}[lang]
    hint = {"go": "install Go: https://go.dev/dl", "node": "install Node 22+: https://nodejs.org"}[lang]
    ok = shutil.which(tool) is not None
    return ok, "ready" if ok else hint


def serve(lang, port, contract):
    d = _lang_dir(contract, lang)
    if not os.path.isdir(d):
        sys.exit(f"dev.py: this repo has no {lang}/ tree")
    hint = (contract.get("serve") or {}).get(lang) or FALLBACK_SERVE[lang]
    env = dict(os.environ, PORT=str(port))
    if lang == "python":
        parts = hint.split()
        if parts and parts[0] == "uvicorn":
            # run uvicorn through THIS interpreter, so it works even when its console script is not on PATH
            cmd, shell = [sys.executable, "-m"] + parts + ["--port", str(port)], False
        else:
            cmd, shell = [sys.executable, "-m"] + parts, False
    else:
        cmd, shell = hint, True                      # go/npm resolve via the shell (Windows included)
    print(f"dev.py: serving the {lang} runtime on http://127.0.0.1:{port}")
    print(f"  next moves: curl http://127.0.0.1:{port}/health  |  open TOUR.md  |  python scripts/seed.py")
    if lang == "python":
        print(f"  interactive API docs (python runtime only): http://127.0.0.1:{port}/docs")
    print(f"  command: {hint}  (cwd: {os.path.relpath(d, HERE) or '.'})")
    try:
        return subprocess.call(cmd, cwd=d, env=env, shell=shell)
    except KeyboardInterrupt:
        return 0


def main(argv):
    if argv and argv[0] == "verify":
        return subprocess.call([sys.executable, os.path.join(HERE, "verify.py")] + argv[1:], cwd=HERE)
    if argv and argv[0] == "seed":
        return subprocess.call([sys.executable, os.path.join(HERE, "scripts", "seed.py")] + argv[1:], cwd=HERE)
    try:
        port = int(os.environ.get("PORT") or 8080)
    except ValueError:
        port = 8080
    if "--port" in argv:
        i = argv.index("--port")
        try:
            port = int(argv[i + 1])
        except (IndexError, ValueError):
            sys.exit("dev.py: --port needs a number, e.g. --port 9000")
        argv = argv[:i] + argv[i + 2:]
    contract = _contract()
    if argv and argv[0] in RUNTIMES:
        ok, why = _available(argv[0])
        if not ok:
            sys.exit(f"dev.py: the {argv[0]} toolchain is not usable here -- {why}")
        return serve(argv[0], port, contract)
    if argv:
        sys.exit(f"dev.py: unknown argument {argv[0]!r} -- try: python dev.py [python|go|node|verify|seed] [--port N]")
    print("dev.py: picking a runtime (python -> go -> node)")
    chosen = None
    for lang in RUNTIMES:
        ok, why = _available(lang)
        print(f"  {lang:6s} {why}")
        if ok and chosen is None:
            chosen = lang
    if chosen is None:
        sys.exit("dev.py: no runtime is usable on this machine yet -- any ONE of the fixes above is enough.")
    return serve(chosen, port, contract)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
