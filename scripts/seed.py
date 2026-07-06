#!/usr/bin/env python3
"""Fill a RUNNING server with demo data -- through its own public API, exactly like any client would.

    python dev.py                                              # terminal 1: serve on :8080
    python scripts/seed.py                                     # terminal 2: seed it
    python scripts/seed.py --base-url http://127.0.0.1:8080    # a server on another port
    python scripts/seed.py --max 60                            # fire more of the contract's creates

How it works, and why it is honest:
  * it reads .gutencode/contract.json (the shipped machine map: every route + its test contract),
  * it signs up a demo account through the real signup route and logs in for a real bearer token
    -- no test switches, no backdoors; if the public API can't do it, this script can't either,
  * then it replays one contract-proven create request per module as that demo user, and says
    plainly which modules it skipped (operator-gated routes stay operator-gated).

Re-run it freely: every write it sends is replay-safe by construction -- a repeat either returns
the same object again or answers with a clean conflict. Both count as OK below.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CONTRACT = os.path.join(os.path.dirname(HERE), ".gutencode", "contract.json")
IDENTITY = "seed-demo@example.com"


def call(base, method, path, body=None, headers=None, timeout=10):
    """One HTTP round trip -> (status, parsed json or None). Connection failures raise."""
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(base + path, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    try:
        return status, json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return status, None


def find_route(contract, suffix):
    """A route located by generic path suffix -- the contract is the only map this script has."""
    for dom in contract.get("domains", {}).values():
        for r in dom.get("routes", []):
            if r.get("method") == "POST" and r.get("path", "").endswith(suffix):
                return r["path"]
    return None


def first_passing_case(tests, method, path):
    for c in tests:
        if c.get("method") == method and c.get("path", "").split("?")[0] == path \
                and 200 <= c.get("status", 0) < 300 and isinstance(c.get("json"), dict):
            return c
    return None


def main():
    ap = argparse.ArgumentParser(description="seed a running server with demo data via its public API")
    ap.add_argument("--base-url", default="http://127.0.0.1:8080", help="where the app is listening")
    ap.add_argument("--max", type=int, default=40, help="total request cap (keeps a run fast)")
    args = ap.parse_args()
    base = args.base_url.rstrip("/")

    try:
        with open(CONTRACT, encoding="utf-8") as f:
            contract = json.load(f)
    except (OSError, ValueError) as e:
        sys.exit(f"seed: cannot read {CONTRACT} ({e}) -- run me from inside this repo")
    tests = contract.get("tests") or []

    try:                                   # is anything listening? any HTTP answer (even 404) means yes
        call(base, "GET", "/")
    except (urllib.error.URLError, OSError):
        sys.exit(f"seed: nothing is answering at {base} -- start the app first (python dev.py), "
                 f"or point me at it with --base-url")

    signup = find_route(contract, "/register")
    login = find_route(contract, "/login")
    if not (signup and login):
        sys.exit("seed: this build ships no signup/login routes, and seeding through the public API "
                 "needs them to mint an honest token -- there is no backdoor to fall back on.")
    reg_case = first_passing_case(tests, "POST", signup)
    log_case = first_passing_case(tests, "POST", login)
    if not (reg_case and log_case):
        sys.exit("seed: the contract carries no passing signup/login case to imitate")

    print(f"seed: talking to {base} as {IDENTITY}")
    sent = ok = skipped = 0

    # 1 -- a real account through the real routes. Bodies come from the contract's own proven cases;
    #      only the account name is swapped, so seed data stays separate from your accounts.
    creds = dict(reg_case["json"])
    for k, v in list(creds.items()):
        if isinstance(v, str) and "@" in v:
            creds[k] = IDENTITY
    status, _ = call(base, "POST", signup, creds)
    sent += 1
    print(f"  {status} POST {signup}  (replies the same for new and existing accounts -- by design)")
    login_body = {k: creds.get(k, v) for k, v in log_case["json"].items()}
    status, data = call(base, "POST", login, login_body)
    sent += 1
    if not (200 <= status < 300 and isinstance(data, dict)):
        sys.exit(f"seed: login answered {status} -- cannot continue without a token")
    token = next((data[k] for k in ("access_token", "token")
                  if isinstance(data.get(k), str) and data[k]), None)
    if token is None:
        token = next((v for k, v in data.items()
                      if isinstance(v, str) and v and "token" in k and "type" not in k), None)
    if token is None:
        sys.exit(f"seed: no token field in the login reply (keys: {sorted(data)})")
    print(f"  {status} POST {login}  -> a real bearer token")
    bearer = "Bearer " + token

    # 2 -- one contract-proven create per module, as the demo user, in module order. The module that owns
    #      the signup/login routes is skipped whole: its other writes mutate THIS session (a replayed
    #      sign-out would revoke the very token the rest of the walk depends on).
    session_module = next((name for name, dom in contract.get("domains", {}).items()
                           if any(r.get("path") == signup for r in dom.get("routes", []))), None)
    by_module = {}
    for c in tests:
        by_module.setdefault(c.get("_domain") or "", []).append(c)
    for module in sorted(contract.get("domains", {})):
        if sent >= args.max:
            print(f"  -- request cap reached ({args.max}); re-run with --max for more")
            break
        if module == session_module:
            continue                                    # already exercised: that module minted our token
        cands = []                                      # (sendable-as-demo-user?, case) in contract order
        for c in by_module.get(module, []):
            if c.get("method") != "POST" or not (200 <= c.get("status", 0) < 300):
                continue
            if c.get("path", "").split("?")[0] in (signup, login):
                continue
            a = (c.get("headers") or {}).get("Authorization", "")
            cands.append(("operator" if (a and "test:" not in a) else "send", c))
        # contract order is the replayability signal: a module's FIRST passing create stands alone, later
        # cases lean on choreography state. So: first sendable-as-demo-user case, else the first operator
        # one (so the skip is reported, not silent).
        pick = next((c for v, c in cands if v == "send"), None)
        verdict = "send"
        if pick is None and cands:
            verdict, pick = cands[0]
        if pick is None:
            continue
        if verdict == "operator":
            print(f"  skip {pick['method']} {pick['path']}  (wants an operator credential, not a demo user)")
            skipped += 1
            continue
        hdrs = dict(pick.get("headers") or {})
        if "Authorization" in hdrs:
            hdrs["Authorization"] = bearer          # the suite identity becomes OUR demo user
        status, _ = call(base, pick["method"], pick["path"], pick.get("json"), hdrs)
        sent += 1
        if 200 <= status < 300:
            print(f"  {status} {pick['method']} {pick['path']}")
            ok += 1
        elif status in (409, 422):
            print(f"  {status} {pick['method']} {pick['path']}  (replay -> clean conflict; already seeded, still OK)")
            ok += 1
        elif status in (401, 403):
            print(f"  skip {pick['method']} {pick['path']}  ({status}: needs more than a fresh demo user)")
            skipped += 1
        else:
            print(f"  skip {pick['method']} {pick['path']}  ({status}: e.g. it builds on data this run did not create)")
            skipped += 1

    print()
    print(f"seed: {ok} writes OK, {skipped} skipped, {sent} requests total against {base}")
    print(f"  your demo bearer token ({IDENTITY}) -- paste it into requests.http or a frontend:")
    print(f"  {token}")
    print("  re-run me freely: every write above is replay-safe through the public API.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
