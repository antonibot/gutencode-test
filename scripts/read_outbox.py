"""Read the DEV outbox — the verify / reset / invitation tokens the app "delivers by email".

Usage:
    python scripts/read_outbox.py                 # every pending token (all outbox namespaces)
    python scripts/read_outbox.py auth_outbox     # just one namespace

Run it with the SAME environment the app uses (DATABASE_URL for Postgres, or DATABASE_PATH for the SQLite
file) so it reads the RUNNING app's store. There is NO HTTP route that exposes these tokens — the app
"emails" them (writes them to an outbox namespace), and this DEV helper reads them straight from the store,
so you can complete the signup -> verify -> login -> reset (and invite -> accept) loop locally without a
mail server.

NEVER expose these tokens in production — this is a local development convenience only.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "python"))

# every "*_outbox" store namespace this build ships (auth verify/reset, org invites, ...) — DERIVED at export.
OUTBOX_NAMESPACES = ["auth_outbox", "email_outbox", "orgs_outbox"]


def main(argv):
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 2
    if not (os.environ.get("DATABASE_URL") or os.environ.get("DATABASE_PATH")):
        print("refusing: neither DATABASE_URL nor DATABASE_PATH is set — this process would open a throwaway "
              "in-memory database and read nothing. Export the SAME storage environment the app runs with "
              "(the one your server uses), then re-run.")
        return 1
    from app_pkg.core import store   # the app's own storage layer (imported late: it reads the env above)
    namespaces = [argv[0]] if argv else OUTBOX_NAMESPACES
    total = 0
    for ns in namespaces:
        for row in store.values(ns):
            total += 1
            out = {"namespace": ns}
            out.update(row if isinstance(row, dict) else {"value": row})
            print(json.dumps(out))
    if total == 0:
        print(f"(no pending outbox rows in {namespaces} — trigger a verify / reset / invite first, then re-run)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
