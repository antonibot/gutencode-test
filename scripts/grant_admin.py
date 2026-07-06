"""Grant the application admin role to an already-registered account.

Usage:
    python scripts/grant_admin.py you@example.com

Run it with the SAME environment the app uses (DATABASE_URL for Postgres, or DATABASE_PATH for the
SQLite file). It writes through the app's own storage layer, so it works on both backends.

Why this exists: the app ships NO bootstrap account and NO seed-by-env-name -- a pre-named subject
would be claimable (whoever registered it first would inherit the role). The safe order is: register
a real account through the app first, then grant it the role here. This script REFUSES a subject
that has never registered, for exactly that reason.

No Python on the host? The SQL equivalent (the row layout is identical on SQLite and Postgres):

    INSERT INTO _kv (ns, k, v) VALUES ('rbac_roles', 'you@example.com', '["admin"]')
    ON CONFLICT (ns, k) DO UPDATE SET v = excluded.v;

(Raw SQL skips the registered-account check -- type the subject exactly as it registered.)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "python"))

ROLES_NS = "rbac_roles"        # the namespace the app's admin check reads
ADMIN_ROLE = "admin"    # the role name it looks for
USERS_NS = "auth_users"          # registered accounts (written by the signup flow)


def main(argv):
    if len(argv) != 1 or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 2
    subject = argv[0].strip()
    if not subject:
        print("refusing: empty subject")
        return 1
    if not (os.environ.get("DATABASE_URL") or os.environ.get("DATABASE_PATH")):
        print("refusing: neither DATABASE_URL nor DATABASE_PATH is set -- this process would open an "
              "in-memory database, grant the role there, and throw it away on exit. Export the same "
              "storage environment the app runs with, then re-run.")
        return 1
    from app_pkg.core import store   # the app's own storage layer (imported late: it reads the env above)
    if store.get(USERS_NS, subject) is None:
        print(f"refusing: {subject!r} has never registered (no account row). Create the account through "
              f"the app first (POST /auth/register), then re-run. Granting an unregistered name would "
              f"hand the role to whoever registers it later.")
        return 1

    def grant(current):
        roles = list(current or [])
        if ADMIN_ROLE in roles:
            return None, roles                       # already granted -- leave the row as-is (idempotent)
        return roles + [ADMIN_ROLE], roles + [ADMIN_ROLE]

    roles = store.do(ROLES_NS, subject, grant)       # atomic read-modify-write (safe next to a live app)
    print(f"{subject}: roles = {roles}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
