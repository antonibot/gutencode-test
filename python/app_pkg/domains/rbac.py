"""rbac — access control, deny-by-default (the OWASP ASVS V8 / NIST RBAC shape), governed by the AUTHENTICATED
identity. Two complementary models behind one surface: RBAC (subject -> assigned roles -> permissions over a fixed
code-reviewed role policy, least-privilege union) and FLAT relation tuples (ACL-style): a decision is allowed ONLY
on an exact (subject, relation, object) match — no wildcard, no prefix, no userset rewrite. (Full Zanzibar's
defining feature is userset rewrites — derived relations / role hierarchy; deliberately OUT OF SCOPE in v1, so
this is a flat tuple store, not a Zanzibar engine — a documented divergence: NIST Core/Flat RBAC + ACL is a valid
level.)

IDENTITY: every route is deny-by-default authenticated (no token -> 401). The DECISION reads (/can,
/check) are CALLER-SCOPED — the subject is the authenticated caller (the core require_identity seam), so a caller
asks only about THEIR OWN access (no enumeration of others). The MUTATIONS (/roles, /relations) are ADMIN-GATED
(ARBAC — role administration is itself a permissioned operation): the caller must be an rbac admin — holding the
'admin' role, which the operator provisions OUT-OF-BAND (seeding rbac_roles[<a real, already-registered subject>]
= ['admin'] at deploy time; there is NO env-NAME seed, because a claimable username was itself a
privilege-escalation hole). A non-admin is 403, so a caller can NEVER self-escalate. With no admin
provisioned, mutations are fully LOCKED (no one can assign until the operator bootstraps) — deny-by-default. (Under
APP_TEST_SESSIONS=1 a fixed test admin is recognized — inert in production, like the test-session seam.) The
grantee/relation/object remain free identifiers, so the central well_formed
rule is KEPT (key-forgery protection on the \x1f tuple delimiter). Assignment appends through the ATOMIC do()
seam; assignments and tuples live in the durable store, so decisions survive a restart.
"""
import os
from typing import Dict, Set

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from ..core import clock, store
from ..core.errors import forbidden, invalid, is_admin, require_identity
from ..parts.paginate import paginate
from ..parts.well_formed import WellFormedStr, require_well_formed

router = APIRouter(prefix="/rbac", tags=["rbac"])

# The role policy is POLICY (fixed, code-reviewed), not per-request state — so it stays a constant.
_ROLE_PERMS: Dict[str, Set[str]] = {
    "admin": {"read", "write", "delete"},
    "editor": {"read", "write"},
    "viewer": {"read"},
}
# state in `store`: ns "rbac_roles" subject -> [role, ...] · ns "rbac_rel" "subject\x1frelation\x1fobject" -> true
# (same namespaces + key model in all three languages)


# every name here is an IDENTIFIER — the central well_formed rule (non-empty, no control chars). For rbac this is
# also key-forgery protection: the unit separator is the tuple-key delimiter, so a name carrying a control
# character could forge the key of a DIFFERENT tuple. Rejected at the door, identically in all three languages.
class RoleAssign(BaseModel):
    subject: WellFormedStr
    role: WellFormedStr


class RelationIn(BaseModel):
    subject: WellFormedStr
    relation: WellFormedStr
    object: WellFormedStr


class Decision(BaseModel):
    allowed: bool


class Removed(BaseModel):
    removed: bool   # was the grant present before this revoke? (best-effort, idempotent — absent is still 200)


def _rel_key(subject: str, relation: str, object: str) -> str:
    return "\x1f".join((subject, relation, object))   # unit separator joins the tuple into ONE exact key


# the ADMIN check is the CORE seam (core.errors.is_admin): rbac is the management SURFACE that WRITES roles, core
# owns the cross-cutting NOTION (it reads rbac_roles) so non-rbac admin-only domains can gate WITHOUT importing rbac
# (the boundary rule: domains -> core only). The ARBAC rule, the out-of-band production bootstrap, and the inert
# test admin all live there — ONE definition for the whole app.


def _require_admin(caller, request, kind) -> None:
    # the LIST-introspection authz chokepoint (mutations use _admin_dep): a denied attempt is audited
    # UNCONDITIONALLY (ASVS 16.3.2 L2 — EVERY failed authorization is logged, list reads included), then refused.
    # request is REQUIRED (the audit timestamp comes from the clock seam) — there is no skip path.
    if not is_admin(caller):
        _audit(request, caller, kind, "", "", "deny", "not-admin")
        raise forbidden("rbac administration requires the admin role")


_AUDIT_NS = "rbac_decisions"


def _audit(request, subject, kind, action, obj, result, reason):
    # Path-2 decision audit (DOMAIN-LOCAL — the field convention: the authz component owns its own log; Cerbos/
    # Topaz/OPA/Cedar all do). APP_RBAC_AUDIT: "off" | "deny" (default — log denials, the ASVS 16.3.2 L2 MUST) |
    # "all". Append-only; ordered by a monotonic id; ts via the clock seam. Records DECISIONS (/can, /check) AND
    # MUTATIONS — a denied (403) mutation attempt is logged in deny mode (the ASVS failed-authz MUST); a successful
    # grant/revoke is the admin-event trail (surfaced in "all" mode). Queryable at GET /rbac/decisions (admin-only).
    mode = (os.getenv("APP_RBAC_AUDIT") or "").strip().lower()
    if mode not in ("off", "all"):           # unknown / empty / typo -> fail SAFE to the documented "deny" default
        mode = "deny"
    if mode == "off" or (mode == "deny" and result != "deny"):
        return
    rid = store.next_id("rbac_decision")
    store.put(_AUDIT_NS, str(rid), {"id": rid, "subject": subject, "kind": kind, "action": action,
                                    "object": obj, "result": result, "reason": reason, "ts": clock.current(request)})


def _admin_dep(kind):
    # A dependency: resolve the caller, require rbac admin, AUDIT a denied attempt — resolved by FastAPI BEFORE the
    # body is validated, so a non-admin gets 403 (not the body's 422): authn -> authz -> validation, identical ×3
    # with go/node. The denied-attempt audit carries no action/object (the body isn't parsed yet — same ×3).
    def dep(request: Request, caller: str = Depends(require_identity)) -> str:
        if not is_admin(caller):
            _audit(request, caller, kind, "", "", "deny", "not-admin")
            raise forbidden("rbac administration requires the admin role")
        return caller
    return dep


@router.post("/roles", response_model=Decision, status_code=201)
def assign(data: RoleAssign, request: Request, caller: str = Depends(_admin_dep("assign"))) -> Decision:
    if data.role not in _ROLE_PERMS:         # unknown role -> deny, loudly (never silently grant an undefined role)
        _audit(request, caller, "assign", data.role, data.subject, "deny", "unknown-role")
        return Decision(allowed=False)
    # ATOMIC append: a bare get-then-put RACES across processes — two concurrent grants of different roles to one
    # subject lose one. The do seam takes the write lock BEFORE the read; the callback is PURE and idempotent
    # (re-assigning the same role returns None -> no write).
    store.do("rbac_roles", data.subject,
             lambda cur: (None, None) if data.role in (cur or []) else ((cur or []) + [data.role], None))
    _audit(request, caller, "assign", data.role, data.subject, "grant", "ok")   # admin-event trail (all mode)
    return Decision(allowed=True)


@router.get("/can", response_model=Decision)
def can(request: Request, permission: str = "", caller: str = Depends(require_identity)) -> Decision:
    require_well_formed(permission, "permission")
    # caller-scoped + deny-by-default: allowed iff some role ASSIGNED TO THE CALLER grants the permission
    granted: Set[str] = set()
    for role in store.get("rbac_roles", caller) or []:
        granted |= _ROLE_PERMS.get(role, set())
    allowed = permission in granted
    _audit(request, caller, "can", permission, "", "allow" if allowed else "deny",
           "role-union" if allowed else "deny-by-default")
    return Decision(allowed=allowed)


@router.post("/relations", response_model=Decision, status_code=201)
def grant(data: RelationIn, request: Request, caller: str = Depends(_admin_dep("grant"))) -> Decision:
    # store the tuple components as the VALUE (self-describing) so listing can filter via values(); the existence
    # check (get is not None) is unchanged. The composite key still guarantees one row per exact tuple.
    store.put("rbac_rel", _rel_key(data.subject, data.relation, data.object),
              {"subject": data.subject, "relation": data.relation, "object": data.object})
    _audit(request, caller, "grant", data.relation, data.subject, "grant", "ok")   # admin-event trail (all mode)
    return Decision(allowed=True)


@router.get("/check", response_model=Decision)
def check(request: Request, relation: str = "", object: str = "", caller: str = Depends(require_identity)) -> Decision:
    require_well_formed(relation, "relation")
    require_well_formed(object, "object")
    # caller-scoped + deny-by-default: the EXACT (caller, relation, object) tuple must exist (no wildcard/prefix)
    allowed = store.get("rbac_rel", _rel_key(caller, relation, object)) is not None
    _audit(request, caller, "check", relation, object, "allow" if allowed else "deny",
           "tuple-match" if allowed else "deny-by-default")
    return Decision(allowed=allowed)


@router.delete("/roles", response_model=Removed)
def revoke_role(data: RoleAssign, request: Request, caller: str = Depends(_admin_dep("revoke-role"))) -> Removed:
    # ATOMIC remove via the do seam (a bare get-then-put RACES); idempotent — removing an absent role is a no-op
    # that returns removed:false (the field convention: deleting what isn't there still succeeds).
    def _rm(cur):
        roles = cur or []
        if data.role not in roles:
            return (None, False)              # absent -> no write
        return ([r for r in roles if r != data.role], True)
    removed = store.do("rbac_roles", data.subject, _rm)
    _audit(request, caller, "revoke-role", data.role, data.subject, "revoke", "ok")   # admin-event trail (all mode)
    return Removed(removed=bool(removed))


@router.delete("/relations", response_model=Removed)
def revoke_relation(data: RelationIn, request: Request, caller: str = Depends(_admin_dep("revoke-relation"))) -> Removed:
    key = _rel_key(data.subject, data.relation, data.object)
    existed = store.get("rbac_rel", key) is not None   # best-effort was-present signal
    store.delete_("rbac_rel", key)            # idempotent: delete is a no-op if the tuple is absent
    _audit(request, caller, "revoke-relation", data.relation, data.subject, "revoke", "ok")   # admin-event trail
    return Removed(removed=existed)


@router.get("/roles")
def list_roles(request: Request, subject: str = "", limit: str = "", cursor: str = "",
               caller: str = Depends(require_identity)) -> dict:
    # introspection: a caller may list THEIR OWN roles (default); listing another subject's roles is an admin op.
    target = subject or caller
    if target != caller:
        _require_admin(caller, request, "list-roles")
    require_well_formed(target, "subject")
    roles = store.get("rbac_roles", target) or []          # stored append-order is stable + identical ×3
    page, nxt, ok = paginate(roles, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/relations")
def list_relations(request: Request, subject: str = "", object: str = "", limit: str = "", cursor: str = "",
                   caller: str = Depends(require_identity)) -> dict:
    # a caller may list THEIR OWN forward tuples (subject==caller, no object filter); any other query — another
    # subject's tuples, or the inverse "who can access object Y" — is an admin introspection op (deny-by-default).
    self_ok = bool(subject) and subject == caller and not object
    if not self_ok:
        _require_admin(caller, request, "list-relations")
    if subject:
        require_well_formed(subject, "subject")
    if object:
        require_well_formed(object, "object")
    if not subject and not object:
        raise invalid("a subject or object filter is required")   # never an unbounded full dump
    rows = store.values("rbac_rel")                                # rowid-stable order, identical ×3
    filtered = [t for t in rows if (not subject or t["subject"] == subject) and (not object or t["object"] == object)]
    page, nxt, ok = paginate(filtered, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/decisions")
def list_decisions(request: Request, subject: str = "", limit: str = "", cursor: str = "",
                   caller: str = Depends(require_identity)) -> dict:
    _require_admin(caller, request, "list-decisions")   # the decision log is ADMIN-ONLY (reveals every subject's)
    rows = store.values(_AUDIT_NS)          # rowid order == monotonic id order, stable
    if subject:
        require_well_formed(subject, "subject")
        rows = [d for d in rows if d["subject"] == subject]
    page, nxt, ok = paginate(rows, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}
