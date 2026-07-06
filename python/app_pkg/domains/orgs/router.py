"""orgs — organizations / workspaces, the ownership root tenancy and teams hang off, with MULTI-MEMBER roles.
Dangerous properties:
(1) SLUG UNIQUENESS via the idempotent_claim part (two processes racing a slug create ONE org; duplicate 409).
(2) NEVER OWNERLESS: an org is created with an owner stamped FROM THE AUTHENTICATED TOKEN (never a body field),
    ownership transfers ONLY to a well-formed handle, and there is EXACTLY ONE owner at all times — the owner can
    never be removed or demoted (transfer is the only way ownership moves; the old owner becomes an admin). Archival
    is monotonic and idempotent (an archived org never returns to active). Durable across restart.
(3) ROLE-GOVERNED MEMBERSHIP, MEMBERSHIP PENDING UNTIL ACCEPTED: the authenticated caller's role in the org
    (owner|admin|member) gates every management op — add/set/remove member + archive need owner|admin; transfer needs
    owner. A member can never escalate itself (an added role ∈ {admin,member} — ownership only via transfer), and a
    non-member is 403. add_member is an INVITE: it writes a PENDING row + mints a single-use token; the role is
    conferred ONLY when the INVITED party ACCEPTS with that token (a pending invite grants NOTHING). This closes the
    member-identity escalation — a manager pre-naming a raw handle they do not control (which an attacker could later
    self-register) cannot grant that handle a role, because the attacker never receives the accept token.

IDENTITY: every mutation is deny-by-default authenticated (no token -> 401). The owner is the AUTHENTICATED
identity at create (the core require_identity seam) — never client-supplied — and management is authorized against
the caller's ORG ROLE (the core org_role seam, resolved BEFORE the body is validated, so a non-member gets 403 not
the body's 422 — identical ×3 with go/node, the rbac precedence). orgs is the management SURFACE that WRITES the
membership store; core owns the NOTION (org_role reads it) so teams authorize against org membership WITHOUT
importing orgs (the boundary rule: domains -> core only).

The membership store is the cross-cutting namespace the core seam reads: ns "orgs_members", key
"<slug>\x1f<handle>" -> a self-describing record {org, handle, role, status} (+ secret_hash, invite_exp while
PENDING). The \x1f unit separator is un-forgeable because slugs/handles are well_formed (no control chars), so a
member key can never collide with another org's. orgs_records still holds {id, slug, status, owner} (owner = the
canonical owner handle).

MEMBERSHIP IS PENDING UNTIL ACCEPTED (closes the member-identity escalation): add_member is an INVITE — it
writes a PENDING row + mints a single-use secret token delivered to an outbox; the role is conferred (org_role reads
it) ONLY once the INVITED party ACCEPTS with that token. So pre-naming a raw handle a manager does not control grants
nothing: the attacker who later self-registers that handle never received the token. Mirrors auth's mint/deliver/
consume (single-use via the do() seam, const-time secret compare); the token's secrecy + single-use/expiry are the
proof of identity that a raw handle alone is not."""
import hmac
import os
import secrets

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from ...core import clock, store
from ...core.errors import conflict, forbidden, gone, invalid, not_found, org_role, require_identity
from ...parts.digest import digest_hex
from ...parts.env_int import env_int
from ...parts.idempotent_claim import claim_once
from ...parts.paginate import paginate
from ...parts.well_formed import WellFormedStr, require_well_formed

router = APIRouter(prefix="/orgs", tags=["orgs"])
# state in `store`: seq "orgs_org" · ns "orgs_records" slug -> {id, slug, owner, status} · ns "orgs_members"
# "<slug>\x1f<handle>" -> {org, handle, role, status, secret_hash?, invite_exp?} (the record the core org_role
# seam reads — role granted iff status=="active"; ×3 identical) · ns "orgs_outbox" "<slug>\x1f<handle>" -> the invite token

_OWNER, _ADMIN, _MEMBER = "owner", "admin", "member"
_MANAGER_ROLES = (_OWNER, _ADMIN)            # roles allowed to manage membership / archive
_ASSIGNABLE_ROLES = (_ADMIN, _MEMBER)        # roles a manager may grant via add-member (NEVER owner — see transfer)
_PENDING, _ACTIVE = "pending", "active"      # an invite is PENDING until ACCEPTED; only an active member has a role
_REMOVED = "removed"                         # a SOFT-delete tombstone: org_role grants only status=="active", so it is inert


class OrgIn(BaseModel):
    slug: WellFormedStr      # the owner is NOT a body field — it is stamped from the authenticated token (no forgery)


class TransferIn(BaseModel):
    owner: WellFormedStr      # the new owner — well-formed, so a transfer can never blank the owner


class MemberIn(BaseModel):
    handle: WellFormedStr
    role: WellFormedStr


class AcceptIn(BaseModel):
    token: WellFormedStr      # the single-use invite secret — the proof the caller owns the invited handle


def _mkey(slug: str, handle: str) -> str:
    return f"{slug}\x1f{handle}"   # unit separator joins (slug, handle) into the ONE membership key the seam reads


def _invite_ttl() -> int:
    return env_int(os.getenv("ORGS_INVITE_TTL_SECONDS"), 604800, 1)   # 7 days; env-tunable, floored at 1s


def _deliver_invite(slug: str, handle: str, token: str) -> None:
    # the delivery seam (mirrors auth._deliver): queue the single-use token for the email worker. Until email is wired
    # it lands in orgs_outbox (the invariant test drains it as the "email worker"). The token is the invite, never logged.
    # KEY is <slug>\x1f<handle> (un-forgeable, like the member key) — NOT <slug>:<handle>: ':' is well_formed, so a crafted "<victim>:<x>" owner could otherwise clobber another org's delivery row; \x1f can't collide.
    store.put("orgs_outbox", f"{slug}\x1f{handle}", {"to": handle, "kind": "org-invite", "token": token, "org": slug})


_AUDIT_NS = "orgs_decisions"   # the domain-local decision log (Path-2: the authz surface owns its own trail)


def _deny_audit_budget() -> tuple:
    # how many DENY rows one subject may append per window before the audit-write becomes a no-op (the deny-audit
    # soft-DoS wall). Generous so a real attack leaves a forensic trail (the first N denials ARE recorded) while a
    # non-member hammering a deny path can no longer pump orgs_decisions unbounded. Env-tunable; floored at 1.
    limit = env_int(os.getenv("ORGS_DENY_AUDIT_LIMIT"), 50, 1)
    window = env_int(os.getenv("ORGS_DENY_AUDIT_WINDOW"), 3600, 1)
    return limit, window


def _audit(request, subject, kind, target, org, result, reason):
    # Path-2 decision audit (DOMAIN-LOCAL — rbac/Cerbos/Topaz do the same). APP_ORGS_AUDIT: "off" | "deny" (DEFAULT —
    # every authz DENIAL + every successful ownership/membership MUTATION: the ASVS 7.1.3/7.2.2 "who took over this
    # org" trail) | "all" (reserved: + reads, none audited yet). Append-only, ordered by a monotonic id; ts via the
    # clock seam. orgs is a SEAM-NAMESPACE writer, so auditing is mandatory (every denial and every authz write is recorded).
    mode = (os.getenv("APP_ORGS_AUDIT") or "").strip().lower()
    if mode not in ("off", "all"):
        mode = "deny"                        # unknown/empty/typo -> fail SAFE to the documented "deny" default
    if mode == "off":
        return
    now = clock.current(request)
    if result == "deny":
        # THROTTLE the DENY-audit write per (ORG, subject) (deny-audit flood + cross-org isolation): a caller hammering a
        # deny path can otherwise append unbounded rows (a storage-amplification soft-DoS). The key includes the ORG
        # (\x1f-joined, un-forgeable since well_formed blocks <0x20) so noise an attacker generates on a DECOY org can
        # NOT blind a VICTIM org's trail — each org keeps its own first-N forensic denials. The deny-audit CALL still
        # precedes the 403 in the source (the denial audit still fires) — this is a RUNTIME budget INSIDE _audit.
        # Success-mutation audits (low-volume, high-value) are NEVER throttled.
        limit, window = _deny_audit_budget()
        if not store.throttle(f"orgs:deny-audit:{org}\x1f{subject}", limit, window, now):
            return                           # over budget for this (org, subject) in the window -> no-op (bounded growth)
    rid = store.next_id("orgs_decision")
    store.put(_AUDIT_NS, str(rid), {"id": rid, "subject": subject, "kind": kind, "target": target, "org": org,
                                    "result": result, "reason": reason, "ts": now})


def _load(slug: str) -> dict:
    org = store.get("orgs_records", require_well_formed(slug, "the slug"))
    if org is None:
        raise not_found("org")
    return org


def _manage_dep(allowed):
    # A dependency: resolve the caller, LOAD the org (404), require the caller's org_role ∈ `allowed` (403) — all
    # resolved by FastAPI BEFORE the body is validated, so authn -> not-found -> authz -> validation, identical ×3
    # with go/node (the rbac order). Returns (org, caller) so the handler reuses the already-loaded row.
    def dep(request: Request, slug: str, caller: str = Depends(require_identity)) -> tuple:
        org = _load(slug)
        if org_role(slug, caller) not in allowed:
            _audit(request, caller, "manage", "", slug, "deny", "not-a-manager")   # ASVS 7.1.3: log the failed authz
            raise forbidden("this operation requires an org owner or admin")
        return org, caller
    return dep


@router.post("", status_code=201)
def create(data: OrgIn, request: Request, caller: str = Depends(require_identity)) -> dict:
    # owner = the authenticated caller, stamped from the token (the body carries NO owner — never client-supplied)
    if store.get("orgs_records", data.slug) is not None:
        raise conflict("slug taken")     # fast path: a settled slug never mints (ids stay contiguous)
    rec = {"id": store.next_id("orgs_org"), "slug": data.slug, "owner": caller, "status": "active"}
    settled = claim_once("orgs_records", data.slug, rec)
    if settled["id"] != rec["id"]:
        raise conflict("slug taken")     # lost the race — never overwrite the winner's org
    # SINGLE-SOURCE OWNERSHIP: the owner is DERIVED from orgs_records.owner (the core org_role seam reads it) — we do
    # NOT write an 'owner' membership row, so there can never be two owners. orgs_members holds only admin|member.
    _audit(request, caller, "create", data.slug, data.slug, "create", "ok")   # ownership-event trail
    return settled


@router.get("/{slug}")
def get_org(slug: str, caller: str = Depends(require_identity)) -> dict:
    # read is MEMBER-SCOPED: authn (401) -> load (404) -> membership. A non-member is
    # 404 — byte-identical to a missing slug (not-yours == not-found, mirroring api_keys _load), so existence never
    # leaks cross-org. Precedence mirrors the mutation chokepoint (_manage_dep): identity before the membership 404.
    org = _load(slug)
    if org_role(slug, caller) is None:
        raise not_found("org")   # not a member -> same 404 as a missing org (existence never leaks)
    return org


@router.post("/{slug}/transfer")
def transfer(slug: str, data: TransferIn, request: Request, ctx: tuple = Depends(_manage_dep((_OWNER,)))) -> dict:
    # ONLY the current owner may transfer (the dependency enforced owner-role 403 before this body validated). The
    # ownership swap is a SINGLE-KEY ATOMIC do() on orgs_records that RE-ASSERTS the caller is STILL the owner INSIDE
    # the lock — the _manage_dep owner check was read before the lock, so two concurrent transfers from one owner
    # would otherwise both write (the two-owner race, F1). The loser's re-check fails -> 409 (never a silent overwrite).
    org, caller = ctx
    new_owner = data.owner

    def _swap(cur):
        if cur is None or cur.get("owner") != caller:
            return None, None                     # ownership changed concurrently (or vanished) -> don't write
        return {**cur, "owner": new_owner}, {**cur, "owner": new_owner}
    transferred = store.do("orgs_records", slug, _swap)
    if transferred is None:
        raise conflict("ownership changed concurrently")
    # maintain "orgs_members holds ONLY non-owner roles; the owner is solely orgs_records.owner": the NEW owner is the
    # DERIVED owner (tombstone any membership row they had); the OLD owner (caller) is demoted to an ACTIVE 'admin' (an
    # existing owner is a real, already-proven identity — no invite/accept needed; status="active" grants immediately).
    # Both projections go through the do() seam so they SERIALIZE with a concurrent remove_member(caller) on the SAME
    # member key — deterministic last-writer-wins, no resurrection of a hard-deleted row (invariant I18). [rmw-safe]
    store.do("orgs_members", _mkey(slug, new_owner),
             lambda cur: (None, None) if cur is None else ({**cur, "status": _REMOVED}, None))
    if new_owner != caller:
        store.do("orgs_members", _mkey(slug, caller),
                 lambda cur: ({"org": slug, "handle": caller, "role": _ADMIN, "status": _ACTIVE}, None))
    _audit(request, caller, "transfer", new_owner, slug, "transfer", "ok")   # the OWNERSHIP-CHANGE event (highest value)
    return transferred


@router.post("/{slug}/archive")
def archive(slug: str, request: Request, ctx: tuple = Depends(_manage_dep(_MANAGER_ROLES))) -> dict:
    org, caller = ctx
    # monotonic + idempotent: "archived" is TERMINAL. The do() seam reads the CURRENT record INSIDE the lock, so a
    # concurrent transfer's owner change is PRESERVED — a bare get(dep)->put would clobber the owner back.
    archived = store.do("orgs_records", slug,
                        lambda cur: (None, None) if cur is None else ({**cur, "status": "archived"}, {**cur, "status": "archived"}))
    if archived is None:
        raise not_found("org")    # vanished concurrently (no delete route today; defensive)
    _audit(request, caller, "archive", slug, slug, "archive", "ok")
    return archived


@router.post("/{slug}/members", status_code=201)
def add_member(slug: str, data: MemberIn, request: Request, ctx: tuple = Depends(_manage_dep(_MANAGER_ROLES))) -> dict:
    # INVITE a member (the dependency enforced owner|admin (403) before this body validated (422)). The role is NOT
    # granted here — it is PENDING until the invited party ACCEPTS with the single-use token (closes the member-identity
    # escalation: pre-naming a raw handle a manager does not control confers nothing). Re-inviting an ALREADY-ACTIVE
    # member updates the role in place (no new token — they are already proven). All in ONE atomic do() on the member key.
    _org, caller = ctx
    if data.role not in _ASSIGNABLE_ROLES:
        # ownership moves ONLY via transfer — a manager can never mint a second owner through add-member
        _audit(request, caller, "add-member", data.handle, slug, "deny", "role-not-assignable")
        raise forbidden("role must be 'admin' or 'member' (ownership transfers only)")
    now = clock.current(request)
    token = f"{secrets.token_urlsafe(12)}.{secrets.token_urlsafe(32)}"   # minted OUTSIDE do (do's fn must be pure)
    secret_hash, exp = digest_hex(token), now + _invite_ttl()
    out = {"status": None}

    def upsert(cur):
        if cur is not None and cur.get("status") == _ACTIVE:
            out["status"] = _ACTIVE                                  # already proven -> just (re)set the role, no token
            return {**cur, "role": data.role}, None
        out["status"] = _PENDING                                    # new or still-pending -> (re)issue a single-use invite
        return ({"org": slug, "handle": data.handle, "role": data.role, "status": _PENDING,
                 "secret_hash": secret_hash, "invite_exp": exp}, None)

    store.do("orgs_members", _mkey(slug, data.handle), upsert)
    if out["status"] == _PENDING:
        _deliver_invite(slug, data.handle, token)                   # the token reaches the invitee, never the inviter
        _audit(request, caller, "invite", data.handle, slug, "ok", "pending")
    else:
        _audit(request, caller, "add-member", data.handle, slug, "grant", "ok")
    return {"slug": slug, "handle": data.handle, "role": data.role, "status": out["status"]}


@router.post("/{slug}/members/accept")
def accept(slug: str, data: AcceptIn, request: Request, caller: str = Depends(require_identity)) -> dict:
    # ACCEPT a pending invite — authenticated; the membership is keyed on the CALLER (== the invited handle by
    # construction), so a token issued for handle X can only ever be redeemed by the authenticated subject X. SINGLE-USE
    # + const-time secret match + unexpired, all atomic via the do() seam (mirrors auth._consume): the FIRST valid accept
    # wins and clears the secret. A wrong/absent secret is 403, a non-pending/absent membership is 404, an expired is 410.
    _load(slug)                                                     # honest 404 on a missing org (load before the lookup)
    now = clock.current(request)
    out = {"r": "missing"}

    def consume(cur):
        if cur is None or cur.get("status") != _PENDING:
            out["r"] = "missing"                                    # no invite for this caller (or already active) -> 404
            return None, None
        if now >= cur.get("invite_exp", 0):
            out["r"] = "expired"                                    # expiry beats availability (even an unused token)
            return None, None
        if not (cur.get("secret_hash")
                and hmac.compare_digest(digest_hex(data.token), cur["secret_hash"])):
            out["r"] = "badtoken"                                   # wrong secret -> 403 (do NOT activate, do NOT consume)
            return None, None
        out["r"] = "ok"
        return {"org": slug, "handle": caller, "role": cur["role"], "status": _ACTIVE}, None   # activate + clear secret

    store.do("orgs_members", _mkey(slug, caller), consume)
    if out["r"] == "missing":
        _audit(request, caller, "accept", caller, slug, "deny", "no-pending-invite")
        raise not_found("invitation")
    if out["r"] == "expired":
        _audit(request, caller, "accept", caller, slug, "deny", "invite-expired")
        raise gone("invitation expired")
    if out["r"] == "badtoken":
        _audit(request, caller, "accept", caller, slug, "deny", "invalid-token")
        raise forbidden("invalid invitation token")
    _audit(request, caller, "accept", caller, slug, "accept", "ok")
    return {"slug": slug, "handle": caller, "role": store.get("orgs_members", _mkey(slug, caller))["role"],
            "status": _ACTIVE}


@router.delete("/{slug}/members/{handle}")
def remove_member(slug: str, handle: str, request: Request, ctx: tuple = Depends(_manage_dep(_MANAGER_ROLES))) -> dict:
    # owner|admin only (the dependency enforced it). The owner can NEVER be removed (never ownerless).
    org, caller = ctx
    require_well_formed(handle, "the member handle")
    if handle == org["owner"]:
        _audit(request, caller, "remove-member", handle, slug, "deny", "owner-not-removable")
        raise forbidden("the owner cannot be removed (transfer ownership first)")
    # SOFT delete: tombstone the row (status="removed") through the do() seam — NOT a hard delete_. This SERIALIZES
    # with a concurrent transfer-demotion on the SAME member key (deterministic last-writer-wins), so a confirmed-
    # removed member can never be resurrected by the demotion's bare write (invariant I18). org_role grants only
    # status=="active" and list-members filters active, so the tombstone is inert. Removing an absent member is a no-op.
    store.do("orgs_members", _mkey(slug, handle),
             lambda cur: (None, None) if cur is None else ({**cur, "status": _REMOVED}, None))
    _audit(request, caller, "remove-member", handle, slug, "remove", "ok")
    return {"slug": slug, "handle": handle, "removed": True}


@router.get("")
def list_mine(request: Request, limit: str = "", cursor: str = "", caller: str = Depends(require_identity)) -> dict:
    # MY orgs: the caller's own orgs — those they OWN (orgs_records.owner == caller) or are an ACTIVE member of.
    # Authenticated (the authenticated-read wall); the result is intrinsically caller-scoped (no cross-tenant leak). Scan the
    # records in rowid order (stable + identical ×3) and route through paginate (the soft-DoS wall).
    mine = [r for r in store.values("orgs_records")
            if r.get("owner") == caller or org_role(r.get("slug", ""), caller) is not None]
    page, nxt, ok = paginate(mine, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/{slug}/members")
def list_members(slug: str, request: Request, limit: str = "", cursor: str = "",
                 caller: str = Depends(require_identity)) -> dict:
    # MEMBER-SCOPED: authn (401) -> load (404) -> ACTIVE membership; a non-member is 404
    # BYTE-IDENTICAL to a missing slug (existence never leaks, exactly like get_org). The roster = the DERIVED owner
    # (orgs_records.owner, role "owner" — it has no membership row) + every ACTIVE orgs_members row for this slug
    # (pending invites are NOT listed — see list_invitations). Stable rowid order ×3; paginated.
    org = _load(slug)
    if org_role(slug, caller) is None:
        raise not_found("org")   # not a member -> same 404 as a missing org (existence never leaks)
    roster = [{"handle": org["owner"], "role": _OWNER}]
    roster += [{"handle": m["handle"], "role": m["role"]} for m in store.values("orgs_members")
               if m.get("org") == slug and m.get("status") == _ACTIVE]
    page, nxt, ok = paginate(roster, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/{slug}/invitations")
def list_invitations(slug: str, request: Request, limit: str = "", cursor: str = "",
                     ctx: tuple = Depends(_manage_dep(_MANAGER_ROLES))) -> dict:
    # MANAGER-ONLY (owner|admin, via the same chokepoint as the membership mutations): the PENDING invites for this
    # slug — (handle, role, invite_exp) ONLY, NEVER the secret_hash/token (the invite secret reaches the invitee
    # alone). Stable rowid order ×3; paginated.
    invites = [{"handle": m["handle"], "role": m["role"], "invite_exp": m.get("invite_exp")}
               for m in store.values("orgs_members")
               if m.get("org") == slug and m.get("status") == _PENDING]
    page, nxt, ok = paginate(invites, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.post("/{slug}/leave")
def leave(slug: str, request: Request, caller: str = Depends(require_identity)) -> dict:
    # SELF-leave — the authenticated caller leaves (deletes THEIR OWN orgs_members row). MEMBER-SCOPED like get_org/
    # list_members: authn (401) -> load (404) -> ACTIVE membership. A NON-member (or already-left) is 404 BYTE-IDENTICAL
    # to a missing slug — existence never leaks via leave's 200/404, and a non-member can't pump no-op 'leave' rows into
    # the decision log (only a REAL member's leave is audited — no existence oracle, no no-op audit flood). The OWNER cannot
    # leave (records-owner; would orphan the org) -> 409 (never-ownerless, mirroring owner-not-removable; audited —
    # though a 409 itself needs no denial audit). A re-leave by the now-removed caller is 404 (consistent — no longer a member).
    org = _load(slug)
    if org_role(slug, caller) is None:
        raise not_found("org")   # not a member -> same 404 as a missing org (no existence leak, no no-op audit firehose)
    if caller == org["owner"]:
        _audit(request, caller, "leave", caller, slug, "deny", "owner-cannot-leave")
        raise conflict("the owner cannot leave (transfer ownership first)")
    store.delete_("orgs_members", _mkey(slug, caller))   # only a real ACTIVE member reaches here
    _audit(request, caller, "leave", caller, slug, "leave", "ok")
    return {"slug": slug, "handle": caller, "left": True}
