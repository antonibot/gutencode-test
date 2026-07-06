// orgs — organizations / workspaces, the ownership root, with MULTI-MEMBER roles. (1) SLUG UNIQUENESS via
// idempotent_claim (racing processes create ONE org; duplicate 409). (2) NEVER OWNERLESS: created with an owner
// STAMPED FROM THE AUTHENTICATED TOKEN (never a body field), ownership transfers ONLY to a well-formed handle, and
// there is EXACTLY ONE owner at all times — the owner is never removed/demoted (transfer is the only move; the old
// owner becomes an admin). Archival is monotonic + idempotent. (3) ROLE-GOVERNED MEMBERSHIP, PENDING UNTIL ACCEPTED:
// the caller's org_role (owner|admin|member) gates every management op — add/set/remove member + archive need
// owner|admin, transfer needs owner; a manager may grant only admin|member, and a non-member is 403. add_member is an
// INVITE (a PENDING row + a single-use token); the role is conferred ONLY when the invitee ACCEPTS with that token.
//
// IDENTITY: mutations are deny-by-default authenticated (401). authn -> not-found -> authz -> validation,
// identical ×3 (the rbac order): requireIdentity then load then org_role run BEFORE the body fields are
// validated, so a non-member gets 403 not the body's 422. orgs is the management SURFACE that WRITES the membership
// store; core owns the NOTION (orgRole reads it) so teams authorize WITHOUT importing orgs (boundary: domains -> core).
//
// The membership store is the cross-cutting namespace the core seam reads: ns 'orgs_members', key
// `${slug}\x1f${handle}` -> a self-describing record {org, handle, role, status} (+ secret_hash, invite_exp
// while PENDING). The \x1f unit separator is un-forgeable (slugs/handles are well_formed). orgs_records stays
// {id, slug, owner, status}. Store names + shapes match python/go; durable.
//
// MEMBERSHIP IS PENDING UNTIL ACCEPTED (closes the member-identity escalation): add_member is an INVITE — it
// writes a PENDING row + mints a single-use secret token delivered to an outbox; the role is conferred (orgRole reads
// it) ONLY once the INVITED party ACCEPTS with that token. Pre-naming a raw handle a manager does not control grants
// nothing. Mirrors auth's mint/deliver/consume (single-use via storeDo, const-time secret compare).
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { nextId, orgRole, problem, requireIdentity, sendJSON, storeDelete, storeDo, storeGet, storePut, storeValues, testNow, throttle } from '../../core/runtime.js';
import { digestHex } from '../../parts/digest.js';
import { envInt } from '../../parts/env_int.js';
import { claimOnce } from '../../parts/idempotent_claim.js';
import { paginate } from '../../parts/paginate.js';
import { isWellFormed } from '../../parts/well_formed.js';

// state in store: seq 'orgs_org' · ns 'orgs_records' slug -> {id, slug, owner, status} · ns 'orgs_members'
// `${slug}\x1f${handle}` -> {org, handle, role, status, secret_hash?, invite_exp?} (role granted iff
// status==='active'; the core orgRole seam reads it) · ns 'orgs_outbox' `${slug}\x1f${handle}` -> the invite token

const ROLE_OWNER = 'owner';
const ROLE_ADMIN = 'admin';
const ROLE_MEMBER = 'member';
const MANAGER_ROLES = [ROLE_OWNER, ROLE_ADMIN]; // may manage membership / archive
const ASSIGNABLE_ROLES = [ROLE_ADMIN, ROLE_MEMBER]; // a manager may grant only these (NEVER owner — see transfer)
const PENDING = 'pending'; // an invite is PENDING until ACCEPTED
const ACTIVE = 'active'; // only an ACTIVE member has a role (orgRole returns it)
const REMOVED = 'removed'; // a SOFT-delete tombstone: orgRole grants only status==='active', so it is inert

const memberKey = (slug, handle) => `${slug}\x1f${handle}`; // the ONE membership key the seam reads (\x1f un-forgeable)
function ctEqual(a, b) { // constant-time hex compare (mirrors auth.ctEqual)
  const ba = Buffer.from(a, 'utf8'); const bb = Buffer.from(b, 'utf8');
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}
function inviteTTL() {
  return envInt(process.env.ORGS_INVITE_TTL_SECONDS, 604800, 1); // 7 days; env-tunable, floored at 1s
}
async function deliverInvite(slug, handle, token) { // delivery seam (mirrors auth): the token, never logged; key is \x1f-joined (un-forgeable, NOT ':') so a "<victim>:<x>" owner can't clobber another org's delivery
  await storePut('orgs_outbox', `${slug}\x1f${handle}`, { to: handle, kind: 'org-invite', token, org: slug });
}

const ORGS_AUDIT_NS = 'orgs_decisions'; // domain-local decision log (Path-2: the authz surface owns its own trail)

// denyAuditBudget — how many DENY rows one subject may append per window before the audit-write becomes a no-op (the
// deny-audit flood wall): generous so a real attack leaves a forensic trail while an attacker can no longer pump
// orgs_decisions unbounded. Env-tunable; floored at 1.
function denyAuditBudget() {
  return [envInt(process.env.ORGS_DENY_AUDIT_LIMIT, 50, 1), envInt(process.env.ORGS_DENY_AUDIT_WINDOW, 3600, 1)];
}

// orgsAudit appends a decision record. APP_ORGS_AUDIT: 'off' | 'deny' (DEFAULT — every authz DENIAL + every successful
// ownership/membership MUTATION: the ASVS 7.1.3/7.2.2 'who took over this org' trail) | 'all' (reserved: + reads).
async function orgsAudit(req, subject, kind, target, org, result, reason) {
  let mode = (process.env.APP_ORGS_AUDIT || '').trim().toLowerCase();
  if (mode !== 'off' && mode !== 'all') mode = 'deny'; // unknown / empty / typo -> fail SAFE to the 'deny' default
  if (mode === 'off') return;
  const now = testNow(req);
  if (result === 'deny') {
    // THROTTLE the DENY-audit write per (ORG, subject) (deny-audit flood + cross-org isolation): the key includes the ORG
    // (\x1f-joined, un-forgeable) so noise an attacker generates on a DECOY org can NOT blind a VICTIM org's trail —
    // each org keeps its own first-N forensic denials. The deny-audit CALL still precedes the 403 in the source
    // (the denial audit still fires) — a RUNTIME budget INSIDE orgsAudit. Success audits are NEVER throttled.
    const [limit, window] = denyAuditBudget();
    if (!(await throttle(`orgs:deny-audit:${org}\x1f${subject}`, limit, window, now))) return; // over budget -> no-op (bounded)
  }
  const id = await nextId('orgs_decision');
  await storePut(ORGS_AUDIT_NS, String(id), { id, subject, kind, target, org, result, reason, ts: now });
}

async function loadOrg(req, res, params) {
  if (!isWellFormed(params.slug)) {
    problem(res, 422, 'the slug must be non-empty with no control characters');
    return null;
  }
  const org = await storeGet('orgs_records', params.slug);
  if (org === undefined) {
    problem(res, 404, 'org not found');
    return null;
  }
  return org;
}

// manage: the shared authz chokepoint for path-scoped management routes. authn (401) -> slug validation (422) ->
// load (404) -> orgRole in `allowed` (403), all BEFORE the body fields are validated — identical ×3 with python's
// Depends(manage_dep). Returns the loaded org + caller, or null after sending the right status.
async function manage(req, res, params, allowed) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return null;
  const org = await loadOrg(req, res, params);
  if (org === null) return null;
  if (!allowed.includes(await orgRole(params.slug, caller))) {
    await orgsAudit(req, caller, 'manage', '', params.slug, 'deny', 'not-a-manager'); // ASVS 7.1.3: log the failed authz
    problem(res, 403, 'this operation requires an org owner or admin');
    return null;
  }
  return { org, caller };
}

export async function orgsCreate(req, res, params, body) {
  // the body is already parsed by the runtime (a malformed body 422'd before here); requireIdentity then validates.
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  if (!body || !isWellFormed(body.slug)) return problem(res, 422, 'invalid body'); // owner is the TOKEN, not the body
  if ((await storeGet('orgs_records', body.slug)) !== undefined) return problem(res, 409, 'slug taken'); // fast path
  const rec = { id: await nextId('orgs_org'), slug: body.slug, owner: caller, status: 'active' };
  const settled = await claimOnce('orgs_records', body.slug, rec);
  if (settled.id !== rec.id) return problem(res, 409, 'slug taken'); // lost the race — never overwrite the winner
  // SINGLE-SOURCE OWNERSHIP: the owner is DERIVED from orgs_records.owner (the core orgRole seam reads it) — we do NOT
  // write an 'owner' membership row, so there can never be two owners. orgs_members holds only admin|member.
  await orgsAudit(req, caller, 'create', body.slug, body.slug, 'create', 'ok'); // ownership-event trail
  sendJSON(res, 201, settled);
}

export async function orgsGet(req, res, params) {
  // read is MEMBER-SCOPED: authn (401) -> load (404) -> membership. A non-member is
  // 404 — byte-identical to a missing slug (not-yours == not-found, mirroring api_keys load), so existence never
  // leaks cross-org. AUTH first (mirrors manage): a no-token probe is 401 before the load.
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const org = await loadOrg(req, res, params);
  if (org === null) return;
  if ((await orgRole(params.slug, caller)) === undefined) {
    return problem(res, 404, 'org not found'); // not a member -> same 404 as a missing org (existence never leaks)
  }
  sendJSON(res, 200, org);
}

export async function orgsTransfer(req, res, params, body) {
  const ctx = await manage(req, res, params, [ROLE_OWNER]); // ONLY the current owner may transfer (authz before validation)
  if (ctx === null) return;
  if (!body || !isWellFormed(body.owner)) return problem(res, 422, 'invalid body');
  const caller = ctx.caller;
  const newOwner = body.owner;
  // the ownership swap is a SINGLE-KEY ATOMIC storeDo() on orgs_records that RE-ASSERTS the caller is STILL the owner
  // INSIDE the lock — manage()'s owner check was read before the lock, so two concurrent transfers from one owner
  // would otherwise both write (the two-owner race, F1). The loser's re-check fails -> 409 (never a silent overwrite).
  const result = await storeDo('orgs_records', params.slug, (cur) => {
    if (cur === undefined || cur.owner !== caller) return [undefined, null]; // ownership changed concurrently -> no write
    const next = { ...cur, owner: newOwner };
    return [next, next];
  });
  if (result === null) return problem(res, 409, 'ownership changed concurrently');
  // maintain "orgs_members holds ONLY non-owner roles; the owner is solely orgs_records.owner": the NEW owner is the
  // DERIVED owner (tombstone any membership row they had); the OLD owner (caller) is demoted to an ACTIVE 'admin' (an
  // existing owner is a real, already-proven identity — no invite/accept needed). BOTH projections go through the
  // storeDo() seam so they SERIALIZE with a concurrent orgsRemoveMember(caller) on the SAME member key — deterministic
  // last-writer-wins, no resurrection of a hard-deleted row (invariant I18). [rmw-safe]
  await storeDo('orgs_members', memberKey(params.slug, newOwner), (cur) =>
    cur === undefined ? [undefined, null] : [{ ...cur, status: REMOVED }, null]);
  if (newOwner !== caller) {
    await storeDo('orgs_members', memberKey(params.slug, caller), () =>
      [{ org: params.slug, handle: caller, role: ROLE_ADMIN, status: ACTIVE }, null]);
  }
  await orgsAudit(req, caller, 'transfer', newOwner, params.slug, 'transfer', 'ok'); // the OWNERSHIP-CHANGE event (highest value)
  sendJSON(res, 200, result);
}

export async function orgsArchive(req, res, params) {
  const ctx = await manage(req, res, params, MANAGER_ROLES); // owner|admin may archive
  if (ctx === null) return;
  // monotonic + idempotent: 'archived' is TERMINAL. storeDo() reads the CURRENT record INSIDE the lock, so a concurrent
  // transfer's owner change is PRESERVED — a bare snapshot->put would clobber the owner back.
  const archived = await storeDo('orgs_records', params.slug, (cur) =>
    cur === undefined ? [undefined, null] : [{ ...cur, status: 'archived' }, { ...cur, status: 'archived' }]);
  if (archived === null) return problem(res, 404, 'org not found');
  await orgsAudit(req, ctx.caller, 'archive', params.slug, params.slug, 'archive', 'ok');
  sendJSON(res, 200, archived);
}

export async function orgsAddMember(req, res, params, body) {
  const ctx = await manage(req, res, params, MANAGER_ROLES); // owner|admin only (authz before validation)
  if (ctx === null) return;
  if (!body || !isWellFormed(body.handle) || !isWellFormed(body.role)) return problem(res, 422, 'invalid body');
  if (!ASSIGNABLE_ROLES.includes(body.role)) {
    // ownership moves ONLY via transfer — a manager can never mint a second owner through add-member
    await orgsAudit(req, ctx.caller, 'add-member', body.handle, params.slug, 'deny', 'role-not-assignable');
    return problem(res, 403, "role must be 'admin' or 'member' (ownership transfers only)");
  }
  // INVITE: the role is NOT granted here — it is PENDING until the invited party ACCEPTS with the single-use token
  // (closes the member-identity escalation). Re-inviting an ALREADY-ACTIVE member updates the role in place (no new
  // token). All in ONE atomic storeDo() on the member key. The token is minted OUTSIDE storeDo (its fn must be pure).
  const now = testNow(req);
  const token = `${randomBytes(9).toString('base64url')}.${randomBytes(24).toString('base64url')}`;
  const secretHash = digestHex(token);
  const exp = now + inviteTTL();
  let status = null;
  await storeDo('orgs_members', memberKey(params.slug, body.handle), (cur) => {
    if (cur !== undefined && cur.status === ACTIVE) {
      status = ACTIVE; // already proven -> just (re)set the role, no token
      return [{ ...cur, role: body.role }, null];
    }
    status = PENDING; // new or still-pending -> (re)issue a single-use invite
    return [{ org: params.slug, handle: body.handle, role: body.role, status: PENDING, secret_hash: secretHash, invite_exp: exp }, null];
  });
  if (status === PENDING) {
    await deliverInvite(params.slug, body.handle, token); // the token reaches the invitee, never the inviter
    await orgsAudit(req, ctx.caller, 'invite', body.handle, params.slug, 'ok', 'pending');
  } else {
    await orgsAudit(req, ctx.caller, 'add-member', body.handle, params.slug, 'grant', 'ok');
  }
  sendJSON(res, 201, { slug: params.slug, handle: body.handle, role: body.role, status });
}

export async function orgsAccept(req, res, params, body) {
  // ACCEPT a pending invite — authenticated; the membership is keyed on the CALLER (== the invited handle by
  // construction), so a token issued for handle X can only be redeemed by the authenticated subject X. SINGLE-USE +
  // const-time secret match + unexpired, all atomic via storeDo (mirrors auth consume). authn (401) -> load (404) ->
  // the body+token. A wrong/absent secret is 403, a non-pending/absent membership is 404, an expired is 410.
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const org = await loadOrg(req, res, params); // honest 404 on a missing org (load before the lookup)
  if (org === null) return;
  if (!body || !isWellFormed(body.token)) return problem(res, 422, 'invalid body');
  const now = testNow(req);
  let outcome = 'missing';
  await storeDo('orgs_members', memberKey(params.slug, caller), (cur) => {
    if (cur === undefined || cur.status !== PENDING) { outcome = 'missing'; return [undefined, null]; } // -> 404
    if (now >= cur.invite_exp) { outcome = 'expired'; return [undefined, null]; } // expiry beats availability -> 410
    if (!cur.secret_hash || !ctEqual(digestHex(body.token), cur.secret_hash)) {
      outcome = 'badtoken'; return [undefined, null]; // wrong secret -> 403 (do NOT activate, do NOT consume)
    }
    outcome = 'ok';
    return [{ org: params.slug, handle: caller, role: cur.role, status: ACTIVE }, null]; // activate + clear secret
  });
  if (outcome === 'missing') {
    await orgsAudit(req, caller, 'accept', caller, params.slug, 'deny', 'no-pending-invite');
    return problem(res, 404, 'invitation not found');
  }
  if (outcome === 'expired') {
    await orgsAudit(req, caller, 'accept', caller, params.slug, 'deny', 'invite-expired');
    return problem(res, 410, 'invitation expired');
  }
  if (outcome === 'badtoken') {
    await orgsAudit(req, caller, 'accept', caller, params.slug, 'deny', 'invalid-token');
    return problem(res, 403, 'invalid invitation token');
  }
  const member = await storeGet('orgs_members', memberKey(params.slug, caller));
  await orgsAudit(req, caller, 'accept', caller, params.slug, 'accept', 'ok');
  sendJSON(res, 200, { slug: params.slug, handle: caller, role: member.role, status: ACTIVE });
}

export async function orgsRemoveMember(req, res, params) {
  const ctx = await manage(req, res, params, MANAGER_ROLES); // owner|admin only (authz before path validation)
  if (ctx === null) return;
  if (!isWellFormed(params.handle)) {
    return problem(res, 422, 'the member handle must be non-empty with no control characters');
  }
  if (params.handle === ctx.org.owner) {
    await orgsAudit(req, ctx.caller, 'remove-member', params.handle, ctx.org.slug, 'deny', 'owner-not-removable');
    return problem(res, 403, 'the owner cannot be removed (transfer ownership first)'); // never ownerless
  }
  // SOFT delete: tombstone the row (status='removed') through the storeDo() seam — NOT a hard storeDelete. This
  // SERIALIZES with a concurrent transfer-demotion on the SAME member key (deterministic last-writer-wins), so a
  // confirmed-removed member can never be resurrected by the demotion's write (invariant I18). orgRole grants only
  // status==='active', so the tombstone is inert. Removing an absent member is a no-op.
  await storeDo('orgs_members', memberKey(ctx.org.slug, params.handle), (cur) =>
    cur === undefined ? [undefined, null] : [{ ...cur, status: REMOVED }, null]);
  await orgsAudit(req, ctx.caller, 'remove-member', params.handle, ctx.org.slug, 'remove', 'ok');
  sendJSON(res, 200, { slug: ctx.org.slug, handle: params.handle, removed: true });
}

export async function orgsListMine(req, res, params) {
  // MY orgs: the caller's own — those they OWN (orgs_records.owner === caller) or are an ACTIVE member of. Authenticated
  // (the authenticated-read wall); intrinsically caller-scoped. Scan records in rowid order (stable + identical ×3); paginate.
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  // orgRole is async, and Array.filter does NOT await its predicate (an async predicate returns an always-truthy
  // Promise), so resolve membership in a sequential loop that preserves rowid order.
  const mine = [];
  for (const r of (await storeValues('orgs_records'))) {
    if (r.owner === caller || (await orgRole(r.slug, caller)) !== undefined) mine.push(r);
  }
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(mine, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function orgsListMembers(req, res, params) {
  // MEMBER-SCOPED: authn (401) -> load (404) -> ACTIVE membership; a non-member is 404 BYTE-IDENTICAL
  // to a missing slug (existence never leaks, like orgsGet). The roster = the DERIVED owner (orgs_records.owner, role 'owner' —
  // no membership row) + every ACTIVE orgs_members row for this slug (pending invites are NOT listed). Stable rowid order ×3; paginated.
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const org = await loadOrg(req, res, params);
  if (org === null) return;
  if ((await orgRole(params.slug, caller)) === undefined) {
    return problem(res, 404, 'org not found'); // not a member -> same 404 as a missing org (existence never leaks)
  }
  const roster = [{ handle: org.owner, role: ROLE_OWNER }];
  for (const m of await storeValues('orgs_members')) {
    if (m.org === params.slug && m.status === ACTIVE) roster.push({ handle: m.handle, role: m.role });
  }
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(roster, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function orgsListInvites(req, res, params) {
  // MANAGER-ONLY (owner|admin, the same chokepoint as the membership mutations): the PENDING invites for this slug —
  // (handle, role, invite_exp) ONLY, NEVER the secret_hash/token (the invite secret reaches the invitee alone). Paginated.
  const ctx = await manage(req, res, params, MANAGER_ROLES);
  if (ctx === null) return;
  const invites = [];
  for (const m of await storeValues('orgs_members')) {
    if (m.org === params.slug && m.status === PENDING) invites.push({ handle: m.handle, role: m.role, invite_exp: m.invite_exp });
  }
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(invites, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function orgsLeave(req, res, params) {
  // SELF-leave, MEMBER-SCOPED like orgsGet/orgsListMembers: authn (401) -> load (404) -> ACTIVE membership. A NON-member
  // (or already-left) is 404 BYTE-IDENTICAL to a missing slug — existence never leaks via leave's 200/404, and a non-member
  // can't pump no-op 'leave' rows into the decision log (only a REAL member's leave is audited — no existence oracle,
  // no no-op audit flood). The OWNER cannot leave (records-owner; would orphan the org) -> 409 (never-ownerless, mirroring
  // owner-not-removable; audited — though a 409 itself needs no denial audit). A re-leave by the removed caller is 404.
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const org = await loadOrg(req, res, params);
  if (org === null) return;
  if ((await orgRole(params.slug, caller)) === undefined) {
    return problem(res, 404, 'org not found'); // not a member -> same 404 as a missing org (no existence leak, no no-op audit)
  }
  if (caller === org.owner) {
    await orgsAudit(req, caller, 'leave', caller, params.slug, 'deny', 'owner-cannot-leave');
    return problem(res, 409, 'the owner cannot leave (transfer ownership first)');
  }
  await storeDelete('orgs_members', memberKey(params.slug, caller)); // only a real ACTIVE member reaches here
  await orgsAudit(req, caller, 'leave', caller, params.slug, 'leave', 'ok');
  sendJSON(res, 200, { slug: params.slug, handle: caller, left: true });
}
