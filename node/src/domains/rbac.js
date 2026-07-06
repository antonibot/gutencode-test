// rbac — access control, deny-by-default (the OWASP ASVS V8 / NIST RBAC shape), governed by the AUTHENTICATED
// identity. RBAC (subject -> assigned roles -> permissions over a fixed code-reviewed policy, least-privilege
// union) + FLAT relation tuples (ACL-style): a decision is allowed ONLY on an exact (subject, relation, object)
// match — no wildcard, no prefix, no userset rewrite. (Userset rewrites / hierarchy are deliberately OUT OF SCOPE
// in v1 — a documented divergence: NIST Core/Flat RBAC + ACL is a valid level.)
//
// IDENTITY: every route is deny-by-default authenticated (no token -> 401). DECISION reads (/can, /check)
// are CALLER-SCOPED — the subject is the authenticated caller (the core requireIdentity seam), so a caller asks
// only about THEIR OWN access. MUTATIONS (/roles, /relations) are ADMIN-GATED (ARBAC — role administration is
// itself a permissioned op): the caller must be an rbac admin — holding the 'admin' role, provisioned OUT-OF-BAND
// by the operator (no env-NAME seed; a claimable username was a privilege-escalation hole). A non-admin is
// 403, so no caller can self-escalate. With no admin provisioned, mutations are LOCKED (deny-by-default); under
// APP_TEST_SESSIONS=1 a fixed test admin is recognized, inert in prod. The grantee/relation/object remain free
// identifiers, so the central
// well_formed rule is KEPT (key-forgery protection on the \x1f delimiter). Assignment appends through the ATOMIC
// storeDo seam. Store namespaces match the python/go impls so decisions are identical ×3 and survive a restart.
import { isAdmin, nextId, problem, requireIdentity, sendJSON, storeDelete, storeDo, storeGet, storePut, storeValues, testNow } from '../core/runtime.js';
import { paginate } from '../parts/paginate.js';
import { isWellFormed } from '../parts/well_formed.js';

// the role policy is POLICY (fixed, code-reviewed), not per-request state — so it stays a constant.
const ROLE_PERMS = {
  admin: ['read', 'write', 'delete'],
  editor: ['read', 'write'],
  viewer: ['read'],
};
// durable state: ns "rbac_roles" subject -> [role, ...] · ns "rbac_rel" "subject\x1frelation\x1fobject" -> true

// the CENTRAL identifier rule (well_formed part): non-empty, no control characters. For rbac this is also key
// forgery protection — the unit separator is the tuple-key delimiter, so a name carrying it could forge the key
// of a DIFFERENT tuple. Rejected at the door, identically in all three languages.
const relKey = (subject, relation, object) => [subject, relation, object].join('\x1f'); // ONE exact key per tuple

// the ADMIN check is the CORE seam (isAdmin): rbac is the management SURFACE that WRITES roles, core owns the
// cross-cutting NOTION (it reads rbac_roles) so non-rbac admin-only domains gate WITHOUT importing rbac (the
// boundary rule: domains -> core only). The ARBAC rule, the out-of-band prod bootstrap, and the inert test admin
// all live there — ONE definition for the whole app.

const RBAC_AUDIT_NS = 'rbac_decisions';

// Path-2 decision audit (domain-local — the authz component owns its own log). APP_RBAC_AUDIT: 'off' | 'deny'
// (default — log denials, the ASVS 16.3.2 L2 MUST) | 'all'. Append-only, ordered by id, ts via the clock seam.
async function rbacAudit(req, subject, kind, action, object, result, reason) {
  let mode = (process.env.APP_RBAC_AUDIT || '').trim().toLowerCase();
  if (mode !== 'off' && mode !== 'all') mode = 'deny'; // unknown / empty / typo -> fail SAFE to the "deny" default
  if (mode === 'off' || (mode === 'deny' && result !== 'deny')) return;
  const id = await nextId('rbac_decision');
  await storePut(RBAC_AUDIT_NS, String(id), { id, subject, kind, action, object, result, reason, ts: testNow(req) });
}

export async function rbacAssign(req, res, params, body) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  if (!(await isAdmin(caller))) {
    await rbacAudit(req, caller, 'assign', '', '', 'deny', 'not-admin'); // audit the denied attempt (ASVS L2)
    return problem(res, 403, 'rbac administration requires the admin role'); // ARBAC
  }
  if (!body || !isWellFormed(body.subject) || !isWellFormed(body.role)) {
    return problem(res, 422, 'invalid body');
  }
  if (!(body.role in ROLE_PERMS)) {
    await rbacAudit(req, caller, 'assign', body.role, body.subject, 'deny', 'unknown-role');
    return sendJSON(res, 201, { allowed: false }); // unknown role -> deny, loudly (never silently grant)
  }
  // ATOMIC append: a bare get-then-put RACES; storeDo holds the write lock across read+write; the callback is
  // pure and idempotent (re-assigning the same role returns undefined -> no write).
  await storeDo('rbac_roles', body.subject, (cur) => {
    const roles = cur || [];
    return roles.includes(body.role) ? [undefined, null] : [[...roles, body.role], null];
  });
  await rbacAudit(req, caller, 'assign', body.role, body.subject, 'grant', 'ok'); // admin-event trail (all mode)
  sendJSON(res, 201, { allowed: true });
}

export async function rbacCan(req, res) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const permission = new URL(req.url, 'http://localhost').searchParams.get('permission') || '';
  if (!isWellFormed(permission)) {
    return problem(res, 422, 'permission is required');
  }
  // caller-scoped + deny-by-default: allowed iff some role ASSIGNED TO THE CALLER grants the permission
  const roles = (await storeGet('rbac_roles', caller)) || [];
  const allowed = roles.some((role) => (ROLE_PERMS[role] || []).includes(permission));
  await rbacAudit(req, caller, 'can', permission, '', allowed ? 'allow' : 'deny', allowed ? 'role-union' : 'deny-by-default');
  sendJSON(res, 200, { allowed });
}

export async function rbacGrant(req, res, params, body) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  if (!(await isAdmin(caller))) {
    await rbacAudit(req, caller, 'grant', '', '', 'deny', 'not-admin'); // audit the denied attempt (ASVS L2)
    return problem(res, 403, 'rbac administration requires the admin role'); // ARBAC
  }
  if (!body || !isWellFormed(body.subject) || !isWellFormed(body.relation) || !isWellFormed(body.object)) {
    return problem(res, 422, 'invalid body');
  }
  // store the tuple components AS the value (self-describing) so listing can filter via storeValues; the existence
  // check (storeGet !== undefined) is unchanged.
  await storePut('rbac_rel', relKey(body.subject, body.relation, body.object),
    { subject: body.subject, relation: body.relation, object: body.object });
  await rbacAudit(req, caller, 'grant', body.relation, body.subject, 'grant', 'ok'); // admin-event trail (all mode)
  sendJSON(res, 201, { allowed: true });
}

export async function rbacCheck(req, res) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const q = new URL(req.url, 'http://localhost').searchParams;
  const relation = q.get('relation') || '';
  const object = q.get('object') || '';
  if (!isWellFormed(relation) || !isWellFormed(object)) {
    return problem(res, 422, 'relation and object are required');
  }
  // caller-scoped + deny-by-default: the EXACT (caller, relation, object) tuple must exist (no wildcard/prefix)
  const allowed = (await storeGet('rbac_rel', relKey(caller, relation, object))) !== undefined;
  await rbacAudit(req, caller, 'check', relation, object, allowed ? 'allow' : 'deny', allowed ? 'tuple-match' : 'deny-by-default');
  sendJSON(res, 200, { allowed });
}

export async function rbacRevokeRole(req, res, params, body) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  if (!(await isAdmin(caller))) {
    await rbacAudit(req, caller, 'revoke-role', '', '', 'deny', 'not-admin'); // audit the denied attempt (ASVS L2)
    return problem(res, 403, 'rbac administration requires the admin role'); // ARBAC
  }
  if (!body || !isWellFormed(body.subject) || !isWellFormed(body.role)) {
    return problem(res, 422, 'invalid body');
  }
  // ATOMIC remove via storeDo; idempotent — removing an absent role is a no-op that returns removed:false.
  const removed = await storeDo('rbac_roles', body.subject, (cur) => {
    const roles = cur || [];
    if (!roles.includes(body.role)) return [undefined, false]; // absent -> no write
    return [roles.filter((r) => r !== body.role), true];
  });
  await rbacAudit(req, caller, 'revoke-role', body.role, body.subject, 'revoke', 'ok'); // admin-event trail (all mode)
  sendJSON(res, 200, { removed });
}

export async function rbacRevokeRelation(req, res, params, body) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  if (!(await isAdmin(caller))) {
    await rbacAudit(req, caller, 'revoke-relation', '', '', 'deny', 'not-admin'); // audit the denied attempt (ASVS L2)
    return problem(res, 403, 'rbac administration requires the admin role'); // ARBAC
  }
  if (!body || !isWellFormed(body.subject) || !isWellFormed(body.relation) || !isWellFormed(body.object)) {
    return problem(res, 422, 'invalid body');
  }
  const key = relKey(body.subject, body.relation, body.object);
  const existed = (await storeGet('rbac_rel', key)) !== undefined; // best-effort was-present signal
  await storeDelete('rbac_rel', key); // idempotent: no-op if the tuple is absent
  await rbacAudit(req, caller, 'revoke-relation', body.relation, body.subject, 'revoke', 'ok'); // admin-event trail (all mode)
  sendJSON(res, 200, { removed: existed });
}

export async function rbacListRoles(req, res) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const q = new URL(req.url, 'http://localhost').searchParams;
  const target = q.get('subject') || caller; // default to the caller's own roles
  if (target !== caller && !(await isAdmin(caller))) {
    await rbacAudit(req, caller, 'list-roles', '', '', 'deny', 'not-admin'); // ASVS L2 — audit the denied list attempt
    return problem(res, 403, 'rbac administration requires the admin role');
  }
  if (!isWellFormed(target)) return problem(res, 422, 'subject is required');
  const roles = (await storeGet('rbac_roles', target)) || [];
  const { items, next, ok } = paginate(roles, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function rbacListRelations(req, res) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const q = new URL(req.url, 'http://localhost').searchParams;
  const subject = q.get('subject') || '';
  const object = q.get('object') || '';
  // a caller may list THEIR OWN forward tuples; another subject's tuples or the inverse (object=) is an admin op.
  const selfOK = subject !== '' && subject === caller && object === '';
  if (!selfOK && !(await isAdmin(caller))) {
    await rbacAudit(req, caller, 'list-relations', '', '', 'deny', 'not-admin'); // ASVS L2 — audit the denied list attempt
    return problem(res, 403, 'rbac administration requires the admin role');
  }
  if (subject !== '' && !isWellFormed(subject)) return problem(res, 422, 'invalid subject');
  if (object !== '' && !isWellFormed(object)) return problem(res, 422, 'invalid object');
  if (subject === '' && object === '') return problem(res, 422, 'a subject or object filter is required'); // never a full dump
  const filtered = (await storeValues('rbac_rel')).filter(
    (t) => (subject === '' || t.subject === subject) && (object === '' || t.object === object),
  );
  const { items, next, ok } = paginate(filtered, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function rbacListDecisions(req, res) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  if (!(await isAdmin(caller))) {
    await rbacAudit(req, caller, 'list-decisions', '', '', 'deny', 'not-admin'); // ASVS L2 — audit the denied list attempt
    return problem(res, 403, 'rbac administration requires the admin role'); // admin-only
  }
  const q = new URL(req.url, 'http://localhost').searchParams;
  const subject = q.get('subject') || '';
  if (subject !== '' && !isWellFormed(subject)) return problem(res, 422, 'invalid subject');
  const rows = (await storeValues(RBAC_AUDIT_NS)).filter((d) => subject === '' || d.subject === subject); // id-ordered
  const { items, next, ok } = paginate(rows, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}
