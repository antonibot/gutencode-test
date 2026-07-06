// audit_log — an append-only, tamper-evident evidence log (the hash-chain shape). Every event's hash is sha256
// over the COMPLETE record (prev · id · at · actor · action — the two well_formed fields pre-hashed so the join
// stays injective), rooted at GENESIS, so editing ANY past field breaks every later link. The
// dangerous property is CHAIN INTEGRITY: the append is ONE atomic read-modify-write on the chain head through
// storeDo — two processes appending concurrently get sequential ids on one chain, never a fork. Immutability is
// by construction (no update or delete route). /verify re-derives the whole chain and reports ANY damage loudly
// — including self-damage (a crash between head advance and event write leaves a visible hole; an evidence log
// must show its own wounds). Store names and shapes match the python/go impls.
//
// WRITES ARE SERVICE-ONLY, THE DISCLOSING READ ADMIN-ONLY: an anonymous append is log-poisoning (the chain
// stays "valid" over forged rows) and the event LIST discloses every subject's events. append is gated by the
// trusted SERVICE seam (core.requireService) — events are ingested by app services on a user's behalf, not posted
// by end users; list requires the 'admin' role (core.requireAdmin). Both call the seam FIRST in the handler (the
// runtime already parsed the body), resolved BEFORE the strict validation — so an ill-typed body with no token is
// 401, ×3. verify stays OPEN: the integrity probe returns only {valid, count, detail} — no event contents.
import { problem, requireAdmin, requireService, sendJSON, storeDo, storeGet, storePut, storeValues, testNow } from '../core/runtime.js';
import { digestHex } from '../parts/digest.js';
import { paginate } from '../parts/paginate.js';
import { isWellFormed } from '../parts/well_formed.js';

// state in store: ns "audit_log_chain" key "head" -> {id, hash} (the RMW target — the ONLY mutable row) ·
// ns "audit_log_events" String(id) -> {id, at, actor, action, prev, hash} (append-only; WHO·WHAT·WHEN, all hashed)

// the chain link over the COMPLETE record, INJECTIVE: prev/id/at are colon-free; the two ADVERSARIAL well_formed
// fields (actor, action — can contain ':') are PRE-HASHED to colon-free 64-hex FIRST, so digestHex's ':'-join stays
// unambiguous (the delimiter lesson — a bare digestHex(prev,id,at,actor,action) is collision-prone).
const link = (prev, id, at, actor, action) => digestHex(prev, id, at, digestHex(actor), digestHex(action));

export async function auditLogAppend(req, res, params, body) {
  // mutation-auth: service — audit events are ingested by the trusted backend (a SERVICE) on a user's behalf, never
  // posted by end users, so the append is gated by core.requireService, NOT requireAdmin. The `mutation-auth: service`
  // declaration + the requireService call sit in the same handler, so the two cannot drift apart.
  if (requireService(req, res) === null) return; // AUTH (runtime already parsed the body); strict check follows, ×3
  if (!body || !isWellFormed(body.actor) || !isWellFormed(body.action)) return problem(res, 422, 'invalid body');
  // WHEN: the timestamp comes from the core CLOCK seam — deterministic under APP_TEST_CLOCK (?now=), the real wall
  // clock in prod (a client can't forge prod time). COVERED BY THE HASH below, so a backdate is tamper-evident.
  const at = testNow(req);
  // THE APPEND: one atomic claim on the head — the id is chain-derived (head.id + 1) and computed INSIDE the
  // exclusive transaction, so two processes can never build on the same predecessor. The fn stays PURE; the
  // event row is written right after the head advances.
  const event = await storeDo('audit_log_chain', 'head', (head) => {
    const prevId = head ? head.id : 0;
    const prevHash = head ? head.hash : 'GENESIS';
    const e = { id: prevId + 1, at, actor: body.actor, action: body.action, prev: prevHash,
      hash: link(prevHash, prevId + 1, at, body.actor, body.action) };
    return [{ id: e.id, hash: e.hash }, e];
  });
  await storePut('audit_log_events', String(event.id), event);
  sendJSON(res, 201, event);
}

export async function auditLogList(req, res) {
  // ADMIN-ONLY read: the full event list discloses every subject's events — a read the mutation gate won't catch,
  // so it is hand-gated. requireAdmin FIRST, before pagination; no token 401, non-admin 403 (auth precedence
  // PRESERVED). verify stays OPEN. BOUNDED via the shared paginate part — never an unbounded full dump. Events
  // are the hash-chain rows in stable id order (storeValues is rowid-stable == monotonic id order).
  if ((await requireAdmin(req, res)) === null) return;
  // unscoped-read: admin — the event log is GLOBAL by design (every subject's events); requireAdmin above is the
  // explicit privileged gate. The whole hash-chain IS the trail — there is no per-caller owner field.
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate((await storeValues('audit_log_events')), q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function auditLogVerify(req, res) {
  // read-scope: public — integrity probe, returns only {valid, count, detail}, never event contents (already documented as intentionally open).
  // re-derive the WHOLE chain from GENESIS: every id 1..head present, every link correct. Any deviation —
  // a tampered action, a missing event (crash damage), a forged head — is reported loudly, never smoothed.
  const head = await storeGet('audit_log_chain', 'head');
  const count = head ? head.id : 0;
  let prev = 'GENESIS';
  for (let id = 1; id <= count; id++) {
    const event = await storeGet('audit_log_events', String(id));
    if (event === undefined) {
      return sendJSON(res, 200, { valid: false, count, detail: `event ${id} missing (hole in the chain)` });
    }
    if (event.prev !== prev || event.hash !== link(prev, id, event.at, event.actor, event.action)) {
      return sendJSON(res, 200, { valid: false, count, detail: `chain broken at event ${id}` });
    }
    prev = event.hash;
  }
  if (head && head.hash !== prev) {
    return sendJSON(res, 200, { valid: false, count, detail: 'head does not match the derived chain' });
  }
  sendJSON(res, 200, { valid: true, count, detail: 'chain intact' });
}
