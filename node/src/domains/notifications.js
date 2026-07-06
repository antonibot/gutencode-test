// notifications — in-app notifications with three dangerous properties, all proven:
// (1) SENDER IS THE AUTHENTICATED CALLER: sending requires a valid bearer token (no token -> 401) and the
// notification's `from` is STAMPED from the authenticated subject (the core requireIdentity seam) — NEVER a
// caller-supplied body field, so a caller cannot forge the sender. (2) RECIPIENT SCOPING: a notification belongs
// to its recipient; listing or acting as anyone else returns 404, byte-indistinguishable from missing (existence
// never leaks), keyed by the AUTHENTICATED identity from the core requireIdentity seam — NOT a caller-supplied
// param, so a client cannot read another's by setting a header. Deny-by-default. (3) MONOTONIC READ-STATE: unread
// -> read only; marking read is idempotent (a TERMINAL-value write — concurrent marks converge, the billing-cancel
// class) and a read notification never returns to unread. Store names and shapes match the python/go impls (the
// `from` field included); the read-state survives a restart.
import { intParam, nextId, problem, requireIdentity, sendJSON, storeGet, storePut, storeValues } from '../core/runtime.js';
import { paginate } from '../parts/paginate.js';
import { isWellFormed } from '../parts/well_formed.js';

// state in store: seq "notifications_item" · ns "notifications_items" String(id) -> {id, from, to, message, status}
// `from` is the AUTHENTICATED sender (requireIdentity), never a body field — the sender can't be forged.

export async function notificationsSend(req, res, params, body) {
  // auth FIRST (the runtime already parsed the body), then field validation. The body carries only
  // {to, message} — a `from` in the body is IGNORED; the sender is stamped from the token, never client-set.
  const sender = await requireIdentity(req, res);
  if (sender === null) return; // no/invalid token -> 401, before any write
  if (!body || !isWellFormed(body.to) || typeof body.message !== 'string' || body.message === '') {
    return problem(res, 422, 'invalid body');
  }
  const nid = await nextId('notifications_item'); // atomic, durable; a crash before the put loses the id (a gap)
  const notif = { id: nid, from: sender, to: body.to, message: body.message, status: 'unread' }; // created UNREAD
  await storePut('notifications_items', String(nid), notif);
  sendJSON(res, 201, notif);
}

export async function notificationsList(req, res) {
  const who = await requireIdentity(req, res);
  if (who === null) return;
  // SCOPED read: only the recipient's rows ever leave the store, in id order (deterministic x3)
  const rows = (await storeValues('notifications_items')).filter((n) => n.to === who).sort((a, b) => a.id - b.id);
  // BOUNDED: the owner-scoped list rides the shared paginate seam (clamps to PAGE_MAX) so a busy inbox can never
  // become a soft-DoS/OOM ceiling — owner-scope applied FIRST, then the page is sliced.
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(rows, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function notificationsRead(req, res, params) {
  const who = await requireIdentity(req, res);
  if (who === null) return;
  const nid = intParam(params.note_id);
  if (nid === null) return problem(res, 422, 'invalid notification id'); // non-numeric/5.0 -> 422
  const notif = await storeGet('notifications_items', String(nid));
  if (notif === undefined || notif.to !== who) {
    return problem(res, 404, 'notification not found'); // not-yours == not-found: no existence leak
  }
  // monotonic + idempotent: "read" is TERMINAL — concurrent marks converge; nothing writes "unread" back
  const read = { ...notif, status: 'read' };
  await storePut('notifications_items', String(nid), read);
  sendJSON(res, 200, read);
}
