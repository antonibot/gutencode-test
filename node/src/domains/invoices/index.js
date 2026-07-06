// invoices — a CONSERVED multi-line bill (create-draft · retrieve · edit-draft · finalize · pay/void/uncollectible).
// The dangerous properties proven here:
// (1) CONSERVATION: the server RECOMPUTES every total — line amount = unit_amount × quantity, subtotal = Σ line
// amounts, total = subtotal + tax — and DISCARDS any client total, so a stored bill ALWAYS reconciles to its lines +
// tax. Every amount is capped at 2^53-1 and the per-line PRODUCT is bounded (an integer below 2^53 is exact and a
// product >=2^53 stays >=2^53, so the comparison is exact at this ceiling), as is the running subtotal/total.
// (2) OWNER ISOLATION: a bill belongs to its creating caller (the core requireIdentity seam). The store slot is the
// composite '<caller>\x1f<id>', so a by-id get for another caller's bill lands in a DIFFERENT slot -> 404,
// byte-indistinguishable from missing; the list is owner-FIELD-filtered.
// (3) FINALIZE-IMMUTABILITY: a draft is editable (PATCH); finalize is a ONE-WAY trap door draft -> open that assigns a
// monotonic, no-duplicate NUMBER and FREEZES the bill (PATCH on a non-draft -> 409). The number is minted OUTSIDE the
// transition storeDo (a nextId INSIDE it would re-enter the store), so it is monotonic + unique but not gapless.
// Every route requires the AUTHENTICATED caller — an anonymous create is bill fabrication; no token -> 401.
// Store names + the bill shape match the python/go impls.
import { isStrictInt, nextId, problem, requireIdentity, sendJSON, storeDo, storeGet, storeValues, testNow } from '../../core/runtime.js';
import { isCurrency } from '../../parts/currency.js';
import { digestHex, scopedKey } from '../../parts/digest.js';
import { claimOnce } from '../../parts/idempotent_claim.js';
import { paginate } from '../../parts/paginate.js';
import { isWellFormed, makeWellFormed } from '../../parts/well_formed.js';

const NS = 'invoices_records';
const ROUTE = 'POST /invoices'; // the route discriminator (per-route caller-private derived id/slot)
const MAX_AMOUNT = Number.MAX_SAFE_INTEGER; // 2^53-1 — the cross-language-safe ceiling (no float-precision/int64 sum overflow)
const MAX_LINES = 1000; // a single bill's line list is COUNT-bounded (no unbounded record growth)

function invoicesDigest(customer, currency, tax, lines) {
  // the central canonical body fingerprint (over the recomputed, U+FFFD-safe shape) — lines field-by-field, in order
  const parts = ['customer', customer, 'currency', currency, 'tax', tax, 'lines', lines.length];
  lines.forEach((li, i) => parts.push(`d${i}`, li.description, `q${i}`, li.quantity, `u${i}`, li.unit_amount));
  return digestHex(...parts);
}

// the PUBLIC projection — the internal caller/body_hash/finalized_at bookkeeping never leaves the store.
const publicOut = (v) => ({ id: v.id, number: v.number, customer: v.customer, status: v.status, currency: v.currency,
  line_items: v.line_items.map((li) => ({ description: li.description, quantity: li.quantity,
    unit_amount: li.unit_amount, amount: li.amount })),
  subtotal: v.subtotal, tax: v.tax, total: v.total, amount_paid: v.amount_paid });

// parseInvoiceFields — PASS 1 (every field strict + range, mirrors python pydantic) + is_currency. SHARED by create +
// update (the body shape + validation are identical — the centralization rule). Writes the 422 + returns null on fail.
function parseInvoiceFields(res, body) {
  if (!body || !isWellFormed(body.customer) || !isWellFormed(body.currency) ||
      !isStrictInt(body, 'tax') || body.tax < 0 || body.tax > MAX_AMOUNT) {
    problem(res, 422, 'invalid body');
    return null;
  }
  if (!Array.isArray(body.line_items) || body.line_items.length < 1 || body.line_items.length > MAX_LINES) {
    problem(res, 422, 'invalid body');
    return null;
  }
  const parsed = [];
  for (const li of body.line_items) {
    if (!li || typeof li !== 'object' || !isWellFormed(li.description) ||
        !isStrictInt(li, 'quantity') || li.quantity < 1 || li.quantity > MAX_AMOUNT ||
        !isStrictInt(li, 'unit_amount') || li.unit_amount < 1 || li.unit_amount > MAX_AMOUNT) {
      problem(res, 422, 'invalid body');
      return null;
    }
    parsed.push({ description: li.description, quantity: li.quantity, unit_amount: li.unit_amount });
  }
  if (!isCurrency(body.currency)) { problem(res, 422, 'invalid body'); return null; } // a CLOSED ISO-4217 set
  return { customer: body.customer, currency: body.currency, tax: body.tax, parsed };
}

// recomputeInvoice — PASS 2: the CONSERVATION arithmetic. Derives every money field; bounds the per-line PRODUCT and
// the running subtotal/total. Echoed text is U+FFFD-sanitized. Writes the 422 + returns null on overflow.
function recomputeInvoice(res, customer, parsed, tax) {
  const lines = [];
  let subtotal = 0;
  for (const p of parsed) {
    if (p.unit_amount * p.quantity > MAX_AMOUNT) { problem(res, 422, 'a line amount exceeds the maximum'); return null; }
    const amount = p.unit_amount * p.quantity;
    lines.push({ description: makeWellFormed(p.description), quantity: p.quantity, unit_amount: p.unit_amount, amount });
    subtotal += amount;
    if (subtotal > MAX_AMOUNT) { problem(res, 422, 'the subtotal exceeds the maximum'); return null; }
  }
  const total = subtotal + tax;
  if (total > MAX_AMOUNT) { problem(res, 422, 'the total exceeds the maximum'); return null; }
  return { safeCustomer: makeWellFormed(customer), lines, subtotal, total };
}

export async function invoicesCreate(req, res, params, body) {
  // The runtime frame-parses the body first (a malformed body -> 422 before the handler, matching python's pydantic +
  // go's DecodeJSON); then requireIdentity (no token + a valid body -> 401), then VALIDATE (PASS1 + is_currency),
  // then SEMANTIC (idem-key), then RECOMPUTE (PASS2). Identical ×3.
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const f = parseInvoiceFields(res, body);
  if (f === null) return;
  const key = req.headers['idempotency-key'];
  if (key === undefined) return problem(res, 422, 'Idempotency-Key header is required'); // DERIVED id: no key, no id
  // a SINGLE opaque token; node comma-joins duplicate headers, so count the raw header lines and REJECT >1 (×3 parity)
  let nKeys = 0;
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i].toLowerCase() === 'idempotency-key') nKeys += 1;
  }
  if (nKeys > 1) return problem(res, 422, 'Idempotency-Key must be a single value');
  if (!isWellFormed(key)) return problem(res, 422, 'Idempotency-Key must be non-empty with no control characters');
  const rc = recomputeInvoice(res, f.customer, f.parsed, f.tax);
  if (rc === null) return;
  const h = invoicesDigest(rc.safeCustomer, f.currency, f.tax, rc.lines);
  const invId = scopedKey(ROUTE, caller, key); // the deterministic, caller-private bill id
  const slot = `${caller}\x1f${invId}`;        // the owner-composite store slot (cross-caller -> 404)
  let prior = await storeGet(NS, slot);              // fast path: a settled key never re-creates
  if (prior === undefined) {
    const rec = { id: invId, caller, customer: rc.safeCustomer, status: 'draft', currency: f.currency,
      line_items: rc.lines, subtotal: rc.subtotal, tax: f.tax, total: rc.total, amount_paid: 0,
      number: null, finalized_at: null, body_hash: h };
    prior = await claimOnce(NS, slot, rec); // ONE atomic claim per slot (no double-create under a race)
  }
  if (prior.caller !== caller) return problem(res, 409, 'idempotency key is not owned by this caller');
  if (prior.body_hash !== h) return problem(res, 409, 'idempotency key reused with a different body');
  sendJSON(res, 201, publicOut(prior));
}

export async function invoicesList(req, res) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  // SCOPED read: only the caller's OWN bills (owner-FIELD-filtered — the comparison runs on the STORED owner
  // field, never a client value), then a BOUNDED page over that stable-ordered set via the shared paginate part.
  const mine = (await storeValues(NS)).filter((v) => v.caller === caller);
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(mine, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items.map(publicOut), next_cursor: next });
}

export async function invoicesGet(req, res, params) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const id = params.invoice_id;
  if (!isWellFormed(id)) return problem(res, 422, 'the invoice id must be non-empty with no control characters');
  const rec = await storeGet(NS, `${caller}\x1f${id}`);
  if (rec === undefined) return problem(res, 404, 'invoice not found'); // not-yours == not-found
  sendJSON(res, 200, publicOut(rec));
}

// ── the lifecycle TRANSITIONS — each is ONE atomic read-modify-write through storeDo. The state read, the
// recompute, and the write ALL happen INSIDE the callback against `cur` (NEVER a value read before storeDo), so two
// processes racing a transition serialize and the loser sees the already-transitioned bill. ────────────────────────

export async function invoicesUpdate(req, res, params, body) {
  // DRAFT-ONLY edit (the IMMUTABILITY trap door: a finalized bill is FROZEN, 409). Re-validate + RECOMPUTE BEFORE the
  // storeDo, then atomically check status=="draft" and replace the editable fields. No Idempotency-Key (the bill is
  // addressed by its path id). Order: parse -> recompute -> id -> do (matches python).
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const f = parseInvoiceFields(res, body);
  if (f === null) return;
  const rc = recomputeInvoice(res, f.customer, f.parsed, f.tax);
  if (rc === null) return;
  const id = params.invoice_id;
  if (!isWellFormed(id)) return problem(res, 422, 'the invoice id must be non-empty with no control characters');
  const h = invoicesDigest(rc.safeCustomer, f.currency, f.tax, rc.lines);
  let code = 0;
  let rec;
  await storeDo(NS, `${caller}\x1f${id}`, (cur) => {
    if (cur === undefined) { code = 404; return [undefined, null]; }
    if (cur.status !== 'draft') { code = 409; return [undefined, null]; } // IMMUTABILITY: only a draft is editable
    cur.customer = rc.safeCustomer;
    cur.currency = f.currency;
    cur.line_items = rc.lines;
    cur.subtotal = rc.subtotal;
    cur.tax = f.tax;
    cur.total = rc.total;
    cur.body_hash = h;
    rec = cur;
    return [cur, null];
  });
  if (code === 404) return problem(res, 404, 'invoice not found');
  if (code === 409) return problem(res, 409, 'only a draft invoice can be edited');
  sendJSON(res, 200, publicOut(rec));
}

export async function invoicesFinalize(req, res, params) {
  // FINALIZE = the one-way trap door draft -> open + assign the legal NUMBER. Minting INSIDE the transition storeDo
  // would RE-ENTER the store (the reentry guard fails ×3); minting BEFORE a possible 409 would burn a number -> a gap.
  // So a TWO-STEP: (1) an atomic storeDo flips draft->open WITHOUT minting; (2) only after it commits, mint nextId
  // OUTSIDE the callback and attach via a 2nd storeDo. A crash between leaves an open bill with number=null, which a
  // re-finalize COMPLETES (idempotent). Two processes racing -> exactly ONE number attached (the other's is an owned gap).
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const id = params.invoice_id;
  if (!isWellFormed(id)) return problem(res, 422, 'the invoice id must be non-empty with no control characters');
  const slot = `${caller}\x1f${id}`;
  const now = testNow(req);
  let code = 0;
  let rec;
  await storeDo(NS, slot, (cur) => {
    if (cur === undefined) { code = 404; return [undefined, null]; }
    if (cur.status === 'draft') { // the transition: freeze the content, stamp finalized_at, NO mint
      cur.status = 'open';
      cur.finalized_at = now;
      rec = cur;
      return [cur, null];
    }
    if (cur.status === 'open') { rec = cur; return [undefined, null]; } // already finalized OR half-finalized
    code = 409; // paid / void / uncollectible -> past finalize, not re-finalizable
    return [undefined, null];
  });
  if (code === 404) return problem(res, 404, 'invoice not found');
  if (code === 409) return problem(res, 409, 'only a draft invoice can be finalized');
  if (rec.number === null) { // mint OUTSIDE the storeDo (reentrancy-safe), then attach atomically
    const minted = `INV-${String(await nextId('invoices_number_' + caller)).padStart(6, '0')}`;
    await storeDo(NS, slot, (cur) => {
      if (cur === undefined || cur.status !== 'open' || cur.number !== null) {
        if (cur !== undefined) rec = cur; // another process attached first -> use the stored number (this mint is a gap)
        return [undefined, null];
      }
      cur.number = minted;
      rec = cur;
      return [cur, null];
    });
  }
  sendJSON(res, 200, publicOut(rec));
}

// ── the TERMINAL transitions — a finalized (open) bill moves ONCE to paid / void / uncollectible. Each is ONE
// atomic storeDo that reads + checks + writes against `cur`; idempotent on its own target, 409 from any other.
// amount_paid == total IFF paid (conservation: fully paid or written off, never partial). The three share ONE helper. ──

async function invoicesTerminal(req, res, params, target, pay) {
  const caller = await requireIdentity(req, res);
  if (caller === null) return;
  const id = params.invoice_id;
  if (!isWellFormed(id)) return problem(res, 422, 'the invoice id must be non-empty with no control characters');
  let code = 0;
  let rec;
  await storeDo(NS, `${caller}\x1f${id}`, (cur) => {
    if (cur === undefined) { code = 404; return [undefined, null]; }
    if (cur.status === target) { rec = cur; return [undefined, null]; } // idempotent re-application (no double-pay)
    // only a FULLY-finalized (NUMBERED) bill transitions — a torn finalize (open, number=null, the crash/race window)
    // 409s until a re-finalize completes its number (no number-less terminal bill)
    if (cur.status !== 'open' || cur.number === null) { code = 409; return [undefined, null]; }
    cur.status = target;
    if (pay) cur.amount_paid = cur.total; // CONSERVATION: a paid bill records its FULL total (never partial)
    rec = cur;
    return [cur, null];
  });
  if (code === 404) return problem(res, 404, 'invoice not found');
  if (code === 409) return problem(res, 409, `invoice cannot transition to ${target} from its current state`);
  sendJSON(res, 200, publicOut(rec));
}

// mark-paid: the bill is fully paid (amount_paid = total) WITHOUT importing the payments domain.
export async function invoicesPay(req, res, params) { return invoicesTerminal(req, res, params, 'paid', true); }

// void a finalized bill that will NOT be collected. open -> void; idempotent; else 409.
export async function invoicesVoid(req, res, params) { return invoicesTerminal(req, res, params, 'void', false); }

// mark a finalized bill as bad debt. open -> uncollectible; idempotent; else 409.
export async function invoicesMarkUncollectible(req, res, params) {
  return invoicesTerminal(req, res, params, 'uncollectible', false);
}
