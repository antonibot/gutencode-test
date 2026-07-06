// reporting — a self-contained, owner-scoped read-side AGGREGATION store (a CQRS read model the app FEEDS; it does NOT
// read other domains' stores — the boundary rule). Matches python/go; durable. Dangerous properties: (1) AGGREGATION
// CORRECTNESS ×3 (COUNT/SUM/MIN/MAX byte-identical — a wrong sum still returns 200; the invariant recomputes it).
// (2) OWNER-SCOPED AGGREGATION — owner = requireIdentity (never a client field), a mandatory conjunct on every scan;
// a stranger gets an empty result, never 403. (3) DERIVED-OVERFLOW SAFETY — measures are STRICT ints bounded
// ±(2^53-1) (isStrictInt rejects 5.0/5.5/str ×3); the SUM predicts overflow BEFORE each add and fails loud (422) at
// 2^53 (no precision-lost float). (4) DETERMINISTIC GROUP ORDER — groups keyed+ordered by the digestHex of their
// PRE-HASHED group-by values (ASCII hex — injective + byte-identical ×3, dodging the codepoint/UTF-16 sort split).
// Exactly-once ingest via scopedKey+claimOnce (a fact is immutable). Every route requireIdentity. The in-process
// scan is the documented store-swap-at-scale limit (INTEROP.md).
import { isStrictInt, problem, requireIdentity, sendJSON, storeDelete, storeGet, storeValues, testNow } from '../core/runtime.js';
import { digestHex, scopedKey } from '../parts/digest.js';
import { claimOnce } from '../parts/idempotent_claim.js';
import { paginate } from '../parts/paginate.js';
import { isWellFormed, makeWellFormed } from '../parts/well_formed.js';

const ROUTE = 'POST /reporting/facts'; // the owner-scoped fact-slot discriminator (same string ×3)
const MAX = 9007199254740991;          // 2^53-1: the ×3-safe integer ceiling
const OPS = new Set(['count', 'sum', 'min', 'max']);

// state: seq "reporting_fact" · ns "reporting_facts" scopedKey(route, owner, digestHex(_h(dataset), _h(key))) -> the
// whole record {id, owner, dataset, key, dimensions:{str:str}, measures:{str:int}, created_at}. Owner-scoped + injective.

const _h = (s) => digestHex(s); // pre-hash a component (colon-free -> injective join)

// contain-BEFORE-hash then validate: surrogate -> U+FFFD (a stored value never 5xxs a re-read), THEN reject
// empty/control/>1024cp. Applied to EVERY response-bound string incl. map KEYS + group_by/`as` names. null = invalid.
function clean(s) {
  const c = makeWellFormed(s);
  return isWellFormed(c) ? c : null;
}

const publicView = (r) => ({ id: r.id, owner: r.owner, dataset: r.dataset, key: r.key,
  dimensions: r.dimensions, measures: r.measures, created_at: r.created_at });

export async function reportingFactsCreate(req, res, params, body) {
  const owner = await requireIdentity(req, res); // the runtime parsed the body already, so identity-first is fine
  if (owner === null) return;
  if (!body || typeof body.dataset !== 'string' || typeof body.key !== 'string') return problem(res, 422, 'invalid body');
  const dataset = clean(body.dataset);
  const key = clean(body.key);
  if (dataset === null || key === null) return problem(res, 422, 'dataset and key must be non-empty with no control characters');
  const dimsIn = body.dimensions === undefined ? {} : body.dimensions;
  const measIn = body.measures === undefined ? {} : body.measures;
  if (typeof dimsIn !== 'object' || dimsIn === null || Array.isArray(dimsIn)
      || typeof measIn !== 'object' || measIn === null || Array.isArray(measIn)) {
    return problem(res, 422, 'dimensions and measures must be objects');
  }
  const dims = {};
  for (const [k, v] of Object.entries(dimsIn)) {
    if (typeof v !== 'string') return problem(res, 422, 'dimension values must be strings');
    const ck = clean(k);
    const cv = clean(v);
    if (ck === null || cv === null) return problem(res, 422, 'dimension names and values must be non-empty with no control characters');
    dims[ck] = cv;
  }
  const meas = {};
  for (const k of Object.keys(measIn)) {
    if (!isStrictInt(measIn, k)) return problem(res, 422, 'measure values must be integers in the safe range'); // rejects 5.0/5.5/str/bool/>2^53 ×3
    const ck = clean(k);
    if (ck === null) return problem(res, 422, 'measure names must be non-empty with no control characters');
    meas[ck] = measIn[k];
  }
  const slot = scopedKey(ROUTE, owner, digestHex(_h(dataset), _h(key))); // owner-scoped + injective in (dataset,key)
  let prior = await storeGet('reporting_facts', slot);                   // fast path: a settled fact never re-writes
  if (prior === undefined) {
    const rec = { id: slot, owner, dataset, key, dimensions: dims, measures: meas, created_at: testNow(req) }; // id = the deterministic slot
    prior = await claimOnce('reporting_facts', slot, rec);              // exactly-once: a repeat (dataset,key) returns the winner
  }
  sendJSON(res, 201, publicView(prior));
}

export async function reportingFactsList(req, res) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  // SCOPED read: only the caller's own facts leave the store (owner FIELD filter, as stored — never a client value),
  // id-sorted, then a BOUNDED page; a stranger gets an empty page.
  const q = new URL(req.url, 'http://localhost').searchParams;
  const ds = makeWellFormed(q.get('dataset') || ''); // contain the optional filter (empty = no filter)
  const mine = (await storeValues('reporting_facts'))
    .filter((r) => r.owner === owner && (ds === '' || r.dataset === ds))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)).map(publicView);
  const { items, next, ok } = paginate(mine, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

// validateAggs -> { aggs } or { err }. Mirrors python/go.
function validateAggs(aggregate) {
  if (!Array.isArray(aggregate)) return { err: 'unknown aggregate op' };
  const aggs = [];
  const seen = new Set();
  for (const a of aggregate) {
    if (!a || typeof a !== 'object' || Array.isArray(a) || typeof a.op !== 'string' || !OPS.has(a.op)) return { err: 'unknown aggregate op' };
    let field = null;
    let as;
    if (a.op === 'count') {
      if (a.field !== undefined && a.field !== null) return { err: 'count takes no field' };
      if (a.as !== undefined && a.as !== null && typeof a.as !== 'string') return { err: 'aggregate name must be non-empty with no control characters' };
      as = clean(a.as !== undefined && a.as !== null ? a.as : 'count');
    } else {
      if (a.field === undefined || a.field === null || typeof a.field !== 'string') return { err: `${a.op} requires a field` };
      field = clean(a.field);
      if (field === null) return { err: 'aggregate field must be non-empty with no control characters' };
      if (a.as !== undefined && a.as !== null && typeof a.as !== 'string') return { err: 'aggregate name must be non-empty with no control characters' };
      as = clean(a.as !== undefined && a.as !== null ? a.as : `${a.op}_${field}`);
    }
    if (as === null) return { err: 'aggregate name must be non-empty with no control characters' };
    if (seen.has(as)) return { err: 'duplicate aggregate name' };
    seen.add(as);
    aggs.push({ op: a.op, field, as });
  }
  if (aggs.length === 0) return { err: 'at least one aggregate is required' };
  return { aggs };
}

export async function reportingQuery(req, res, params, body) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  // SCOPED aggregation: the owner conjunct is INLINE; the O(n) scan is the documented store-swap-at-scale limit, the
  // GROUPS result rides paginate.
  if (!body || typeof body.dataset !== 'string') return problem(res, 422, 'invalid body');
  const dataset = clean(body.dataset);
  if (dataset === null) return problem(res, 422, 'dataset must be non-empty with no control characters');
  const groupByIn = body.group_by === undefined ? [] : body.group_by;
  if (!Array.isArray(groupByIn)) return problem(res, 422, 'group_by must be a list');
  const groupBy = [];
  for (const n of groupByIn) {
    if (typeof n !== 'string') return problem(res, 422, 'group_by name must be non-empty with no control characters');
    const c = clean(n);
    if (c === null) return problem(res, 422, 'group_by name must be non-empty with no control characters');
    groupBy.push(c);
  }
  const va = validateAggs(body.aggregate === undefined ? [] : body.aggregate);
  if (va.err) return problem(res, 422, va.err);
  const aggs = va.aggs;
  const filterIn = body.filter === undefined ? {} : body.filter;
  if (typeof filterIn !== 'object' || filterIn === null || Array.isArray(filterIn)) return problem(res, 422, 'filter must be an object');
  const filt = {};
  for (const [k, v] of Object.entries(filterIn)) {
    if (typeof v !== 'string') return problem(res, 422, 'filter values must be strings');
    const ck = clean(k);
    const cv = clean(v);
    if (ck === null || cv === null) return problem(res, 422, 'filter names and values must be non-empty with no control characters');
    filt[ck] = cv;
  }
  const fEntries = Object.entries(filt);
  // id-sorted so the SUM accumulation order (hence any overflow trip) is deterministic ×3
  const matching = (await storeValues('reporting_facts'))
    .filter((r) => r.owner === owner && r.dataset === dataset && fEntries.every(([fk, fv]) => r.dimensions[fk] === fv))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const groups = new Map();
  for (const r of matching) {
    const values = groupBy.map((n) => (Object.hasOwn(r.dimensions, n) ? r.dimensions[n] : null));
    const kh = digestHex(...values.map((v) => (v !== null ? _h(v) : ''))); // injective, ASCII-hex, ×3-identical
    let g = groups.get(kh);
    if (g === undefined) { g = { values, count: 0, sum: {}, min: {}, max: {} }; groups.set(kh, g); }
    g.count += 1;
    for (const a of aggs) {
      if (a.op === 'count' || !Object.hasOwn(r.measures, a.field)) continue;
      const v = r.measures[a.field];
      if (a.op === 'sum') {
        const acc = a.as in g.sum ? g.sum[a.as] : 0;
        if ((v > 0 && acc > MAX - v) || (v < 0 && acc < -MAX - v)) return problem(res, 422, 'an aggregate sum exceeds the safe integer range');
        g.sum[a.as] = acc + v;
      } else if (a.op === 'min') {
        g.min[a.as] = a.as in g.min ? Math.min(g.min[a.as], v) : v;
      } else if (a.op === 'max') {
        g.max[a.as] = a.as in g.max ? Math.max(g.max[a.as], v) : v;
      }
    }
  }
  const out = [...groups.keys()].sort().map((kh) => { // default sort: lexicographic on ASCII hex -> identical ×3
    const g = groups.get(kh);
    const key = {};
    groupBy.forEach((n, i) => { key[n] = g.values[i]; });
    const vals = {};
    for (const a of aggs) {
      if (a.op === 'count') vals[a.as] = g.count;
      else if (a.op === 'sum') vals[a.as] = (a.as in g.sum ? g.sum[a.as] : 0); // SUM of no matching values = 0 (documented)
      else if (a.op === 'min') { if (a.as in g.min) vals[a.as] = g.min[a.as]; } // MIN/MAX of no values -> OMITTED
      else if (a.op === 'max') { if (a.as in g.max) vals[a.as] = g.max[a.as]; }
    }
    return { key, values: vals };
  });
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(out, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { groups: items, next_cursor: next });
}

export async function reportingFactsDrain(req, res) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  // OWNER-scoped filtered DRAIN (the relations bulk-delete precedent): dataset REQUIRED (>=1 anchor) + optional
  // ?<dim>=<val> filters. unbounded-safe: a filtered delete drains ALL matching; owner conjunct INLINE.
  const q = new URL(req.url, 'http://localhost').searchParams;
  const dsRaw = q.get('dataset');
  if (!dsRaw) return problem(res, 422, 'dataset is required');
  const dataset = clean(dsRaw);
  if (dataset === null) return problem(res, 422, 'dataset must be non-empty with no control characters');
  const filt = {};
  for (const k of q.keys()) {
    if (k === 'dataset') continue;
    const ck = clean(k);
    const cv = clean(q.get(k));
    if (ck === null || cv === null) return problem(res, 422, 'filter names and values must be non-empty with no control characters');
    filt[ck] = cv;
  }
  const fEntries = Object.entries(filt);
  let deleted = 0;
  for (const r of await storeValues('reporting_facts')) {
    if (r.owner === owner && r.dataset === dataset && fEntries.every(([fk, fv]) => r.dimensions[fk] === fv)) {
      await storeDelete('reporting_facts', r.id); // id IS the slot (deterministic scoped_key)
      deleted += 1;
    }
  }
  sendJSON(res, 200, { deleted });
}
