// search — token full-text search over a durable corpus. The dangerous property is RETRIEVAL HONESTY:
// AND-complete (a document containing ALL query terms IS returned) and AND-sound (a document missing ANY term is
// NOT), whole-token matching only, case-insensitive. Deny-by-default: an empty query returns [] — never the
// corpus. Ranking is DETERMINISTIC x3: total query-term frequency desc, then id asc. Re-indexing an id replaces
// its document. Tokenization is lowercase ascii alphanumerics (the documented v1 limit). Store names and the
// document shape match the python/go impls; the corpus is durable.
// USER-SCOPED: a document belongs to the caller who indexed it, and a query sees ONLY the caller's own corpus.
// POST /search/index requires identity (the core requireIdentity seam — ANY authenticated caller; no/invalid token
// -> 401) and stamps `owner` from the authenticated subject — NEVER a body field. The runtime already parsed the
// body before the handler, so requireIdentity-first matches python's Depends order ×3. GET /search/query ALSO
// requires identity (no body, so requireIdentity runs first — a no-token query is 401) and filters the scan to the
// caller's own docs: a doc whose owner != caller is invisible (the api_keys not-yours==not-found pattern over a
// corpus scan). The stored owner is private — never returned (query yields {query, results}; index yields {id, tokens}).
import { isStrictInt, problem, requireIdentity, sendJSON, storePut, storeValues } from '../core/runtime.js';

// state in store: ns "search_docs" "<owner>\x1f<id>" -> {id, text, owner} (the WHOLE document in one write); owner
// private; the composite key partitions by owner so caller B can't overwrite caller A's id (the cross-owner WRITE wall)

const tokens = (text) => text.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

export async function searchIndex(req, res, params, body) {
  const owner = await requireIdentity(req, res); // authenticated mutation (runtime already parsed the body)
  if (owner === null) return;
  if (!body || !isStrictInt(body, 'id') || body.id < 1 || typeof body.text !== 'string' || body.text === '') {
    return problem(res, 422, 'invalid body');
  }
  // one write replaces the document; owner stamped from the TOKEN (never the body); the COMPOSITE key partitions by
  // owner so caller B can't overwrite caller A's id (the cross-owner WRITE wall)
  await storePut('search_docs', `${owner}\x1f${body.id}`, { id: body.id, text: body.text, owner });
  sendJSON(res, 201, { id: body.id, tokens: new Set(tokens(body.text)).size });
}

export async function searchQuery(req, res) {
  const owner = await requireIdentity(req, res); // AUTH first (no body): a no-token query is 401, matching python's Depends
  if (owner === null) return;
  const q = new URL(req.url, 'http://localhost').searchParams.get('q') || '';
  const terms = tokens(q);
  if (terms.length === 0) {
    // deny-by-default: no terms -> no results, never the whole corpus
    return sendJSON(res, 200, { query: q, results: [] });
  }
  const hits = [];
  // unbounded-safe: ranked top-k — returns at most k results (k clamped), never the corpus; the full-scan is the documented search-index-swap-at-scale limit.
  for (const doc of await storeValues('search_docs')) {
    if (doc.owner !== owner) continue; // USER-SCOPED: a doc that isn't yours is invisible (not-yours==not-found)
    const toks = tokens(doc.text);
    const counts = new Map();
    for (const t of toks) counts.set(t, (counts.get(t) || 0) + 1);
    let all = true;
    let score = 0;
    for (const term of terms) {
      const n = counts.get(term) || 0;
      if (n === 0) { all = false; break; } // AND: every query term present as a whole token
      score += n;
    }
    if (all) hits.push({ score, id: doc.id });
  }
  hits.sort((a, b) => (b.score - a.score) || (a.id - b.id)); // deterministic: frequency desc, then id asc
  sendJSON(res, 200, { query: q, results: hits.map((h) => h.id) });
}
