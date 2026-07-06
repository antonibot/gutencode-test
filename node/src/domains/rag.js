// rag — a retrieval pipeline (chunk -> embed -> rank -> cite) over an owner-scoped document corpus. The dangerous
// property is CITATION SOUNDNESS + GROUNDING: every query hit carries a source span {doc_id, start, end} that is an
// in-bounds window into the CURRENT stored document (0 <= start <= end <= len), the hit text is exactly that window's
// code points, and an exact-chunk-text query self-matches at cosine 1.0 — so an answer is always traceable to a real
// source chunk and a citation can never be fabricated or stale. Ranking is DETERMINISTIC (score desc, ties by chunk_id
// asc — identical x3; scores are floats, NOT pinned) and a query returns at most k hits.
//
// IDENTITY + ISOLATION: both routes are POST mutations -> requireIdentity FIRST in the handler (the runtime already
// parsed the body / emitted 413/422 before the handler runs, so auth-before-validation holds, x3). No/invalid token ->
// 401. A document is USER-SCOPED two ways: the store key is the composite <owner><doc_id> (caller B can NEVER
// overwrite caller A's doc_id — the separator is a control char well_formed rejects, so it can't be forged), and the
// query scan filters on the authenticated owner FIELD (another owner's chunks are invisible). The owner is stamped
// from the token, never a body field, never surfaced in a hit.
import { isStrictInt, problem, requireIdentity, sendJSON, storePut, storeValues } from '../core/runtime.js';
import { chunkCount, chunkEnd, chunkSlice, chunkStart } from '../parts/chunking.js';
import { cosine, embed } from '../parts/embedding.js';
import { envInt } from '../parts/env_int.js';
import { isWellFormed, makeWellFormed } from '../parts/well_formed.js';
// state in store: ns "rag_documents" "<owner><doc_id>" -> {id, owner, text, chunks:[{ordinal,start,end,vector}]}.
// the composite key partitions by owner (no cross-owner clobber); the `owner` field also scopes the query scan.

const CHUNK_SIZE = envInt(process.env.RAG_CHUNK_SIZE, 400, 1);
const CHUNK_OVERLAP = envInt(process.env.RAG_CHUNK_OVERLAP, 80, 0);
const MAX_CHUNKS = envInt(process.env.RAG_MAX_CHUNKS, 1000, 1);
// fail-loud at startup: the stride size-overlap must be >= 1 (else no progress / an infinite chunk loop), x3
if (!(CHUNK_OVERLAP >= 0 && CHUNK_OVERLAP < CHUNK_SIZE)) {
  throw new Error('RAG_CHUNK_OVERLAP must satisfy 0 <= RAG_CHUNK_OVERLAP < RAG_CHUNK_SIZE');
}

export async function ragIngest(req, res, params, body) {
  const owner = await requireIdentity(req, res); // authn BEFORE validation (runtime already parsed the body), x3
  if (owner === null) return;
  if (!body || !isWellFormed(body.doc_id) || typeof body.text !== 'string' || body.text === '') {
    return problem(res, 422, 'invalid body');
  }
  // contain the text BEFORE it is chunked / embedded / stored (lone surrogate -> U+FFFD so no slice 5xxs on serialize)
  const text = makeWellFormed(body.text);
  const n = chunkCount(text, CHUNK_SIZE, CHUNK_OVERLAP);
  if (n > MAX_CHUNKS) return problem(res, 422, 'document too large'); // soft-DoS ceiling -> 422
  const chunks = [];
  for (let i = 0; i < n; i++) {
    const start = chunkStart(CHUNK_SIZE, CHUNK_OVERLAP, i);
    const end = chunkEnd(text, CHUNK_SIZE, CHUNK_OVERLAP, i);
    chunks.push({ ordinal: i, start, end, vector: embed(chunkSlice(text, start, end)) });
  }
  // owner from the token, never client-set; the composite key partitions by owner so B can't overwrite A's doc_id.
  // a blind put REPLACES the whole record (re-ingest = last-writer-wins; NOT a get-then-put RMW)
  await storePut('rag_documents', `${owner}${body.doc_id}`, { id: body.doc_id, owner, text, chunks });
  sendJSON(res, 201, { doc_id: body.doc_id, chunks: n });
}

export async function ragQuery(req, res, params, body) {
  const caller = await requireIdentity(req, res); // a POST is a mutation -> authn BEFORE validation, x3
  if (caller === null) return;
  if (!body || typeof body.query !== 'string' || body.query === '') return problem(res, 422, 'invalid body');
  let k = 3;
  if (body.k !== undefined) {
    if (!isStrictInt(body, 'k') || body.k < 1 || body.k > 50) {
      return problem(res, 422, 'k must be an integer between 1 and 50');
    }
    k = body.k;
  }
  const qv = embed(makeWellFormed(body.query)); // contain the query too — a lone-surrogate query embeds identically x3
  const hits = [];
  // unbounded-safe: ranked top-k — at most k hits (k clamped), never the corpus; the full-scan is the documented
  // embeddings-index-swap-at-scale limit. read-scope: only the caller's own docs (owner FIELD === caller).
  for (const d of await storeValues('rag_documents')) {
    if (d.owner !== caller) continue; // read-scoping: another owner's chunks are invisible (cross-corpus leak wall)
    for (const c of d.chunks) {
      hits.push({ // owner/vector/ordinal stay internal — never in the hit
        chunk_id: `${d.id}#${c.ordinal}`,
        text: chunkSlice(d.text, c.start, c.end),
        score: cosine(qv, c.vector),
        source: { doc_id: d.id, start: c.start, end: c.end },
      });
    }
  }
  hits.sort((a, b) => (b.score - a.score) || (a.chunk_id < b.chunk_id ? -1 : a.chunk_id > b.chunk_id ? 1 : 0)); // score desc, chunk_id asc
  sendJSON(res, 200, { top: hits.length > 0 ? hits[0].chunk_id : null, hits: hits.slice(0, k) }); // at most k hits, ever
}
