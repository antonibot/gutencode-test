// vectorstore — embeddings + retrieval, the RAG backbone. The dangerous property is RETRIEVAL GROUNDING: an
// exact-text query MUST self-match as the top hit, the ordering is DETERMINISTIC (score desc, ties by id asc —
// identical x3), and a query returns at most k hits. The offline embedder is the shared `embedding` part (an
// 8-bucket codepoint histogram of the lowercased text — pure integer counts, so every cosine is bit-identical
// across languages); the real embedder + vector DB swap in behind the same routes. Scores are floats and deliberately
// NOT pinned in the contract; it pins the TOP id. Vectors are durable.
//
// IDENTITY + READ-SCOPING + WRITE-PARTITION: both routes are POST mutations -> requireIdentity FIRST in the handler
// (the runtime already parsed the body / emitted 413/422 before the handler runs, so auth-before-validation holds, x3).
// No/invalid token -> 401. A document is USER-SCOPED two ways: at index the OWNER is stamped from the authenticated
// subject (never a body field) and the store key is the COMPOSITE <owner>\x1f<id> (caller B can NEVER overwrite caller
// A's id — the cross-owner WRITE wall; the \x1f separator is a control char isWellFormed rejects, so the key can't be
// forged); at query the scan is filtered to ONLY the caller's own docs (a doc whose owner != caller is skipped, never
// appearing in hits — the tenancy not-yours==not-found pattern). The owner field is INTERNAL — never surfaced in the
// query response.
import { isStrictInt, problem, requireIdentity, sendJSON, storePut, storeValues } from '../core/runtime.js';
import { cosine, embed } from '../parts/embedding.js';
import { isWellFormed } from '../parts/well_formed.js';

// state in store: ns "vectorstore_docs" "<owner>\x1f<id>" -> {id, text, vector, owner} (owner is PRIVATE — scopes the
// query scan, never returned; the composite key partitions by owner so B can't overwrite A's id)

export async function vectorstoreIndex(req, res, params, body) {
  const owner = await requireIdentity(req, res); // authn BEFORE validation (runtime already parsed the body), x3
  if (owner === null) return;
  if (!body || !isWellFormed(body.id) || typeof body.text !== 'string' || body.text === '') {
    return problem(res, 422, 'invalid body');
  }
  // owner derived from the token, never client-set; the COMPOSITE key partitions by owner so B can't overwrite A's id
  await storePut('vectorstore_docs', `${owner}\x1f${body.id}`, { id: body.id, text: body.text, vector: embed(body.text), owner });
  sendJSON(res, 201, { id: body.id, indexed: true });
}

export async function vectorstoreQuery(req, res, params, body) {
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
  const qv = embed(body.query);
  // unbounded-safe: ranked top-k — returns at most k hits (k clamped), never the corpus; the full-scan is the documented embeddings-index-swap-at-scale limit.
  const hits = (await storeValues('vectorstore_docs'))
    .filter((d) => d.owner === caller) // read-scoping: skip any doc not owned by the caller (not-yours == not-found)
    .map((d) => ({ id: d.id, text: d.text, score: cosine(qv, d.vector) })) // owner stays internal — not in the hit
    .sort((a, b) => (b.score - a.score) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)) // score desc, id asc
    .slice(0, k); // at most k hits, ever
  sendJSON(res, 200, { top: hits.length > 0 ? hits[0].id : null, hits });
}
