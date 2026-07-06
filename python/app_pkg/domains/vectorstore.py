"""vectorstore — embeddings + retrieval, the RAG backbone. The dangerous property is RETRIEVAL GROUNDING: an
exact-text query MUST self-match as the top hit (score 1.0 by construction — the nearest stored document wins),
the ordering is DETERMINISTIC (score desc, ties by id asc — identical in all three languages), and a query
returns at most k hits. The offline embedder is the shared `embedding` part (an 8-bucket codepoint histogram of
the lowercased text) so it is the test oracle; the real embedder + vector DB swap in behind the same routes.
Scores are floats and deliberately NOT pinned in the contract (float formatting differs across languages); the
contract pins the TOP id and the invariant proves the ordering. Vectors are durable.

IDENTITY + READ-SCOPING + WRITE-PARTITION: every mutating route (POST /vectors, POST /vectors/query — a POST is
a mutation under the gate) requires an authenticated caller via the core require_identity seam — no/invalid token ->
401. A document is USER-SCOPED two ways: (1) at index the OWNER is stamped from the authenticated subject (never a
body field) and the store key is the COMPOSITE <owner>\x1f<id>, so caller B can NEVER overwrite caller A's id (the
cross-owner WRITE wall — the \x1f separator is a control char WellFormedStr rejects, so the key can't be forged);
(2) at query the document scan is filtered to ONLY the caller's own docs — a doc whose owner != caller is skipped, so
it can never appear in the hits (the tenancy not-yours==not-found pattern, exactly like api_keys/storage). This closes
the anonymous hole, the cross-owner WRITE clobber, AND the cross-owner RAG leak. The owner field is INTERNAL — it is
never surfaced in the query response (which returns {id,text,score}/hits), like api_keys's private owner."""
from typing import Annotated, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, StrictInt, StrictStr, field_validator

from ..core import store
from ..core.errors import require_identity
from ..parts.embedding import cosine, embed
from ..parts.well_formed import WellFormedStr

router = APIRouter(prefix="/vectors", tags=["vectorstore"])
# state in `store`: ns "vectorstore_docs" "<owner>\x1f<id>" -> {id, text, vector, owner} (the WHOLE document in one
# write; same ×3). The composite key partitions by owner so B can't overwrite A's id (the cross-owner WRITE wall);
# `owner` is the authenticated indexer — PRIVATE (used to scope the query scan, never returned).


class IndexIn(BaseModel):
    id: WellFormedStr
    text: StrictStr

    @field_validator("text")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("must be non-empty")
        return value


class QueryIn(BaseModel):
    query: StrictStr
    k: Optional[Annotated[StrictInt, Field(ge=1, le=50)]] = 3

    @field_validator("query")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("must be non-empty")
        return value


@router.post("", status_code=201)
def index(data: IndexIn, caller: str = Depends(require_identity)) -> dict:   # authenticated mutation (no/invalid token -> 401)
    # owner is the authenticated subject, NEVER a body field — stamped here so the query can scope to it; the composite
    # key partitions by owner so caller B can't overwrite caller A's id (the cross-owner WRITE wall)
    store.put("vectorstore_docs", f"{caller}\x1f{data.id}",
              {"id": data.id, "text": data.text, "vector": embed(data.text), "owner": caller})   # one write replaces the doc
    return {"id": data.id, "indexed": True}


@router.post("/query")
def query(data: QueryIn, caller: str = Depends(require_identity)) -> dict:   # a POST is a mutation -> authenticated (no/invalid token -> 401)
    qv = embed(data.query)
    # unbounded-safe: ranked top-k — returns at most k hits (k clamped), never the corpus; the full-scan is the documented embeddings-index-swap-at-scale limit.
    scored = [{"id": d["id"], "text": d["text"], "score": cosine(qv, d["vector"])}
              for d in store.values("vectorstore_docs")
              if d.get("owner") == caller]                 # read-scoping: skip any doc not owned by the caller (not-yours == not-found)
    scored.sort(key=lambda h: (-h["score"], h["id"]))      # DETERMINISTIC: score desc, ties by id asc
    hits = scored[: data.k]                                # at most k hits, ever (owner stays internal — not in the hit)
    return {"top": hits[0]["id"] if hits else None, "hits": hits}
