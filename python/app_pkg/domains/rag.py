"""rag — a retrieval pipeline (chunk -> embed -> rank -> cite) over an owner-scoped document corpus. The dangerous
property is CITATION SOUNDNESS + GROUNDING: every query hit carries a source span {doc_id, start, end} that is an
in-bounds window into the CURRENT stored document (0 <= start <= end <= len), the hit text is exactly that window's
code points, and an exact-chunk-text query self-matches at cosine 1.0 — so an answer is always traceable to a real
source chunk and a citation can never be fabricated or stale. Ranking is DETERMINISTIC (score desc, ties by chunk_id
asc — identical ×3, floats unpinned) and a query returns at most k hits.

IDENTITY + ISOLATION: both routes are body-only POST mutations requiring an authenticated caller (require_identity;
no/invalid token -> 401). A document is USER-SCOPED two ways: (a) the store key is the composite <owner>\\x1f<doc_id>,
so caller B can NEVER overwrite caller A's doc_id (the cross-owner WRITE wall — the \\x1f separator is a control char
well_formed rejects, so the key can't be forged); (b) the query scan filters on the authenticated owner FIELD, so
another owner's chunks are invisible (the cross-corpus RAG-leak wall). The owner is stamped from the token, never a
body field, and never surfaced in a hit. Chunking + the embedder are CENTRAL parts (chunking / embedding) so the
code-point boundaries + the histogram are proven identical ×3; the real embedder + vector DB + a smarter splitter swap
in behind these routes (INTEROP.md)."""
import os
from typing import Annotated, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, StrictInt, StrictStr, field_validator

from ..core import store
from ..core.errors import invalid, require_identity
from ..parts.chunking import chunk_count, chunk_end, chunk_slice, chunk_start
from ..parts.embedding import cosine, embed
from ..parts.env_int import env_int
from ..parts.well_formed import WellFormedStr, make_well_formed

router = APIRouter(prefix="/rag", tags=["rag"])
# state in `store`: ns "rag_documents" "<owner>\x1f<doc_id>" -> {id, owner, text, chunks:[{ordinal,start,end,vector}]}.
# the composite key partitions by owner (no cross-owner clobber); the `owner` field also scopes the query scan. ×3.


_CHUNK_SIZE = env_int(os.getenv("RAG_CHUNK_SIZE"), 400, 1)
_CHUNK_OVERLAP = env_int(os.getenv("RAG_CHUNK_OVERLAP"), 80, 0)
_MAX_CHUNKS = env_int(os.getenv("RAG_MAX_CHUNKS"), 1000, 1)
if not 0 <= _CHUNK_OVERLAP < _CHUNK_SIZE:   # fail-loud at startup: the stride size-overlap must be >= 1 (else no progress / infinite loop)
    raise RuntimeError("RAG_CHUNK_OVERLAP must satisfy 0 <= RAG_CHUNK_OVERLAP < RAG_CHUNK_SIZE")


class IngestIn(BaseModel):
    doc_id: WellFormedStr
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


@router.post("/documents", status_code=201)
def ingest(data: IngestIn, owner: str = Depends(require_identity)) -> dict:   # authenticated mutation (no/invalid token -> 401)
    # contain the text BEFORE it is chunked / embedded / stored — a lone surrogate becomes U+FFFD so no slice ever 5xxs
    # on serialize (the lone-surrogate crash class); the stored text is then UTF-8-safe and byte-identical ×3
    text = make_well_formed(data.text)
    n = chunk_count(text, _CHUNK_SIZE, _CHUNK_OVERLAP)
    if n > _MAX_CHUNKS:
        raise invalid(f"document too large: {n} chunks exceeds the {_MAX_CHUNKS} limit")   # soft-DoS ceiling -> 422
    chunks = []
    for i in range(n):
        start = chunk_start(_CHUNK_SIZE, _CHUNK_OVERLAP, i)
        end = chunk_end(text, _CHUNK_SIZE, _CHUNK_OVERLAP, i)
        chunks.append({"ordinal": i, "start": start, "end": end, "vector": embed(chunk_slice(text, start, end))})
    # owner from the token, never a body field; the composite key partitions by owner so B can't overwrite A's doc_id.
    # a blind put REPLACES the whole record (re-ingest = last-writer-wins; NOT a get-then-put RMW)
    store.put("rag_documents", f"{owner}\x1f{data.doc_id}",
              {"id": data.doc_id, "owner": owner, "text": text, "chunks": chunks})
    return {"doc_id": data.doc_id, "chunks": n}


@router.post("/query")
def query(data: QueryIn, caller: str = Depends(require_identity)) -> dict:   # a POST is a mutation -> authenticated (no/invalid token -> 401)
    qv = embed(make_well_formed(data.query))   # contain the query too, so a lone-surrogate query embeds identically ×3
    hits = []
    # unbounded-safe: ranked top-k — at most k hits (k clamped), never the corpus; the full-scan is the documented
    # embeddings-index-swap-at-scale limit. read-scope: only the caller's own docs (owner FIELD == caller).
    for d in store.values("rag_documents"):
        if d.get("owner") != caller:          # read-scoping: another owner's chunks are invisible (cross-corpus leak wall)
            continue
        for c in d["chunks"]:
            # the hit text is DERIVED from the CURRENT stored text at the cited span (chunk_slice clamps -> never 5xx);
            # source carries the citation {doc_id, start, end}. owner/vector/ordinal stay internal — never in the hit.
            hits.append({"chunk_id": f"{d['id']}#{c['ordinal']}",
                         "text": chunk_slice(d["text"], c["start"], c["end"]),
                         "score": cosine(qv, c["vector"]),
                         "source": {"doc_id": d["id"], "start": c["start"], "end": c["end"]}})
    hits.sort(key=lambda h: (-h["score"], h["chunk_id"]))    # DETERMINISTIC: score desc, ties by chunk_id asc
    hits = hits[: data.k]                                     # at most k hits, ever
    return {"top": hits[0]["chunk_id"] if hits else None, "hits": hits}
