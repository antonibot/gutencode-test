"""search — token full-text search over a durable corpus. The dangerous property is RETRIEVAL HONESTY:
AND-complete (a document containing ALL query terms IS returned — no false negatives) and AND-sound (a document
missing ANY query term is NOT returned — no false positives), with whole-token matching only ('qui' never
matches 'quick'), case-insensitively. Deny-by-default: an empty or term-less query returns [] — never the whole
corpus. Ranking is DETERMINISTIC and identical in all three languages: total query-term frequency descending,
then id ascending. Re-indexing an id replaces its document (the old tokens stop matching). Tokenization is
lowercase ascii alphanumerics (split on everything else) — the documented v1 limit; the corpus is durable.
USER-SCOPED: a document belongs to the caller who indexed it, and a query sees ONLY the caller's own corpus.
POST /search/index requires identity (the core require_identity seam — ANY authenticated caller; no/invalid token
-> 401) and stamps the document's `owner` from the authenticated subject — NEVER a body field (IndexIn has no
`owner`, so a smuggled one is dropped). GET /search/query ALSO requires identity and filters the corpus scan to
the caller's own docs: a doc whose owner != caller is invisible (the api_keys not-yours==not-found pattern, applied
to a corpus scan — a non-owner's doc never appears in results), and an unauthenticated query is 401. The stored
`owner` is private (never returned: query yields only {query, results=[id]}; index yields only {id, tokens})."""
import re
from typing import Annotated, List

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, StrictStr, field_validator

from ..core import store
from ..core.errors import SafeInt, require_identity

router = APIRouter(prefix="/search", tags=["search"])
# state in `store`: ns "search_docs" "<owner>\x1f<id>" -> {id, text, owner} (the WHOLE document in one write; same
# names ×3). The composite key partitions by owner so caller B can't overwrite caller A's id (the cross-owner WRITE
# wall — the int id can't carry the \x1f separator); `owner` is the authenticated indexer — private (never returned),
# the per-caller read filter, AND the write partition.


class IndexIn(BaseModel):
    id: Annotated[SafeInt, Field(ge=1)]
    text: StrictStr

    @field_validator("text")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value:                # content may contain anything printable — but an empty document is a mistake
            raise ValueError("must be non-empty")
        return value


class IndexOut(BaseModel):
    id: int
    tokens: int


class QueryOut(BaseModel):
    query: str
    results: List[int]


def _tokens(text: str) -> List[str]:
    # lowercase ascii alphanumerics, split on everything else — identical tokenization in all three languages
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


@router.post("/index", response_model=IndexOut, status_code=201)
def index(doc: IndexIn, caller: str = Depends(require_identity)) -> IndexOut:
    # one write replaces the document; owner stamped from the TOKEN (never the body — IndexIn has no `owner`); the
    # composite key partitions by owner so caller B can't overwrite caller A's id (the cross-owner WRITE wall)
    store.put("search_docs", f"{caller}\x1f{doc.id}", {"id": doc.id, "text": doc.text, "owner": caller})
    return IndexOut(id=doc.id, tokens=len(set(_tokens(doc.text))))


@router.get("/query", response_model=QueryOut)
def query(q: str = "", caller: str = Depends(require_identity)) -> QueryOut:
    terms = _tokens(q)
    if not terms:                    # deny-by-default: no terms -> no results, never the whole corpus
        return QueryOut(query=q, results=[])
    # unbounded-safe: ranked top-k — returns at most k results (k clamped), never the corpus; the full-scan is the documented search-index-swap-at-scale limit.
    scored = []
    for doc in store.values("search_docs"):
        if doc.get("owner") != caller:                     # USER-SCOPED: a doc that isn't yours is invisible (not-yours==not-found)
            continue
        toks = _tokens(doc["text"])
        if all(t in toks for t in terms):                  # AND: every query term present as a whole token
            scored.append((sum(toks.count(t) for t in terms), doc["id"]))
    scored.sort(key=lambda s: (-s[0], s[1]))               # deterministic: frequency desc, then id asc
    return QueryOut(query=q, results=[doc_id for _, doc_id in scored])
