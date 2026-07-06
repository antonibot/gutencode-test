"""ai_memory — a long-term, owner-scoped agent-memory store whose dangerous property is RETENTION-ENFORCED / BOUNDED
(proven in invariant_test.py): a memory past its retention (TTL-expired, cap-evicted, or explicitly forgotten) is
DETERMINISTICALLY not retrievable, and an owner's store can NEVER grow unbounded.
(1) BOUNDED (the headline): a per-(owner,scope) index caps memories per scope (evict past MAX_MEMORIES); a per-owner
    scope index caps the NUMBER of scopes (a NEW scope past MAX_SCOPES is REJECTED 422) — a per-scope cap ALONE leaves
    the per-owner total unbounded because `scope` is a free-form caller string (the partition-COUNT trap: bound the
    KEY-SPACE, not only the per-key value).
(2) EVICTION: evict the min-(importance ASC, created_at ASC, id ASC) memory, EXPIRED-FIRST — a deterministic superset
    of FIFO (default importance 0 => pure FIFO) that never drops a LIVE memory while an expired one keeps its slot.
(3) TTL: optional ttl_seconds => a SERVER-DERIVED expires_at (smuggled expires_at discarded; the sum is overflow-guarded
    + clamped to 2^53-1 so the derived int is identical x3); lazy read-hide, `expired <=> now > expires_at` (AT = LIVE),
    inert without APP_TEST_CLOCK.
(4) FORGET: DELETE by id (purge the scope-index entry THEN the row) or DELETE a whole scope (scope REQUIRED — no silent
    wipe-all); a forgotten memory is 404 + list-excluded.
(5) OWNER-SCOPED: owner = require_identity (never a body field); rows keyed by the composite <owner>\x1f<id> (id
    server-minted via next_id => by-id is O(1) + owner-scoped by construction; the \x1f separator is a control char
    well_formed rejects, so the key can't be forged); not-yours == 404. The per-scope index is the LIVENESS set — a
    read gates on it (never a raw row scan that could resurrect an evicted/torn orphan). scope is a PARTITION, NOT a
    security boundary (only owner is). content/tags/metadata are CONTAINED (keys AND values) before store.
Retrieval is per-scope, newest-first (created_at desc, id asc), expired-excluded, paginated, with optional ?tag= and
?q= (ASCII-only case-fold substring — a deterministic FLOOR, not 'world-class keyword search'). Append-only: NO update,
NO dedup (recurrence is information for a log). Same names + DECISIONS in all three languages (see INTEROP.md)."""
import os
from typing import Annotated, Dict, List, Optional

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field, StrictStr, field_validator

from ...core import clock, store
from ...core.errors import IntPath, SafeInt, invalid, not_found, require_identity
from ...parts.env_int import env_int
from ...parts.paginate import paginate
from ...parts.well_formed import make_well_formed, require_well_formed

router = APIRouter(prefix="/ai_memory", tags=["ai_memory"])
_OWNER = "ai_memory_owner"    # "<owner>"          -> [scope, ...]                                   (bounds the scope COUNT)
_SCOPE = "ai_memory_scope"    # "<owner>\x1f<scope>" -> [{id, created_at, expires_at, importance}]   (the liveness set)
_MEM = "ai_memory_memory"     # "<owner>\x1f<id>"    -> {id, owner, scope, content, tags, metadata, importance, created_at, expires_at}

_MAX_SAFE = 9007199254740991  # 2^53 - 1: the cross-language safe-integer ceiling (go int64 vs JS float vs py big-int)
_MAX_TAG_BYTES = 128          # a single tag's byte cap (a fixed structural bound)
_MAX_SCOPE_BYTES = 256        # a scope name's byte cap (it is a key component + a per-owner list member)


def _max_scopes() -> int:         return env_int(os.getenv("AI_MEMORY_MAX_SCOPES"), 100, 1)          # per-owner scope cap (the headline)
def _max_memories() -> int:       return env_int(os.getenv("AI_MEMORY_MAX_MEMORIES"), 1000, 1)       # per-scope memory cap
def _max_tags() -> int:           return env_int(os.getenv("AI_MEMORY_MAX_TAGS"), 20, 1)
def _max_content_bytes() -> int:  return env_int(os.getenv("AI_MEMORY_MAX_CONTENT_BYTES"), 16384, 1)
def _max_metadata_bytes() -> int: return env_int(os.getenv("AI_MEMORY_MAX_METADATA_BYTES"), 4096, 1)


def _mkey(owner: str, mid: int) -> str:   return f"{owner}\x1f{mid}"     # owner-partitioned rows (B can't read A's id)
def _skey(owner: str, scope: str) -> str: return f"{owner}\x1f{scope}"   # owner-partitioned per-scope index


def _clean(value: str, what: str) -> str:
    # a scope name: require_well_formed REJECTS a control char (< 0x20, so the \x1f key separator can't be forged) ->
    # 422; make_well_formed then CONTAINS a lone surrogate (>= 0x20, accepted by require) to U+FFFD so the composite key
    # AND the echoed scope are always UTF-8-serializable (the contain-before-serialize rule). Go MakeWellFormed = identity.
    require_well_formed(value, what)
    cleaned = make_well_formed(value)
    if len(cleaned.encode()) > _MAX_SCOPE_BYTES:
        raise invalid(f"{what} is too large")
    return cleaned


def _expires_at(now: int, ttl_seconds: Optional[int]) -> int:
    # DERIVED (server-computed; a smuggled expires_at is discarded). 0 = never expires. The sum is a DERIVED integer:
    # guard the overflow BEFORE the add (node loses precision AT 2^53 inside the add) then CLAMP to 2^53-1 so it is
    # identical x3 and always representable (the strict-int-DERIVED rule).
    if ttl_seconds is None:
        return 0
    if ttl_seconds > _MAX_SAFE - now:
        return _MAX_SAFE
    return now + ttl_seconds


def _expired(entry: dict, now: int) -> bool:
    exp = entry["expires_at"]
    return exp != 0 and now > exp    # AT the boundary is LIVE (now > exp, NOT >=)


def _evict_key(entry: dict, now: int):
    # the eviction order: EXPIRED-FIRST (live=0 sorts before live=1), then lowest importance, oldest, lowest id — a
    # deterministic superset of FIFO (all-integer tuple => identical x3). min() over this picks the victim.
    live = 0 if _expired(entry, now) else 1
    return (live, entry["importance"], entry["created_at"], entry["id"])


def _in_index(owner: str, scope: str, mid: int) -> bool:
    # the per-scope index is LIVENESS-AUTHORITATIVE: an id is live only if it is IN its scope index. This closes the
    # evict/torn-window orphan-resurrection (a lingering row whose index entry was already dropped is NOT live).
    return any(e["id"] == mid for e in (store.get(_SCOPE, _skey(owner, scope)) or []))


def _fold(s: str) -> str:
    # ASCII-only case fold (A-Z -> a-z); non-ASCII stays BYTE-EXACT. py .casefold() / go / node diverge on unicode
    # case, so ?q= is deliberately ASCII-only to stay identical x3 (a labeled floor, not locale-aware search).
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def _clean_tags(tags: Optional[List[str]]) -> List[str]:
    if not tags:
        return []
    mx = _max_tags()
    if len(tags) > mx:
        raise invalid(f"too many tags (max {mx})")
    out = []
    for t in tags:
        require_well_formed(t, "a tag")           # reject control chars (incl. \x1f) + empty
        cleaned = make_well_formed(t)             # CONTAIN a lone surrogate before store (a re-read would 5xx otherwise)
        if len(cleaned.encode()) > _MAX_TAG_BYTES:
            raise invalid("a tag is too large")
        out.append(cleaned)
    return out


def _clean_metadata(metadata: Optional[Dict[str, str]]) -> Dict[str, str]:
    if not metadata:
        return {}
    out = {}
    for k, v in metadata.items():
        # CONTAIN the metadata KEY and VALUE: require_well_formed ACCEPTS a lone surrogate (>= 0x20); only
        # make_well_formed strips it -> an un-contained KEY is a STORED 5xx poison a later re-read 500s on. Contain both.
        out[make_well_formed(k)] = make_well_formed(v)
    # the byte-cap is a raw UTF-8 byte-SUM over the CONTAINED, COLLAPSED dict (NOT the raw entries) -> identical x3:
    # go's json.Decode collapses distinct surrogate keys to one U+FFFD map entry BEFORE the count, so py/node must sum
    # the post-containment `out` (a hostile 2048-surrogate-key body collapses to one key ×3), never the raw input.
    total = sum(len(k.encode()) + len(v.encode()) for k, v in out.items())
    if total > _max_metadata_bytes():
        raise invalid("metadata is too large")
    return out


def _public(rec: dict) -> dict:
    out = {"id": rec["id"], "scope": rec["scope"], "content": rec["content"], "tags": rec["tags"],
           "metadata": rec["metadata"], "importance": rec["importance"], "created_at": rec["created_at"]}
    if rec["expires_at"]:
        out["expires_at"] = rec["expires_at"]
    return out


class AddIn(BaseModel):
    # NULL PARITY (x3): every OPTIONAL field is Optional[...] so an explicit `null` is treated as ABSENT (use the
    # default) — identical to go (a JSON null decodes to a nil `*T`) and node (an explicit `!== null` guard). content is
    # REQUIRED (null -> 422); a null tag ELEMENT or metadata VALUE is an invalid value (null is not a string -> 422).
    content: StrictStr                                                    # the memory text (allowlist read -> owner/id/expires_at smuggles ignored)
    scope: Optional[StrictStr] = None                                    # null/absent -> "default"; NOT a security boundary
    tags: Optional[List[StrictStr]] = None                               # string list; a numeric/null tag -> 422 (no coercion x3)
    metadata: Optional[Dict[str, StrictStr]] = None                      # string->string; a numeric/null/nested value -> 422
    importance: Optional[Annotated[SafeInt, Field(ge=0)]] = None         # null/absent -> 0; strict int in 2^53 else 422
    ttl_seconds: Optional[Annotated[SafeInt, Field(ge=1)]] = None        # strict positive int in 2^53; drives the derived expires_at

    @field_validator("content")
    @classmethod
    def _content_nonempty(cls, value: str) -> str:
        if not value:
            raise ValueError("must be non-empty")
        return value


def _reserve_scope(owner: str, scope: str) -> bool:
    """Reserve `scope` in the per-owner scope index; return True iff REJECTED (a NEW scope past MAX_SCOPES)."""
    mx = _max_scopes()
    rejected = False

    def fn(scopes):
        nonlocal rejected
        cur = scopes or []
        if scope in cur:
            return None, None                     # already present -> no write
        if len(cur) >= mx:
            rejected = True
            return None, None                     # reject: leave unwritten (the partition-COUNT bound)
        # unbounded-safe: the per-owner scope list is bounded at MAX_SCOPES by the reject-past-cap guard above — a NEW
        # scope past the cap is 422, never an eviction (evicting a scope = a silent mass-delete). This bounds the
        # partition COUNT — the number of KEYS in the namespace, a different axis from one list's length.
        return cur + [scope], None

    store.do(_OWNER, owner, fn)
    return rejected


def _append_evict(owner: str, scope: str, entry: dict, now: int) -> int:
    """Append `entry` to the per-scope index; if past MAX_MEMORIES evict min-(importance,created_at,id) EXPIRED-FIRST.
    Returns the evicted id (0 = none)."""
    mx = _max_memories()
    evicted = 0

    def fn(entries):
        nonlocal evicted
        # unbounded-safe: the per-scope index is bounded at MAX_MEMORIES by the importance-weighted, expired-first
        # eviction below — deliberately NOT a positional drop-oldest tail-slice (that silently drops the most-
        # consolidated old facts; age != staleness in a long-term store). Proven by I-BOUNDED + I-EVICT-CORRECT.
        cur = (entries or []) + [entry]
        if len(cur) > mx:
            victim = min(range(len(cur)), key=lambda i: _evict_key(cur[i], now))
            evicted = cur[victim]["id"]
            cur = cur[:victim] + cur[victim + 1:]
        return cur, None

    store.do(_SCOPE, _skey(owner, scope), fn)
    return evicted


@router.post("/memories", status_code=201)
def add_memory(data: AddIn, request: Request, owner: str = Depends(require_identity)) -> dict:
    # mutation-auth: identity — an authenticated caller adds a memory as ITSELF; owner is the token subject, never a
    # body field [guarded_fields: owner].
    scope = _clean(data.scope if data.scope is not None else "default", "the scope")   # null/absent scope -> default (x3)
    importance = data.importance if data.importance is not None else 0                 # null/absent importance -> 0 (x3)
    content = make_well_formed(data.content)                              # CONTAIN before store (a re-read must never 5xx)
    if len(content.encode()) > _max_content_bytes():
        raise invalid("content is too large")
    tags = _clean_tags(data.tags)
    metadata = _clean_metadata(data.metadata)
    now = clock.current(request)
    expires_at = _expires_at(now, data.ttl_seconds)                      # derived, overflow-guarded + clamped
    mid = store.next_id("ai_memory_id")                                  # server-mint (globally unique); a rejected add wastes it as a benign gap
    if _reserve_scope(owner, scope):                                     # bound the partition COUNT (the headline) FIRST
        raise invalid(f"too many scopes (max {_max_scopes()})")
    entry = {"id": mid, "created_at": now, "expires_at": expires_at, "importance": importance}
    evicted = _append_evict(owner, scope, entry, now)                   # bound the per-scope count; returns the evicted id
    # the row, written AFTER the do seams (the callbacks are PURE). A crash here leaves a benign index/row skew the
    # read-side None-check hides (a 404, never a torn 500).
    store.put(_MEM, _mkey(owner, mid),
              {"id": mid, "owner": owner, "scope": scope, "content": content, "tags": tags,
               "metadata": metadata, "importance": importance, "created_at": now, "expires_at": expires_at})
    if evicted:
        store.delete_(_MEM, _mkey(owner, evicted))                       # purge the evicted row (the index already dropped it)
    out = {"id": mid, "scope": scope, "created_at": now}
    if expires_at:
        out["expires_at"] = expires_at
    return out


@router.get("/memories")
def list_memories(request: Request, scope: str = "default", tag: str = "", q: str = "",
                  limit: str = "", cursor: str = "", owner: str = Depends(require_identity)) -> dict:
    # read-scope: owner — the caller's own memories in ONE scope (a partition, not a security boundary); newest-first;
    # EXPIRED excluded; BOUNDED through paginate. The scope INDEX is the liveness set (never a raw cross-owner row scan).
    if not scope:
        scope = "default"                                            # an empty ?scope= reads the default partition (x3 with go/node)
    scope = _clean(scope, "the scope")
    now = clock.current(request)
    # the OWNER index is authoritative for scope existence: a scope not listed for this owner has NO retrievable memories.
    # Gating the read here keeps the retrievable set bounded by MAX_SCOPES x MAX_MEMORIES even if a concurrent
    # forget_scope||add orphaned a scope index (the two-key race — closed on the RETRIEVABLE surface). [I-RACE-FORGET-SCOPE]
    in_owner = scope in (store.get(_OWNER, owner) or [])
    entries = (store.get(_SCOPE, _skey(owner, scope)) or []) if in_owner else []
    rows = []
    for e in entries:
        if _expired(e, now):
            continue                                                     # lazy expiry: an expired memory is read-hidden
        rec = store.get(_MEM, _mkey(owner, e["id"]))
        if rec is not None:                                              # read-side None-check hides an index/row torn window
            rows.append(rec)
    if tag:
        needle = make_well_formed(tag)
        rows = [r for r in rows if needle in r["tags"]]
    if q:
        needle = _fold(make_well_formed(q))
        rows = [r for r in rows if needle in _fold(r["content"])]
    rows.sort(key=lambda r: (-r["created_at"], r["id"]))                # newest-first, tie id asc (all-integer -> x3 stable)
    page, nxt, ok = paginate([_public(r) for r in rows], cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/memories/{id}")
def get_memory(id: IntPath, request: Request, owner: str = Depends(require_identity)) -> dict:
    # unbounded-safe: a single memory by key; OWNER-scoped (the composite key includes owner -> not-yours == 404). The
    # scope index is LIVENESS-AUTHORITATIVE: an expired OR evicted/torn (not-in-index) memory is 404 (never resurrected).
    rec = store.get(_MEM, _mkey(owner, id))
    if rec is None:
        raise not_found("memory")
    now = clock.current(request)
    # liveness = scope still in the OWNER index (race-safe) AND id in the scope index AND not expired. The owner-index
    # gate makes an orphan row (scope removed by a concurrent forget_scope) non-retrievable. [I-RACE-FORGET-SCOPE]
    if (_expired(rec, now) or rec["scope"] not in (store.get(_OWNER, owner) or [])
            or not _in_index(owner, rec["scope"], id)):
        raise not_found("memory")
    return _public(rec)


@router.delete("/memories/{id}", status_code=204)
def forget_memory(id: IntPath, owner: str = Depends(require_identity)) -> Response:
    # mutation-auth: identity — forget ONE memory: purge it from its scope index (via do) THEN delete the row.
    # OWNER-scoped: another owner's id is a different slot -> 404 (existence never leaks).
    rec = store.get(_MEM, _mkey(owner, id))
    if rec is None:
        raise not_found("memory")
    scope = rec["scope"]

    def fn(entries):
        return [e for e in (entries or []) if e["id"] != id], None       # a filtered REBUILD (shrinks — not an append/grow)

    store.do(_SCOPE, _skey(owner, scope), fn)
    store.delete_(_MEM, _mkey(owner, id))
    return Response(status_code=204)


@router.delete("/memories", status_code=204)
def forget_scope(scope: str = "", owner: str = Depends(require_identity)) -> Response:
    # mutation-auth: identity — forget a WHOLE scope. scope is REQUIRED (no silent wipe-all): missing/empty -> 422.
    if not scope:
        raise invalid("scope is required")
    scope = _clean(scope, "the scope")

    def drop(scopes):
        return [s for s in (scopes or []) if s != scope], None           # free the scope slot in the owner index (a rebuild)

    # OWNER-FIRST (B): remove the scope from the owner index atomically BEFORE reaping its index + rows. Because reads
    # gate on the owner index, the scope's memories become non-retrievable the instant this returns; and a concurrent
    # add that re-reserves the scope re-counts it (a bounded counted-but-empty slot) instead of leaving an uncounted-
    # but-retrievable orphan. (A narrow physical-orphan row window remains; reclaimed lazily — see INTEROP / v2.)
    store.do(_OWNER, owner, drop)
    for e in (store.get(_SCOPE, _skey(owner, scope)) or []):
        store.delete_(_MEM, _mkey(owner, e["id"]))                       # delete every row in the scope
    store.delete_(_SCOPE, _skey(owner, scope))                          # drop the scope index
    return Response(status_code=204)
