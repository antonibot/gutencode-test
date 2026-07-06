"""reporting — a self-contained, owner-scoped read-side AGGREGATION store (a CQRS read model the app FEEDS; it does
NOT read other domains' stores — the boundary rule). A caller ingests typed FACT rows into a named dataset, then POSTs
a GROUP BY rollup (COUNT/SUM/MIN/MAX + equality filters + deterministic order + bounded pagination), and can drain a
dataset. Dangerous properties, all proven ×3 (python/go/node):
(1) AGGREGATION CORRECTNESS: COUNT/SUM/MIN/MAX are EXACTLY right and byte-identical ×3 (the search retrieval-honesty
    analog — a wrong sum still returns 200); the invariant recomputes the expectation independently.
(2) OWNER-SCOPED AGGREGATION: an aggregate NEVER includes another owner's facts. The owner is the bearer subject
    (require_identity, NEVER a client field) and is a MANDATORY conjunct on every scan (query/list/drain); a stranger
    gets an empty result, never a 403 (existence never leaks).
(3) DERIVED-OVERFLOW SAFETY: measure inputs are STRICT integers bounded ±(2^53-1) (reject 5.0/5.5/str/bool, ×3); the
    SUM is a derived value accumulated over a scan — it PREDICTS overflow BEFORE each add and fails loud (422) at
    2^53, so no wrapped go-int64 / precision-lost node-float is ever returned.
(4) DETERMINISTIC GROUP ORDER: groups are keyed + ordered by the digest_hex of their PRE-HASHED group-by values
    (an ASCII-hex key — injective and byte-identical ×3, sidestepping the python-codepoint / node-UTF-16 sort split),
    so the same query returns groups in the same order in all three languages regardless of store scan order.
Exactly-once ingest: a fact is immutable and idempotent on (owner, dataset, key) via scoped_key + claim_once (a
re-POST returns the SAME fact; corrections are compensating events — see INTEROP.md). Every route require_identity;
durable across restart. The in-process store.values scan is the documented store-swap-at-scale limit (see INTEROP.md)."""
from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, StrictStr

from ..core import clock, store
from ..core.errors import invalid, require_identity
from ..parts.digest import digest_hex, scoped_key
from ..parts.idempotent_claim import claim_once
from ..parts.paginate import paginate
from ..parts.well_formed import make_well_formed, require_well_formed

router = APIRouter(prefix="/reporting", tags=["reporting"])
_ROUTE = "POST /reporting/facts"          # the owner-scoped fact-slot discriminator (same string ×3, used by the drain)
_MAX = 9007199254740991                   # 2**53-1: the magnitude every language holds EXACTLY (the ×3-safe ceiling)
_OPS = ("count", "sum", "min", "max")

# state in store: seq "reporting_fact" the monotonic id · ns "reporting_facts"
# scoped_key(route, owner, digest_hex(_h(dataset), _h(key))) -> the WHOLE record
# {id, owner, dataset, key, dimensions:{str:str}, measures:{str:int}, created_at} in ONE atomic claim. The slot is
# OWNER-scoped (scoped_key hashes the owner IN) AND injective in (dataset,key) (each pre-hashed). Same names ×3.


def _h(s: str) -> str:
    # pre-hash a component so a ':'-containing value can't forge another key — digest_hex joins with ':', and a
    # pre-hashed component is fixed-width colon-free hex (the relations injective-preimage idiom).
    return digest_hex(s)


def _clean(s: str, what: str) -> str:
    # contain-BEFORE-hash then validate: a lone surrogate -> U+FFFD (so a stored value never 5xxs a later re-read),
    # THEN reject empty / control (<0x20) / >1024 code points. Applied to EVERY response-bound string incl. map KEYS
    # and the query's group_by / aggregate `as` names (an un-contained key would be a stored 5xx poison).
    return require_well_formed(make_well_formed(s), what)


def _strict_int(v, what: str) -> int:
    # a JSON INTEGER in the ×3-safe range: reject a float (5.0/5.5 -> not int ×3), a bool (a distinct JSON type),
    # a string, and a magnitude past ±(2^53-1). `type(v) is int` excludes bool (type(True) is bool) AND float.
    if type(v) is not int or abs(v) > _MAX:
        raise invalid(what)
    return v


class FactIn(BaseModel):
    dataset: StrictStr
    key: StrictStr
    dimensions: dict = {}                  # {str: str} — grouped/filtered on; validated below (no owner/id field exists -> no mass-assignment)
    measures: dict = {}                    # {str: strict-int} — summed; validated below


class AggIn(BaseModel):
    op: str
    field: Optional[str] = None
    as_: Optional[str] = Field(default=None, alias="as")   # 'as' is a python keyword -> alias; the output name


class QueryIn(BaseModel):
    dataset: StrictStr
    group_by: List[str] = []               # dimension names (list[str] -> a non-string element is 422)
    aggregate: List[AggIn] = []
    filter: dict = {}                      # {dim: value} equality, implicit AND


def _public(rec: dict) -> dict:
    return {"id": rec["id"], "owner": rec["owner"], "dataset": rec["dataset"], "key": rec["key"],
            "dimensions": rec["dimensions"], "measures": rec["measures"], "created_at": rec["created_at"]}


@router.post("/facts", status_code=201)
def create(data: FactIn, request: Request, owner: str = Depends(require_identity)) -> dict:
    dataset = _clean(data.dataset, "dataset must be non-empty with no control characters")
    key = _clean(data.key, "key must be non-empty with no control characters")
    if not isinstance(data.dimensions, dict) or not isinstance(data.measures, dict):
        raise invalid("dimensions and measures must be objects")
    dims = {}
    for k, v in data.dimensions.items():
        if not isinstance(v, str):
            raise invalid("dimension values must be strings")
        dims[_clean(k, "dimension name")] = _clean(v, "dimension value")   # contain KEY and value (contain-before-store)
    meas = {}
    for k, v in data.measures.items():
        meas[_clean(k, "measure name")] = _strict_int(v, "measure values must be integers in the safe range")
    now = clock.current(request)
    slot = scoped_key(_ROUTE, owner, digest_hex(_h(dataset), _h(key)))     # owner-scoped + injective in (dataset,key); it IS the id
    prior = store.get("reporting_facts", slot)                            # fast path: a settled fact never re-writes
    if prior is None:
        rec = {"id": slot, "owner": owner, "dataset": dataset, "key": key,
               "dimensions": dims, "measures": meas, "created_at": now}   # id = the deterministic slot; owner from the token
        prior = claim_once("reporting_facts", slot, rec)                  # exactly-once: a repeat (dataset,key) returns the winner (immutable)
    return _public(prior)


@router.get("/facts")
def list_facts(owner: str = Depends(require_identity), dataset: str = "", limit: str = "", cursor: str = "") -> dict:
    # SCOPED read: only the caller's own facts leave the store (filtered on the authenticated owner FIELD as stored,
    # never a client value), id-sorted for a stable paged walk, then a BOUNDED page; a stranger gets an empty
    # page, never 403.
    ds = make_well_formed(dataset)                                        # contain the optional filter (empty = no filter)
    mine = sorted((_public(r) for r in store.values("reporting_facts")
                   if r["owner"] == owner and (ds == "" or r["dataset"] == ds)), key=lambda r: r["id"])
    page, nxt, ok = paginate(mine, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


def _validate_aggs(aggregate: List[AggIn]) -> list:
    aggs, seen = [], set()
    for a in aggregate:
        if a.op not in _OPS:
            raise invalid("unknown aggregate op")
        if a.op == "count":
            if a.field is not None:
                raise invalid("count takes no field")
            field, as_ = None, _clean(a.as_ if a.as_ is not None else "count", "aggregate name")
        else:
            if a.field is None:
                raise invalid(a.op + " requires a field")
            field = _clean(a.field, "aggregate field")
            as_ = _clean(a.as_ if a.as_ is not None else a.op + "_" + field, "aggregate name")
        if as_ in seen:
            raise invalid("duplicate aggregate name")
        seen.add(as_)
        aggs.append((a.op, field, as_))
    if not aggs:
        raise invalid("at least one aggregate is required")
    return aggs


@router.post("/query")
def query(data: QueryIn, owner: str = Depends(require_identity), limit: str = "", cursor: str = "") -> dict:
    # SCOPED aggregation: the owner conjunct is INLINE (never a shared helper — the owner check stays visible at the
    # read site);
    # the O(n) facts scan is the documented store-swap-at-scale limit, the GROUPS result rides paginate (unbounded
    # group cardinality).
    dataset = _clean(data.dataset, "dataset must be non-empty with no control characters")
    group_by = [_clean(n, "group_by name") for n in data.group_by]
    aggs = _validate_aggs(data.aggregate)
    if not isinstance(data.filter, dict):
        raise invalid("filter must be an object")
    filt = {}
    for k, v in data.filter.items():
        if not isinstance(v, str):
            raise invalid("filter values must be strings")
        filt[_clean(k, "filter name")] = _clean(v, "filter value")
    # id-sorted so the SUM accumulation order (hence any overflow trip) is deterministic ×3
    matching = sorted((r for r in store.values("reporting_facts")
                       if r["owner"] == owner and r["dataset"] == dataset
                       and all(r["dimensions"].get(fk) == fv for fk, fv in filt.items())),
                      key=lambda r: r["id"])
    groups: dict = {}
    for r in matching:
        values = [r["dimensions"].get(n) for n in group_by]              # None for a missing dimension
        kh = digest_hex(*[_h(v) if v is not None else "" for v in values])   # injective, ASCII-hex, ×3-identical
        g = groups.get(kh)
        if g is None:
            g = {"values": values, "count": 0, "sum": {}, "min": {}, "max": {}}
            groups[kh] = g
        g["count"] += 1
        for op, field, as_ in aggs:
            if op == "count" or field not in r["measures"]:
                continue
            v = r["measures"][field]
            if op == "sum":
                acc = g["sum"].get(as_, 0)
                if (v > 0 and acc > _MAX - v) or (v < 0 and acc < -_MAX - v):   # predict overflow BEFORE the add
                    raise invalid("an aggregate sum exceeds the safe integer range")
                g["sum"][as_] = acc + v
            elif op == "min":
                g["min"][as_] = v if as_ not in g["min"] else min(g["min"][as_], v)
            elif op == "max":
                g["max"][as_] = v if as_ not in g["max"] else max(g["max"][as_], v)
    out = []
    for kh in sorted(groups):                                            # ASCII-hex order, identical ×3
        g = groups[kh]
        key_obj = {n: val for n, val in zip(group_by, g["values"])}
        vals = {}
        for op, field, as_ in aggs:
            if op == "count":
                vals[as_] = g["count"]
            elif op == "sum":
                vals[as_] = g["sum"].get(as_, 0)                         # SUM of no matching values = 0 (documented)
            elif op == "min" and as_ in g["min"]:
                vals[as_] = g["min"][as_]                                # MIN/MAX of no values -> OMITTED (never 0)
            elif op == "max" and as_ in g["max"]:
                vals[as_] = g["max"][as_]
        out.append({"key": key_obj, "values": vals})
    page, nxt, ok = paginate(out, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"groups": page, "next_cursor": nxt}


@router.delete("/facts")
def drain(request: Request, owner: str = Depends(require_identity)) -> dict:
    # OWNER-scoped filtered DRAIN (the relations bulk-delete precedent): dataset is REQUIRED (>=1 anchor — a bare
    # drain is 422, never delete-all-by-accident) + optional ?<dim>=<val> equality filters. unbounded-safe: a filtered
    # delete drains ALL matching (a bounded page would strand rows); owner conjunct INLINE, only the caller's facts.
    q = request.query_params
    ds_raw = q.get("dataset")
    if not ds_raw:
        raise invalid("dataset is required")
    dataset = _clean(ds_raw, "dataset must be non-empty with no control characters")
    filt = {}
    for k in q.keys():
        if k == "dataset":
            continue
        filt[_clean(k, "filter name")] = _clean(q.get(k), "filter value")
    deleted = 0
    for r in list(store.values("reporting_facts")):
        if r["owner"] == owner and r["dataset"] == dataset \
                and all(r["dimensions"].get(fk) == fv for fk, fv in filt.items()):
            store.delete_("reporting_facts", r["id"])                     # id IS the slot (deterministic scoped_key)
            deleted += 1
    return {"deleted": deleted}
