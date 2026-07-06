"""llm_usage — a per-call LLM token + cost METER. Dangerous property = COST INTEGRITY, all proven:
(1) COST IS SERVER-DERIVED, never client-supplied (anti-self-billing): the event carries TOKEN COUNTS only (no cost
    field, so a client cannot even express one); the cost is computed from a fixed, code-reviewed PRICE TABLE. An
    unknown (provider, model) — or a token dimension the table can't price — is 422, deny-by-default (never a silent
    $0/free, never an under-count). This is the billing.py amount-from-catalog rule applied per-call.
(2) NO DOUBLE-COUNT (exactly-once): recording is idempotent on (owner, identifier) — ONE atomic claim through the
    store `do` seam, so two processes racing the same identifier produce ONE event and the loser is served the
    winner. The slot is SCOPED to the owner (scoped_key) — an identifier is PRIVATE to its caller; caller B can never
    replay nor 409-grief caller A. A same-identifier retry with ANY different cost-input (provider/model/tokens/at/
    cost) is a 409 (the body fingerprint; no silent re-bill / cost-drift). The fingerprint hashes the request AS
    SENT — an omitted `at` hashes as a sentinel, never the server-minted default, so a byte-identical retry replays
    201 even across a wall-clock second tick (identical requests dedup identically regardless of arrival time).
(3) MONOTONIC / APPEND-ONLY: events are immutable — NO update/delete route exists. The owner's running total only
    grows. (4) AGGREGATE IS DERIVED, never stored: GET /summary sums the owner's events on read (the ledger pattern),
    so a stored total can never drift from the log. (5) OWNER-SCOPED: the owner is the bearer subject (require_identity,
    NOT a client field); summary + list count ONLY the caller's own events. (6) INTEGER-EXACT, OVERFLOW-SAFE: tokens
    and cost are SafeInt nanodollars; the rate is integer nanodollars-per-1000-tokens (real per-token rates are
    sub-nanodollar) and cost = tokens × rate // 1000 — no float anywhere, and the intermediate stays within the
    ×3-safe range for any real token count. A per-dimension token ceiling rejects an absurd count. Every route
    require_identity (no token 401), durable across restart."""
import os
import re
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..core import clock, store
from ..core.errors import SafeInt, invalid, require_identity
from ..core.usage import register_usage_sink
from ..parts.digest import digest_hex, scoped_key
from ..parts.idempotent_claim import claim_once
from ..parts.env_int import env_int
from ..parts.paginate import paginate
from ..parts.well_formed import WellFormedStr

router = APIRouter(prefix="/llm_usage", tags=["llm_usage"])

_ROUTE = "POST /llm_usage/events"          # the dedup-slot discriminator (per-operation slot)
_REPLAY = env_int(os.getenv("LLM_USAGE_REPLAY_WINDOW"), 300, 1)      # seconds; the `at` anti-backdate window (stripe seam)
_MAX_TOKENS = env_int(os.getenv("LLM_USAGE_MAX_TOKENS"), 10000000, 1)  # per-dimension sanity ceiling (SafeInt is too loose)

# THE PRICE TABLE (policy, code-reviewed) — (provider, model) -> {dimension: nanodollars-per-1000-tokens}. The rate is
# an INTEGER (real per-token rates are sub-nanodollar — $0.15/1M = 0.15 nd/token — so per-token rounds to free; per-1000
# keeps it an integer AND keeps the intermediate tokens×rate within the ×3-safe 2^53 range for any real token count).
# cost = tokens × rate // 1000. EXTENSIBLE: add a (provider, model) or a dimension by editing this map (reviewed code
# change, immutable within a release — a call's cost is deterministic at record time). NEVER empty (a meter with no
# prices would 422 every event). Same data + same cost ×3 (pinned by the manifest cost cases).
_PRICES = {
    ("openai", "gpt-4o"): {"input": 2_500_000, "output": 10_000_000, "cache_read": 1_250_000},
    ("openai", "gpt-4o-mini"): {"input": 150_000, "output": 600_000, "cache_read": 75_000},
    ("anthropic", "claude-3-5-sonnet"): {"input": 3_000_000, "output": 15_000_000, "cache_read": 300_000, "cache_write": 3_750_000},
    ("anthropic", "claude-sonnet-4-6"): {"input": 3_000_000, "output": 15_000_000, "cache_read": 300_000, "cache_write": 3_750_000},
    ("anthropic", "claude-3-5-haiku"): {"input": 800_000, "output": 4_000_000, "cache_read": 80_000, "cache_write": 1_000_000},
    # the offline provider's row: exists so the metering wire is provable offline (armed via AI_USAGE_METER_FAKE);
    # every rate 0 — a priced-at-zero provider is EXPLICIT policy, not a silent $0 (an unknown model still 422s).
    ("fake", "fake"): {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "reasoning": 0},
}
if not _PRICES:                                # fail LOUD at import if the table is empty (else every event 422s silently)
    raise RuntimeError("llm_usage price table is empty")

# the event's token field -> the price dimension it bills under (FIXED order -> a deterministic ×3 body-hash)
_DIMS = (("input_tokens", "input"), ("output_tokens", "output"), ("cache_read_input_tokens", "cache_read"),
         ("cache_creation_input_tokens", "cache_write"), ("reasoning_tokens", "reasoning"))

# state in store: seq "llm_usage_event" the monotonic id · ns "llm_usage_events" scoped_key(route, owner, identifier)
# -> the WHOLE record {id, owner, identifier, provider, model, <5 token dims>, at, cost_nanodollars, body_hash} in ONE
# atomic claim. The slot is OWNER-scoped (an identifier is private to its caller). Same names + shape ×3.


class EventIn(BaseModel):
    identifier: WellFormedStr                                       # the idempotency key (the provider call id) — REQUIRED
    provider: WellFormedStr
    model: WellFormedStr
    input_tokens: Annotated[SafeInt, Field(ge=0)] = 0
    output_tokens: Annotated[SafeInt, Field(ge=0)] = 0
    cache_read_input_tokens: Annotated[SafeInt, Field(ge=0)] = 0
    cache_creation_input_tokens: Annotated[SafeInt, Field(ge=0)] = 0
    reasoning_tokens: Annotated[SafeInt, Field(ge=0)] = 0
    at: Optional[SafeInt] = None                                    # client event time (epoch s); validated within ±_REPLAY
    # NOTE: there is deliberately NO `cost` field — the server derives it (anti-self-billing). Extra fields are ignored.


def _derive_cost(provider: str, model: str, data: "EventIn") -> int:
    # cost_nanodollars = Σ_dim tokens[dim] × rate[dim] // 1000 (integer-EXACT). The SERVER owns the price table. Unknown
    # (provider, model) OR a dimension with tokens>0 that the model can't price -> 422 (deny-by-default; never bill 0/free,
    # never under-count). A per-dimension token ceiling rejects an absurd count (SafeInt alone is too loose).
    rates = _PRICES.get((provider, model))
    if rates is None:
        raise invalid("no price for this provider/model")
    cost = 0
    for field, dim in _DIMS:
        n = getattr(data, field)
        if n == 0:
            continue
        if n > _MAX_TOKENS:
            raise invalid(f"{field} exceeds the per-call ceiling")
        rate = rates.get(dim)
        if rate is None:
            raise invalid(f"no price for the {dim} dimension of this model")
        cost += n * rate // 1000               # per-dim floor < 1 nanodollar; intermediate n*rate is ×3-safe (per-1000)
    return cost


def _body_hash(data: "EventIn", at_sent, cost: int) -> str:
    # the fingerprint over ALL cost-determining fields AS THE CLIENT SENT THEM — provider + model + EVERY token dim +
    # at + cost. A same-identifier retry with ANY different cost-input is a 409 (no silent re-bill / cost-drift).
    # provider IS in the hash (a provider-swap with a coincidentally-equal price must NOT replay). `at_sent` is the
    # CLIENT's at, or the "-" sentinel when omitted (str(int) can never render a bare "-") — the server-minted default
    # must NEVER enter the hash: it is wall-clock-quantized, so two byte-identical no-`at` retries straddling a second
    # boundary would fingerprint differently and 409 instead of replaying a legitimate client retry.
    return digest_hex("provider", data.provider, "model", data.model, "in", data.input_tokens, "out", data.output_tokens,
                      "cr", data.cache_read_input_tokens, "cw", data.cache_creation_input_tokens,
                      "re", data.reasoning_tokens, "at", at_sent, "cost", cost)


def _public(rec: dict) -> dict:
    # the event view — NEVER the internal body_hash; the cost is the server-derived nanodollars.
    return {k: rec[k] for k in ("id", "identifier", "provider", "model", "input_tokens", "output_tokens",
                                "cache_read_input_tokens", "cache_creation_input_tokens", "reasoning_tokens",
                                "at", "cost_nanodollars")}


def _commit(owner: str, data: "EventIn", at: int, at_sent) -> tuple:
    # THE transport-free recording CORE, shared by the HTTP route AND the in-process usage sink — the ONE writer of
    # llm_usage_events (one namespace writer, one price authority). Derives the SERVER cost (422 on unknown/unpriced),
    # fingerprints the body AS SENT, and claims the (owner, identifier) slot exactly-once. Returns (public|None,
    # status, detail): 201 = recorded/replayed · 409/422 = refused (the route renders it as problem+json, the sink
    # raises it as a contained error). `at` is the STORED/returned time; `at_sent` is the client's at or the "-" sentinel.
    try:
        cost = _derive_cost(data.provider, data.model, data)   # SERVER-derived (anti-self-billing); 422 on unknown/unpriced
    except HTTPException as e:
        return None, e.status_code, str(e.detail)
    body_hash = _body_hash(data, at_sent, cost)
    scoped = scoped_key(_ROUTE, owner, data.identifier)    # owner-scoped dedup slot (private to the caller)
    prior = store.get("llm_usage_events", scoped)          # fast path: a settled identifier never mints
    if prior is None:
        eid = store.next_id("llm_usage_event")             # mint BEFORE the claim (a race loser's id is a harmless gap)
        rec = {"id": eid, "owner": owner, "identifier": data.identifier, "provider": data.provider, "model": data.model,
               "input_tokens": data.input_tokens, "output_tokens": data.output_tokens,
               "cache_read_input_tokens": data.cache_read_input_tokens,
               "cache_creation_input_tokens": data.cache_creation_input_tokens,
               "reasoning_tokens": data.reasoning_tokens, "at": at, "cost_nanodollars": cost, "body_hash": body_hash}
        prior = claim_once("llm_usage_events", scoped, rec)   # exactly-once: a racing loser gets the winner
    if prior.get("owner") != owner:            # defense-in-depth (the scoped slot already isolates callers)
        return None, 409, "identifier is not owned by this caller"
    if prior["body_hash"] != body_hash:        # same identifier, different cost-inputs -> 409 (no re-bill / cost-drift)
        return None, 409, "identifier reused with a different body"
    return _public(prior), 201, ""


@router.post("/events", status_code=201)
def record(data: EventIn, request: Request, owner: str = Depends(require_identity)) -> dict:
    now = clock.current(request)
    at = data.at if data.at is not None else now           # the STORED/returned time; the hash gets `at` AS SENT
    if abs(at - now) > _REPLAY:                # validate `at` BEFORE the body-hash (anti-backdate)
        raise invalid("at is outside the replay window")
    public, status, detail = _commit(owner, data, at, "-" if data.at is None else data.at)  # the shared recording core
    if status != 201:
        raise HTTPException(status_code=status, detail=detail)
    return public


def _record_event(owner: str, call: dict, now: int) -> None:
    # THE usage-sink recorder registered INTO the core hook — the SAME writer as the HTTP route (so this domain's
    # namespace keeps exactly one writer and this price table stays the single cost authority). A producer calls
    # core.usage_record(owner, call, now); core forwards it here. The sink omits the client `at` (the "-" sentinel),
    # so a byte-identical retry replays across a wall-clock tick. A refused event (unpriced/409) RAISES, so the core
    # seam CONTAINS + logs it and the producer's run continues (a broken meter never breaks a chat).
    ev = EventIn(identifier=call["identifier"], provider=call["provider"], model=call["model"],
                 input_tokens=call.get("input_tokens", 0), output_tokens=call.get("output_tokens", 0),
                 cache_read_input_tokens=call.get("cache_read_input_tokens", 0),
                 cache_creation_input_tokens=call.get("cache_creation_input_tokens", 0),
                 reasoning_tokens=call.get("reasoning_tokens", 0))
    _public_rec, status, detail = _commit(owner, ev, now, "-")
    if status != 201:
        raise ValueError(detail)


def _parse_ts(v: Optional[str]) -> Optional[int]:
    if v is None or v == "":
        return None
    if not re.fullmatch(r"-?[0-9]+", v):       # a from/to that isn't an integer epoch -> 422 (strict, ×3)
        raise invalid("from/to must be an integer epoch")
    return int(v)


_SUM_FIELDS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens",
               "reasoning_tokens", "cost_nanodollars")


@router.get("/summary")
def summary(request: Request, owner: str = Depends(require_identity)) -> dict:
    # unbounded-safe: scalar aggregate — sums the OWNER's events into per-(provider,model) totals + a grand total; returns
    # no raw event collection (the O(n) scan is the documented store-swap-at-scale limit, like ledger's balance). OWNER-
    # ISOLATION: only rec["owner"] == owner is counted (cross-owner-proven). The total is DERIVED, never stored.
    q = request.query_params
    frm, to, model = _parse_ts(q.get("from")), _parse_ts(q.get("to")), q.get("model")
    groups: dict = {}
    total = {f: 0 for f in _SUM_FIELDS}
    for rec in store.values("llm_usage_events"):
        if rec["owner"] != owner:
            continue
        if (frm is not None and rec["at"] < frm) or (to is not None and rec["at"] > to):
            continue
        if model and rec["model"] != model:   # `model` falsy (absent OR present-empty) -> no filter (×3 with go/node)
            continue
        g = groups.setdefault((rec["provider"], rec["model"]),
                              {"provider": rec["provider"], "model": rec["model"], **{f: 0 for f in _SUM_FIELDS}})
        for f in _SUM_FIELDS:
            g[f] += rec[f]
            total[f] += rec[f]
    by_model = [groups[k] for k in sorted(groups)]
    return {**total, "by_model": by_model}


@router.get("/events")
def list_events(owner: str = Depends(require_identity), limit: str = "", cursor: str = "") -> dict:
    # OWNER-scoped audit trail, BOUNDED through the paginate part (no one-shot dump). NEVER the body_hash; ordered by id.
    mine = sorted((_public(r) for r in store.values("llm_usage_events") if r["owner"] == owner), key=lambda r: r["id"])
    page, nxt, ok = paginate(mine, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


# self-register the recorder into the core usage hook at module import — guaranteed pre-serve (the app wiring imports
# every domain module to mount routers before the server listens), so no request can race an unregistered sink.
register_usage_sink(_record_event)
