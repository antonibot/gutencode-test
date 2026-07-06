"""jobs — the async job QUEUE: enqueue a unit of background work; a trusted worker pool CLAIMS the next ready job
(an exclusive lease), then COMPLETEs or FAILs it; a failed job retries with deterministic backoff until it is
dead-lettered. The dangerous properties, all proven (same ×3 as jobs.go / jobs.js):
(1) AT-MOST-ONCE CLAIM: a ready job is leased to AT MOST ONE worker at a time — the claim is a single-key do()-CAS,
    so two workers racing the same job cannot both win (I-CLAIM-ONCE). The pick is the lowest-id ready job, sorted
    BEFORE the CAS (store.values is rowid order, not stable ×3).
(2) COMPLETION-AUTH (the fencing token): claim mints a rotating lease_token; complete/fail REQUIRE it and the CAS
    asserts token==current AND status==running — so a STALE worker (its lease expired, the job reclaimed by another)
    cannot complete/reset the new claimant's job (I-COMPLETE-AUTH). Acquire-exclusivity is NOT release-safety.
(3) BOUNDED RETRY: the handler is delivered at most max_attempts times whether the failure is EXPLICIT (fail) or a
    CRASH (the lease lapses and the job is reclaimed) — attempts increments at CLAIM, and BOTH the fail path AND the
    reclaim path dead-letter at attempts>=max (I-RETRY-BOUNDED). A poison job that crashes the worker cannot retry
    forever.
(4) DETERMINISTIC BACKOFF: on each fail, run_at = now + min(base * 2^min(attempts,30), cap) — no jitter, identical
    ×3 (I-BACKOFF-DET); the exponent is clamped + the env limits bounded so base*2^attempt never overflows go int64
    nor loses node precision.
(5) OWNER-SCOPED reads: enqueue stamps the owner from the authenticated subject (never a body field); get/list
    return ONLY the caller's jobs, a cross-owner id is 404 (existence never leaks). The worker pool (claim/complete/
    fail) is the trusted SERVICE seam — cross-owner infrastructure, authorized by the service token + the lease.
(6) PAYLOAD CONTAINED: the opaque payload is ×3-safe via well_formed.sanitize_json (a lone surrogate -> U+FFFD, the
    2^53 number ceiling) — durable storage never crashes serialization nor diverges ×3 (I-PAYLOAD-SAFE).
State lives in the durable store (ns "job_queue_records", key str(id)); delivery is at-least-once (handlers MUST be
idempotent) — the universal queue contract. See INTEROP.md for the SQS / River / BullMQ / Sidekiq mapping."""
import os

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, StrictStr

from ..core import clock, store
from ..core.errors import IntPath, SafeInt, conflict, invalid, not_found, require_identity, require_service
from ..parts.digest import scoped_key
from ..parts.env_int import env_int
from ..parts.paginate import paginate
from ..parts.well_formed import make_well_formed, require_well_formed, sanitize_json

router = APIRouter(prefix="/job_queue", tags=["jobs"])
# state in `store`: ns "job_queue_records" str(id) -> {id, owner, kind, payload, queue, status, attempts, max_attempts,
# run_at, lease_until, lease_token, created_at, updated_at, last_error}. status in {queued, running, done, dead}. ×3.

_NS = "job_queue_records"
_SEQ = "job_queue_job"
_LEASE_ROUTE = "/job_queue/lease"
_MAX_ATTEMPTS_CAP = 1000     # a per-job max_attempts override is clamped to [1, this] — the hard bound on deliveries
_DELAY_CAP = 31536000        # a delay is clamped to [0, 1 year] — no negative, no absurd-future run_at
_SHIFT_CAP = 30              # 2^30 ceiling on the backoff exponent so base*2^attempt can't overflow int64 / lose precision


_DEFAULT_MAX_ATTEMPTS = env_int(os.getenv("JOB_QUEUE_MAX_ATTEMPTS"), 20, 1, _MAX_ATTEMPTS_CAP)
_BACKOFF_BASE = env_int(os.getenv("JOB_QUEUE_BACKOFF_BASE_SECONDS"), 2, 1, 3600)
_BACKOFF_CAP = env_int(os.getenv("JOB_QUEUE_BACKOFF_CAP_SECONDS"), 3600, _BACKOFF_BASE, 86400)
_VISIBILITY = env_int(os.getenv("JOB_QUEUE_VISIBILITY_SECONDS"), 300, 1, 86400)


def _backoff(attempts: int) -> int:
    # run_at delta = min(base * 2^min(attempts, 30), cap) — DETERMINISTIC, no jitter; the clamped exponent + the env
    # clamps keep base*2^shift < 2^53 so the value is identical ×3 (go int64 / node float / python all agree).
    return min(_BACKOFF_BASE * (2 ** min(attempts, _SHIFT_CAP)), _BACKOFF_CAP)


def _public(rec: dict) -> dict:
    # the owner-facing view — every field EXCEPT lease_token (the worker's fencing capability, returned only by claim)
    return {k: rec[k] for k in ("id", "owner", "kind", "payload", "queue", "status", "attempts", "max_attempts",
                                "run_at", "lease_until", "created_at", "updated_at", "last_error")}


def _claimable(rec: dict, now: int) -> bool:
    # a queued job that is DUE, or a running job whose lease has LAPSED (a crashed worker's job, reclaimed)
    return ((rec["status"] == "queued" and rec["run_at"] <= now)
            or (rec["status"] == "running" and rec["lease_until"] <= now))


class EnqueueIn(BaseModel):
    kind: StrictStr
    payload: dict = {}
    queue: StrictStr = "default"
    max_attempts: SafeInt | None = None     # strict body int (rejects 5.0 / >2^53 ×3); None -> the env default
    delay_seconds: SafeInt | None = None     # strict body int; None -> 0


class TokenIn(BaseModel):
    lease_token: StrictStr                   # the fencing capability claim handed the worker
    error: StrictStr = ""


@router.post("", status_code=201)
def enqueue(data: EnqueueIn, request: Request, owner: str = Depends(require_identity)) -> dict:
    kind = require_well_formed(data.kind, "kind")
    queue = require_well_formed(data.queue, "queue")
    payload = sanitize_json("payload", data.payload)          # opaque + ×3-safe (surrogate -> U+FFFD, 2^53 ceiling)
    max_attempts = _DEFAULT_MAX_ATTEMPTS if data.max_attempts is None else data.max_attempts
    if not 1 <= max_attempts <= _MAX_ATTEMPTS_CAP:           # a client override is range-CHECKED (reject, not silently clamped)
        raise invalid("max_attempts must be between 1 and 1000")
    delay = 0 if data.delay_seconds is None else data.delay_seconds
    if not 0 <= delay <= _DELAY_CAP:
        raise invalid("delay_seconds must be between 0 and 31536000")
    now = clock.current(request)
    jid = store.next_id(_SEQ)
    rec = {"id": jid, "owner": owner, "kind": kind, "payload": payload, "queue": queue, "status": "queued",
           "attempts": 0, "max_attempts": max_attempts, "run_at": now + delay, "lease_until": 0, "lease_token": "",
           "created_at": now, "updated_at": now, "last_error": ""}   # owner/id/status/run_at/lease_* server-set, never the body
    store.put(_NS, str(jid), rec)
    return _public(rec)


@router.post("/claim")
def claim(request: Request, _svc: str = Depends(require_service)):
    # mutation-auth: service — the worker pool is a trusted SERVICE, not an end user; gated by core.require_service.
    now = clock.current(request)
    # unbounded-safe: + unscoped-read: the claim scans ALL jobs across owners to pick the lowest-id ready one — a
    # trusted SERVICE-pool operation (cross-owner infrastructure, NOT a per-user read); O(n) is the documented
    # store-swap-at-scale limit (a ready-index is the v2 upgrade). The sort is REQUIRED: store.values is rowid /
    # go-map order, not stable ×3, and the manifest asserts the exact claimed job — pin id-ascending before picking.
    candidates = sorted((j for j in store.values(_NS) if _claimable(j, now)), key=lambda j: j["id"])

    def take(cur):
        if cur is None or not _claimable(cur, now):
            return None, None                                 # vanished, or another worker took it in the lock -> skip
        if cur["attempts"] >= cur["max_attempts"]:
            dead = {**cur, "status": "dead", "lease_token": "", "lease_until": 0, "updated_at": now}
            return dead, None                                 # exhausted on reclaim -> dead-letter (NOT a delivery) [I-RETRY-BOUNDED]
        attempts = cur["attempts"] + 1
        token = scoped_key(_LEASE_ROUTE, str(cur["id"]), str(attempts))   # deterministic ×3, rotates each (re)claim
        claimed = {**cur, "status": "running", "attempts": attempts, "lease_until": now + _VISIBILITY,
                   "lease_token": token, "updated_at": now}
        return claimed, claimed

    for cand in candidates:
        claimed = store.do(_NS, str(cand["id"]), take)        # single-key CAS — the loser sees not-claimable -> None
        if claimed is not None:
            return {**_public(claimed), "lease_token": claimed["lease_token"]}   # the worker needs the token to finish
    return Response(status_code=204)                          # nothing ready (the worker polls again)


@router.post("/{job_id}/complete")
def complete(job_id: IntPath, data: TokenIn, request: Request, _svc: str = Depends(require_service)) -> dict:
    # mutation-auth: service — only the trusted worker pool finishes a job, and only under the CURRENT lease token.
    now = clock.current(request)

    def fn(cur):
        if cur is None:
            return None, ("not_found", None)
        if cur["status"] != "running" or cur["lease_token"] != data.lease_token:
            return None, ("conflict", None)                  # stale/wrong token or not running -> the stale worker is fenced [I-COMPLETE-AUTH]
        done = {**cur, "status": "done", "lease_token": "", "updated_at": now}
        return done, ("ok", done)

    outcome, rec = store.do(_NS, str(job_id), fn)
    if outcome == "not_found":
        raise not_found("job")
    if outcome == "conflict":
        raise conflict("job is not held under this lease")
    return _public(rec)


@router.post("/{job_id}/fail")
def fail(job_id: IntPath, data: TokenIn, request: Request, _svc: str = Depends(require_service)) -> dict:
    # mutation-auth: service — only the lease holder may fail a job; a failed job retries (backoff) or dead-letters.
    now = clock.current(request)
    err = make_well_formed(data.error)                       # surrogate-safe; the body cap bounds its length

    def fn(cur):
        if cur is None:
            return None, ("not_found", None)
        if cur["status"] != "running" or cur["lease_token"] != data.lease_token:
            return None, ("conflict", None)
        if cur["attempts"] >= cur["max_attempts"]:
            dead = {**cur, "status": "dead", "lease_token": "", "last_error": err, "updated_at": now}
            return dead, ("ok", dead)                        # bound reached -> dead-letter [I-RETRY-BOUNDED]
        requeued = {**cur, "status": "queued", "lease_token": "", "run_at": now + _backoff(cur["attempts"]),
                    "last_error": err, "updated_at": now}    # deterministic backoff [I-BACKOFF-DET]
        return requeued, ("ok", requeued)

    outcome, rec = store.do(_NS, str(job_id), fn)
    if outcome == "not_found":
        raise not_found("job")
    if outcome == "conflict":
        raise conflict("job is not held under this lease")
    return _public(rec)


@router.get("/{job_id}")
def get_job(job_id: IntPath, owner: str = Depends(require_identity)) -> dict:
    rec = store.get(_NS, str(job_id))
    if rec is None or rec["owner"] != owner:                 # cross-owner id -> 404 (existence never leaks)
        raise not_found("job")
    return _public(rec)


@router.get("")
def list_jobs(owner: str = Depends(require_identity), limit: str = "", cursor: str = "") -> dict:
    # SCOPED read: only the caller's jobs leave the store (filtered on the authenticated owner FIELD), id-sorted for a
    # stable paged walk, then a BOUNDED page; a stranger gets an empty page, never 403.
    items = [_public(j) for j in sorted(store.values(_NS), key=lambda j: j["id"]) if j["owner"] == owner]
    page, nxt, ok = paginate(items, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}
