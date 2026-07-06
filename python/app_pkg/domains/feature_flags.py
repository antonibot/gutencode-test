"""feature_flags — deterministic percentage rollout via stable hash bucketing. The dangerous property is
STABLE BUCKETING: a subject's bucket is a fixed function of (key, subject) through the digest part, so
evaluation is DETERMINISTIC (the same subject always gets the same answer at a given rollout) and MONOTONIC
under rollout increase — raising the percentage only ever ADMITS more subjects, so a subject already enabled
never flips off during a ramp (no flapping). rollout is an integer 0..100; bucket 0..99; enabled iff
bucket < rollout (so 0 = nobody, 100 = everybody). Durable across restart.

WRITES ARE ADMIN-ONLY: a feature flag is a control-plane kill-switch — an anonymous flip is a live P0
(turn any flag 0<->100 for everyone). So create (POST) and set-rollout (PUT) require the 'admin' role (the core
require_admin seam): no token is 401, a non-admin is 403, resolved BEFORE any body/path validation (identical
×3). The READS stay OPEN on purpose: GET a flag and especially
GET .../evaluate are the runtime hot path consuming apps call on every request — gating them would break those
apps, so evaluate MUST NOT be admin."""
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, StrictInt

from ..core import store
from ..core.errors import conflict, not_found, require_admin
from ..parts.digest import digest_hex
from ..parts.well_formed import WellFormedStr, require_well_formed

router = APIRouter(prefix="/feature_flags", tags=["feature_flags"])
# state in `store`: ns "feature_flags_records" key -> {key, rollout} (×3 identical)

Rollout = Annotated[StrictInt, Field(ge=0, le=100)]


class FlagIn(BaseModel):
    key: WellFormedStr
    rollout: Rollout = 0


class RolloutIn(BaseModel):
    rollout: Rollout


def _bucket(key: str, subject: str) -> int:
    # the stable bucket: first 32 bits of sha256(key:subject) mod 100 — fixed per (key, subject), ×3 identical
    return int(digest_hex(key, subject)[:8], 16) % 100


@router.post("", status_code=201)
def create(data: FlagIn, subject: str = Depends(require_admin)) -> dict:
    rec = {"key": data.key, "rollout": data.rollout}
    # claim-once via the do seam: a get-then-put RACES — two concurrent creates of one key both pass the check and
    # the second overwrites the first. do() holds the write lock across read+write; first writer wins -> 409.
    created = store.do("feature_flags_records", data.key,
                       lambda cur: (rec, True) if cur is None else (None, False))
    if not created:
        raise conflict("flag key taken")
    return rec


def _load(key: str) -> dict:
    flag = store.get("feature_flags_records", require_well_formed(key, "the flag key"))
    if flag is None:
        raise not_found("flag")
    return flag


@router.get("/{key}")
def get_flag(key: str) -> dict:
    # read-scope: global — app-global flag config (admins set the rollout via require_admin; any caller reads the flag state).
    return _load(key)


@router.put("/{key}")
def set_rollout(key: str, data: RolloutIn, subject: str = Depends(require_admin)) -> dict:
    flag = _load(key)
    flag = {**flag, "rollout": data.rollout}
    store.put("feature_flags_records", flag["key"], flag)
    return flag


@router.get("/{key}/evaluate")
def evaluate(key: str, subject: str = "") -> dict:
    # read-scope: global — deterministic flag evaluation for a caller-supplied subject; app-global config, no per-owner data.
    flag = _load(key)
    subject = require_well_formed(subject, "the subject")
    # enabled iff the subject's fixed bucket is under the current rollout — deterministic + monotonic
    return {"key": flag["key"], "subject": subject, "enabled": _bucket(flag["key"], subject) < flag["rollout"]}
