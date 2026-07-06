"""billing — subscription billing where over/under-charging is impossible by construction, scoped to the
AUTHENTICATED owner. The amount is DERIVED from a fixed plan catalog (the input model has no amount field, so a
client-supplied amount cannot even be expressed); an unknown plan is rejected 422, deny-by-default — the system
never silently bills. The owner is the bearer token's subject (the core require_identity seam), NOT a
client-supplied field — so a caller only ever reads/cancels THEIR OWN subscriptions (another owner's subscription
is 404, indistinguishable from missing). The lifecycle is MONOTONIC: active -> canceled only; cancel is idempotent
(a second cancel returns the same canceled record) and writes a TERMINAL value, so concurrent cancels converge and
a canceled subscription can never return to active. Deny-by-default (no token -> 401). State lives in the durable
store seam — a cancellation survives a restart."""
from typing import Dict

from fastapi import APIRouter, Depends
from pydantic import BaseModel, StrictStr

from ..core import store
from ..core.errors import IntPath, invalid, not_found, require_identity

router = APIRouter(prefix="/billing", tags=["billing"])

# the plan catalog is POLICY (fixed, code-reviewed): plan -> monthly price in cents — the ONLY source of amounts
_PLANS: Dict[str, int] = {"free": 0, "pro": 2000, "enterprise": 10000}
# state in `store`: seq "billing_sub" the monotonic id · ns "billing_subs" str(id) ->
# {id, owner, plan, status, amount} (the WHOLE record in one write; same names + shape ×3 languages)


class SubscribeIn(BaseModel):
    plan: StrictStr   # the ONLY input — owner is the authenticated subject, amount is derived from the catalog


class Subscription(BaseModel):
    id: int
    owner: str
    plan: str
    status: str
    amount: int


@router.post("/subscriptions", response_model=Subscription, status_code=201)
def subscribe(data: SubscribeIn, owner: str = Depends(require_identity)) -> Subscription:
    if data.plan not in _PLANS:                 # unknown plan -> deny-by-default (never silently subscribe/bill)
        raise invalid("unknown plan")
    sid = store.next_id("billing_sub")          # atomic, durable; a crash before the put loses the id (a gap)
    # the amount comes from the catalog ALONE — SubscribeIn has no amount field, so a client cannot smuggle one;
    # the owner is the authenticated subject (NOT input), so a client cannot subscribe as someone else
    sub = {"id": sid, "owner": owner, "plan": data.plan, "status": "active", "amount": _PLANS[data.plan]}
    store.put("billing_subs", str(sid), sub)    # the WHOLE record in ONE atomic write
    return Subscription(**sub)


@router.get("/subscriptions/{sub_id}", response_model=Subscription)
def get_subscription(sub_id: IntPath, owner: str = Depends(require_identity)) -> Subscription:
    sub = store.get("billing_subs", str(sub_id))
    if sub is None or sub["owner"] != owner:    # owner-scoped: another owner's sub is 404, never revealed
        raise not_found("subscription")
    return Subscription(**sub)


@router.post("/subscriptions/{sub_id}/cancel", response_model=Subscription)
def cancel(sub_id: IntPath, owner: str = Depends(require_identity)) -> Subscription:
    sub = store.get("billing_subs", str(sub_id))
    if sub is None or sub["owner"] != owner:    # owner-scoped: you cannot cancel another owner's subscription
        raise not_found("subscription")
    # rmw-safe: monotonic + idempotent — "canceled" is TERMINAL, so this get->put converges under any
    # interleaving (two concurrent cancels write the same value; nothing ever writes "active" back)
    canceled = {**sub, "status": "canceled"}
    store.put("billing_subs", str(sub_id), canceled)
    return Subscription(**canceled)
