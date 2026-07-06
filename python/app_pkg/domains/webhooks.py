"""webhooks — Standard-Webhooks signing (outbound /send) + verification with REPLAY-DEDUP (inbound /verify). Signing
is the CENTRAL `signing` part (this domain CALLS sign_v1/verify_v1, never re-inlines HMAC). The msg
counter, the sent log, and the inbound seen-set live in the durable `store` seam. The clock is the `clock`
seam (a `now` query param counts only under APP_TEST_CLOCK=1).

DANGEROUS PROPERTY: delivery integrity at a trust boundary — a forgery, a REPLAY, or a silently-rejected ROTATED
delivery is takeover-class. (1) MULTI-SECRET ROTATION: /send signs with EVERY active secret (space-joined); /verify
accepts a delivery matching ANY active secret — so rotating a secret never drops a valid webhook. (2) INBOUND
REPLAY-DEDUP (exactly-once): a same-id 2nd /verify inside the window is flagged a DUPLICATE so the consumer skips it.

TWO routes, TWO auth models: POST /send is ADMIN-ONLY (core require_admin) — it signs with the SERVER secret, so
an open route is signature forgery; no token 401, a non-admin 403, resolved BEFORE the payload check (×3). POST /verify
is intentionally PUBLIC (its `mutation-auth: public` declaration) — a caller verifies a webhook it received, no session."""
import os

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, StrictStr

from ..core import clock, store
from ..core.errors import SafeInt, invalid, require_admin
from ..parts.digest import scoped_key
from ..parts.signing import sign_v1, verify_v1

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# active signing secrets — NEWLINE-separated list, each ASCII-trimmed (empties dropped). UNSET falls back to the demo
# default; a present-but-BLANK value resolves to NO active secret -> deny (never the placeholder), so blanking the env
# can't leave it open. Multiple secrets = ROTATION. The trim set is the ASCII whitespace bytes ONLY (NOT str.strip()'s
# Unicode set): a stdlib trim DIVERGES ×3 (JS .trim() strips U+FEFF/BOM, py/go strip U+0085/NEL), so a contaminated
# secret would key to a DIFFERENT HMAC per runtime (a silent cross-runtime delivery break) — ASCII-only is byte-identical.
_WS = " \t\r\n\v\f"
_SECRETS = [t for t in (s.strip(_WS) for s in os.getenv("WEBHOOK_SECRETS", "whsec_demo_change_me").split("\n")) if t]
_TOLERANCE = 300                   # seconds; replay window (two-sided, the ts is signed)
_ROUTE = "POST /webhooks/verify"   # the dedup-slot discriminator — scope a replay-dedup to THIS route + the matched secret
# state: seq "webhooks_msg" · ns "webhooks_sent" (the signed log) · ns "webhooks_seen" (the inbound replay-dedup set,
# DURABLE-FOREVER — the catalog store has no reaper; the 300s freshness is the upstream tolerance check, not row deletion).


class SignedOut(BaseModel):
    id: str
    timestamp: int
    payload: str
    signature: str


class VerifyIn(BaseModel):
    id: StrictStr
    timestamp: SafeInt
    payload: StrictStr
    signature: StrictStr


class Decision(BaseModel):
    valid: bool
    duplicate: bool = False        # a valid-but-already-seen replay (the consumer skips it) — best-effort exactly-once


@router.post("/send", response_model=SignedOut, status_code=201)
def send(request: Request, payload: str = "", subject: str = Depends(require_admin)) -> SignedOut:
    # ADMIN-ONLY: require_admin resolves authn -> authz BEFORE the payload check, so a no-token caller is 401 and a
    # non-admin is 403 (never the "payload required" 422) — identical ×3. Signing with the server secret => open = forgery.
    if not payload:
        raise invalid("payload required")
    timestamp = clock.current(request)
    msg_id = f"msg_{store.next_id('webhooks_msg')}"
    signature = " ".join(sign_v1(s, msg_id, timestamp, payload) for s in _SECRETS)   # sign with ALL active secrets (rotation)
    store.put("webhooks_sent", msg_id, {"id": msg_id, "timestamp": timestamp, "payload": payload})
    return SignedOut(id=msg_id, timestamp=timestamp, payload=payload, signature=signature)


@router.post("/verify", response_model=Decision)
def verify(request: Request, data: VerifyIn) -> Decision:
    # mutation-auth: public — INTENTIONALLY unauthenticated (a stateless+dedup HMAC check; no session caller). The PUBLIC
    # `{valid}` shape leaks no reason (a reason-oracle is a signing oracle — SW spec); the reason is captured internally.
    now = clock.current(request)
    verified = False
    for secret in _SECRETS:                            # multi-secret: accept if ANY active secret verifies (rotation)
        if verify_v1(secret, data.id, data.timestamp, data.payload, data.signature, now, _TOLERANCE):
            verified = True
            break
    if not verified:
        return Decision(valid=False)                   # forged / stale / dotted-id -> nothing to dedup (no seen-set pump)
    # INBOUND REPLAY-DEDUP, scoped to the EVENT IDENTITY (route + event id) — NOT which secret matched. The matched
    # secret is CALLER-CONTROLLABLE: a sender broadcasts one candidate per active secret, so presenting only ANOTHER
    # secret's candidate would flip a per-secret slot and replay the SAME event as new DURING a rotation. Any active
    # secret authenticates the same event, so the secret has no role in the dedup key. The dedup is BEHIND the signature
    # gate (only a validly-signed event reaches it). Fast-path a LOCKLESS read; reserve the write lock (store.do) for a
    # genuinely-new id; the do() resolves a concurrent first-race.
    slot = scoped_key(_ROUTE, "wh", data.id)
    if store.get("webhooks_seen", slot) is not None:
        return Decision(valid=True, duplicate=True)
    rec = {"id": data.id, "ts": data.timestamp}
    is_new = store.do("webhooks_seen", slot, lambda cur: (rec, True) if cur is None else (None, False))
    return Decision(valid=True, duplicate=not is_new)  # only one concurrent first wins the atomic claim
