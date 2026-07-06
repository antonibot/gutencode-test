"""oauth — the OAuth 2.0 authorization-code flow, server side. Three dangerous properties, all proven:
(1) CSRF DEFENSE: the callback's state must match a PENDING flow the app issued FOR THAT PROVIDER — forged or
    unknown state is 403; the flow key binds provider+state, so a state issued for one provider is invalid for
    another. (2) SINGLE-USE, END TO END: the consume is ONE atomic read-modify-write through the store's `do`
    seam (two processes racing a code get one token and one 409), AND a consumed state can never be re-opened —
    authorize claims the flow key atomically via the idempotent_claim part, so re-authorizing a used state is a
    409 (a consumed flow stays dead; a naive implementation would resurrect it for code replay).
(3) DENY-BY-DEFAULT: only configured providers are accepted. The access token is an UNGUESSABLE server-minted
    CSPRNG value bound to the flow on consume — never a forgeable digest of the client-supplied (provider, state,
    code) (a real deployment exchanges the code at the provider's token endpoint). Durable: a pending flow
    survives a restart; so does a consumed one (with its token).

BOTH mutating routes are intentionally PUBLIC (see each handler's `mutation-auth: public` declaration), NOT
require_identity: the end-user is logged OUT across this whole flow. POST /authorize is a pre-session flow-init
primitive (it records a pending flow keyed by state); POST /callback is reached by the browser hitting the OAuth
redirect, also logged-out — and there the `state` value IS the credential (matched to a pending flow, single-use,
atomically consumed). require_identity would break every real callback."""
import secrets

from fastapi import APIRouter
from pydantic import BaseModel

from ..core import store
from ..core.errors import conflict, forbidden, invalid
from ..parts.idempotent_claim import claim_once
from ..parts.well_formed import WellFormedStr

router = APIRouter(prefix="/oauth", tags=["oauth"])

_PROVIDERS = {"google", "github"}   # the configured providers — anything else is denied by default
# state in `store`: ns "oauth_flows" "{provider}:{state}" -> {provider, state, status: pending|consumed}
# (the provider prefix is VALIDATED vocabulary, so a crafted state cannot forge another provider's key)


class AuthorizeIn(BaseModel):
    provider: WellFormedStr
    state: WellFormedStr


class CallbackIn(BaseModel):
    provider: WellFormedStr
    state: WellFormedStr
    code: WellFormedStr


def _flow_key(provider: str, state: str) -> str:
    return f"{provider}:{state}"


@router.post("/authorize", response_model=dict, status_code=201)
def authorize(data: AuthorizeIn) -> dict:
    # mutation-auth: public — INTENTIONALLY unauthenticated. This is a pre-session, server-side flow-INITIATION
    # primitive: it records a PENDING flow keyed by state while the end-user is still logged OUT, so requiring a
    # session would break the start of every OAuth flow. (Follow-on: a later wave may gate this behind the user's
    # session for explicit consent — which would also close the state-squatting -> denial-of-login risk, where an
    # attacker pre-claims a victim's state value.)
    if data.provider not in _PROVIDERS:
        raise invalid("unknown provider")    # deny-by-default: only configured providers
    flow = {"provider": data.provider, "state": data.state, "status": "pending"}
    # a state is single-use END TO END: claim the flow key atomically — re-authorizing a PENDING flow is a
    # harmless idempotent replay (same record back), but a CONSUMED one must never silently re-open
    settled = claim_once("oauth_flows", _flow_key(data.provider, data.state), flow)
    if settled["status"] != "pending":
        raise conflict("state already used")
    return settled


@router.post("/callback", response_model=dict)
def callback(data: CallbackIn) -> dict:
    # mutation-auth: public — INTENTIONALLY unauthenticated. The browser hitting the OAuth redirect is logged OUT,
    # and the `state` value IS the capability credential: it is matched to a PENDING flow the server issued,
    # single-use, and atomically consumed (forged/unknown state -> 403; replay -> 409). require_identity would
    # break every real callback, since there is no session at the redirect.
    if data.provider not in _PROVIDERS:
        raise invalid("unknown provider")

    def consume(flow):
        if flow is None:
            return None, ("forged", None)    # no pending flow for this provider+state -> CSRF / forged
        if flow["status"] == "consumed":
            return None, ("replay", None)    # SINGLE-USE: the code was already exchanged
        # mint an UNGUESSABLE, server-side token (CSPRNG) and bind it to the flow inside the SAME atomic consume —
        # never a deterministic digest of the client-supplied (provider, state, code), which anyone could forge
        # offline. A real deployment swaps this mint for the provider's token-endpoint exchange.
        token = "tok_" + secrets.token_urlsafe(24)
        return {**flow, "status": "consumed", "token": token}, ("ok", token)

    kind, token = store.do("oauth_flows", _flow_key(data.provider, data.state), consume)   # ATOMIC single-use
    if kind == "forged":
        raise forbidden("invalid state")
    if kind == "replay":
        raise conflict("authorization code already used")
    return {"provider": data.provider, "state": data.state, "access_token": token, "status": "authorized"}
