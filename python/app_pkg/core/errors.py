"""Runtime `errors` — the ONE error envelope (RFC 9457 problem+json) + the server install hook. Every domain
raises via these helpers (never a bare HTTPException); `install_runtime(app)` registers the handlers (404s,
validation 422s, AND any unhandled exception -> 500) plus the observability+safety middleware (request id,
structured access log, body-size cap, opt-in CORS), so every error is uniform and every request is logged. The
problem media type is `application/problem+json`."""
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from typing import Annotated

from fastapi import HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, BeforeValidator, StrictInt
from starlette.exceptions import HTTPException as StarletteHTTPException

PROBLEM_MEDIA = "application/problem+json"
MAX_BODY_BYTES = 1 << 20            # request body cap (DoS guard) — parity with the go/node runtimes


def _require_int_path(v):
    # STRICT path integer: a path segment is always a string, so accept ONLY a bare integer literal — reject
    # "5.0" / "1e2" / "abc". FastAPI's plain `int` coerces "5.0" -> 5 (it would silently accept a malformed id);
    # this matches go's strconv.Atoi and node's intParam so a path id coerces/rejects IDENTICALLY ×3.
    if isinstance(v, str) and not re.fullmatch(r"-?[0-9]+", v):
        raise ValueError("path segment must be an integer")
    return v


# IntPath: the strict path-int type — use it for every {id} path parameter (`thing_id: IntPath`) instead of `int`.
IntPath = Annotated[int, BeforeValidator(_require_int_path)]

_MAX_SAFE_INT = 9007199254740991   # 2**53-1 = JS Number.MAX_SAFE_INTEGER: the magnitude every language holds EXACTLY


def _require_safe_int(v):
    # Reject an integer magnitude beyond the ×3-safe range BEFORE the strict-int check. Only a real int is range-checked
    # (`type(v) is int` excludes bool — a distinct JSON type StrictInt rejects); a float/str/etc. passes through to
    # StrictInt, which rejects it. A BeforeValidator (not a Field bound) so SafeInt COMPOSES with a domain's own
    # Field(ge=1) without a duplicate-constraint clash.
    if type(v) is int and abs(v) > _MAX_SAFE_INT:
        raise ValueError("integer out of the safe range")
    return v


# SafeInt: a STRICT body integer bounded to the ×3-safe range. Past ±(2**53-1) python (arbitrary-precision) silently
# accepts while go's Atoi caps at int64 and node loses float precision — so a body int field declares SafeInt (not a
# bare StrictInt) to reject an over-range magnitude UNIFORMLY ×3.
SafeInt = Annotated[StrictInt, BeforeValidator(_require_safe_int)]


class ProblemDetail(BaseModel):
    type: str = "about:blank"
    title: str
    status: int
    detail: str


def not_found(resource: str) -> HTTPException:
    return HTTPException(status_code=404, detail=f"{resource} not found")


def invalid(detail: str) -> HTTPException:
    return HTTPException(status_code=422, detail=detail)


def conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=409, detail=detail)


def forbidden(detail: str) -> HTTPException:
    return HTTPException(status_code=403, detail=detail)


def unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=401, detail=detail)


def bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


def too_many(detail: str) -> HTTPException:
    return HTTPException(status_code=429, detail=detail)


def gone(detail: str) -> HTTPException:
    return HTTPException(status_code=410, detail=detail)


def problem_handler(request: Request, exc: Exception) -> JSONResponse:
    status = getattr(exc, "status_code", 500)
    detail = str(getattr(exc, "detail", "internal error"))
    # canonicalize Starlette's built-in routing detail to the lowercase the go/node Fallback emits — ×3 parity [D1]
    detail = {"Not Found": "not found", "Method Not Allowed": "method not allowed"}.get(detail, detail)
    body = ProblemDetail(title=detail, status=status, detail=detail).model_dump()
    return JSONResponse(status_code=status, content=body, media_type=PROBLEM_MEDIA)


def validation_handler(request: Request, exc: Exception) -> JSONResponse:
    # FastAPI's RequestValidationError defaults to a NON-problem+json body; route it through the SAME envelope so a
    # 422 looks like every other error (parity with the Go/Node runtimes).
    body = ProblemDetail(title="invalid body", status=422, detail="invalid body").model_dump()
    return JSONResponse(status_code=422, content=body, media_type=PROBLEM_MEDIA)


def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    # Any exception a domain didn't convert to an HTTPException becomes a uniform problem+json 500 (never a
    # framework HTML/text 500 — the "no silent failure" law: the request fails LOUD and shaped).
    body = ProblemDetail(title="internal error", status=500, detail="internal error").model_dump()
    return JSONResponse(status_code=500, content=body, media_type=PROBLEM_MEDIA)


def _log_line(level, rid, method, path, status, ms, err=""):
    if os.getenv("LOG_LEVEL") == "silent":
        return
    entry = {"level": level, "request_id": rid, "method": method, "path": path, "status": status, "ms": ms}
    if err:
        entry["error"] = err
    print(json.dumps(entry), file=sys.stderr, flush=True)   # stderr keeps stdout clean for probe parsing


def install_runtime(app) -> None:
    """Wire the ONE error envelope (HTTPException/validation/unhandled -> problem+json) + the observability and
    safety middleware (request id header, structured access log, body-size cap, opt-in CORS). The app wiring
    calls this."""
    app.add_exception_handler(StarletteHTTPException, problem_handler)
    app.add_exception_handler(RequestValidationError, validation_handler)
    app.add_exception_handler(Exception, unhandled_handler)

    # CORS is OPT-IN via CORS_ALLOWED_ORIGINS — comma-separated exact origins (e.g.
    # "https://app.example.com,http://localhost:3000") or the single wildcard "*". Unset/empty disables it
    # entirely: no header is added and OPTIONS routes exactly as before. Parsed ONCE here; each request then
    # does an exact-string match against the list (never a pattern or suffix match).
    cors_origins = [o.strip() for o in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()]

    @app.middleware("http")
    async def _observe(request: Request, call_next):
        rid = secrets.token_hex(8)
        request.state.request_id = rid   # expose the per-request id to handlers (the AU-3 'source' of a domain audit) ×3
        start = time.monotonic()
        # The CORS decision for this request: the allowlist entry to echo (the exact matched origin, or "*"),
        # else None. An unlisted Origin is NEVER echoed back — reflecting the caller's Origin would grant every
        # site access.
        origin = request.headers.get("origin")
        allow_origin = None
        if cors_origins and origin:
            allow_origin = "*" if "*" in cors_origins else (origin if origin in cors_origins else None)

        def _finish(resp):
            # Stamp the per-request response headers: the request id always; the CORS grant only for an allowed
            # Origin and on EVERY response, errors included — a browser app can only READ a 4xx/5xx body when
            # the grant is present.
            resp.headers["X-Request-Id"] = rid
            if allow_origin:
                resp.headers["Access-Control-Allow-Origin"] = allow_origin
                resp.headers["Access-Control-Expose-Headers"] = "X-Request-Id"
                if allow_origin != "*":
                    resp.headers["Vary"] = "Origin"   # the grant varies by Origin, so caches must key on it
            return resp

        # Answer a CORS preflight (OPTIONS + Origin + Access-Control-Request-Method) BEFORE routing: 204 always,
        # carrying the Access-Control-* grant only for an allowed origin — the browser treats the bare 204 as a
        # denial, and the allowlist is never revealed. An OPTIONS without both headers routes as normal.
        if cors_origins and request.method == "OPTIONS" and origin \
                and request.headers.get("access-control-request-method"):
            headers = {"X-Request-Id": rid}
            if allow_origin:
                headers["Access-Control-Allow-Origin"] = allow_origin
                headers["Access-Control-Allow-Methods"] = request.headers["access-control-request-method"]
                headers["Access-Control-Allow-Headers"] = (request.headers.get("access-control-request-headers")
                                                           or "Authorization, Content-Type, Idempotency-Key")
                headers["Access-Control-Max-Age"] = "600"
                if allow_origin != "*":
                    headers["Vary"] = "Origin"
            ms = int((time.monotonic() - start) * 1000)
            _log_line("info", rid, request.method, request.url.path, 204, ms)
            return Response(status_code=204, headers=headers)
        # REJECT an ENCODED path separator (%2F / %5C) BEFORE routing — the one path-param drift that is real ×3:
        # python decodes the path BEFORE routing, so `%2F` splits a SEGMENT (a {slug} of "a%2Fb" becomes path "/a/b" ->
        # mis-routes or 404s); go/node route THEN decode, capturing it intact. Rejecting it here (uniform 404, like an
        # unknown route) makes every {param} identifier byte-identical ×3. (Control chars %00/%1F don't split -> they
        # reach well_formed -> 422 identically, so they need no special case; a general %xx like %6D decodes the same ×3.)
        raw_path = request.scope.get("raw_path") or b""
        if b"%2f" in raw_path.lower() or b"%5c" in raw_path.lower():
            ms = int((time.monotonic() - start) * 1000)
            _log_line("warn", rid, request.method, request.url.path, 404, ms)
            body = ProblemDetail(title="not found", status=404, detail="not found").model_dump()
            return _finish(JSONResponse(status_code=404, content=body, media_type=PROBLEM_MEDIA))
        # REJECT a DUPLICATED query parameter (?x=1&x=2) BEFORE routing — the frameworks disagree on a repeat
        # (Starlette takes the LAST value, go/node the FIRST), so a duplicated scalar (limit/cursor/filter) would
        # page/filter DIFFERENTLY ×3. A uniform 422 (the canonical-input stance — same as the dup-header reject)
        # keeps every query scalar identical ×3.
        _qkeys = [k for k, _ in request.query_params.multi_items()]
        if len(_qkeys) != len(set(_qkeys)):
            ms = int((time.monotonic() - start) * 1000)
            _log_line("warn", rid, request.method, request.url.path, 422, ms)
            body = ProblemDetail(title="duplicate query parameter", status=422, detail="duplicate query parameter").model_dump()
            return _finish(JSONResponse(status_code=422, content=body, media_type=PROBLEM_MEDIA))
        def _oversize():
            ms = int((time.monotonic() - start) * 1000)
            _log_line("warn", rid, request.method, request.url.path, 413, ms)
            body = ProblemDetail(title="request body too large", status=413, detail="request body too large").model_dump()
            return _finish(JSONResponse(status_code=413, content=body, media_type=PROBLEM_MEDIA))
        clen = request.headers.get("content-length")
        if clen and clen.isdigit() and int(clen) > MAX_BODY_BYTES:
            return _oversize()                          # fast reject for an honestly-declared oversize body
        # The Content-Length header is ADVISORY — a chunked / Transfer-Encoding / lying-CL request can omit or under-state
        # it (the exact bypass the header-only check missed). So ALSO cap the ACTUAL bytes read (parity with go's
        # MaxBytesReader / node's raw.length cap): stream the body with an EARLY EXIT at the cap, then cache it on the
        # request so the downstream handler re-reads it (Starlette serves request.body()/json() from _body).
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_BODY_BYTES:
                return _oversize()
        request._body = bytes(body)
        try:
            resp = await call_next(request)
        except Exception:
            ms = int((time.monotonic() - start) * 1000)
            _log_line("error", rid, request.method, request.url.path, 500, ms, "unhandled")
            raise
        _finish(resp)
        ms = int((time.monotonic() - start) * 1000)
        _log_line("info", rid, request.method, request.url.path, resp.status_code, ms)
        return resp


# ── the SSE response MODE (opt-in per request — the streaming sibling of the JSON chokepoint) ────────────────

def wants_stream(request: Request) -> bool:
    """True when the caller opted into the Server-Sent-Events response mode on a stream-capable route: the
    canonical `?stream=1` query flag, or an `Accept: text/event-stream` header (content negotiation, honored as
    the equivalent). Never a body field — the request body stays byte-identical between the two modes."""
    return request.query_params.get("stream") == "1" \
        or "text/event-stream" in (request.headers.get("accept") or "")


def sse_stream(deltas, done) -> StreamingResponse:
    """A Server-Sent Events response: each text delta rides one `event: delta` frame as {"delta": <text>}, then
    ONE terminal `event: done` frame carries the FULL sync-shape body — so the streamed response always
    reconstructs to exactly the non-streamed one. All guards run BEFORE this is called (a pre-stream refusal
    keeps the normal problem+json envelope); a failure AFTER the first byte cannot change the already-sent 200,
    so it becomes a terminal `event: error` frame (the same problem shape, as frame data) and the stream closes.
    `Cache-Control: no-cache` + `X-Accel-Buffering: no` tell reverse proxies not to buffer the frames (a
    buffering proxy is the #1 real-world SSE failure — also disable proxy buffering at the proxy)."""
    def _frame(event, data):
        return f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'), ensure_ascii=False)}\n\n"

    def gen():
        try:
            for chunk in deltas:
                yield _frame("delta", {"delta": chunk})
            yield _frame("done", done)
        except Exception:
            yield _frame("error", {"type": "about:blank", "title": "internal error",
                                   "status": 500, "detail": "internal error"})

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def require_identity(request: Request) -> str:
    """The authenticated subject from the bearer token, or 401. A scoping domain DEPENDS on this
    (`subject: str = Depends(require_identity)`) instead of trusting a header/query param — the identity comes from a
    real core-owned session, never caller-supplied input."""
    from .store import session_resolve   # call-time import: a sibling core module; avoids any load-order coupling
    header = (request.headers.get("authorization") or "").rstrip()   # match go/node framework trailing-OWS trim — ×3 parity [D2]
    if not header.startswith("Bearer "):
        raise unauthorized("not authenticated")
    subject = session_resolve(header[7:])
    if subject is None:                                       # session miss -> try an api-key bearer (owner identity)
        from .store import api_key_resolve
        subject = api_key_resolve(header[7:])
    if subject is None:
        raise unauthorized("invalid or expired token")
    return subject


def revoke_current(request: Request) -> None:
    """Revoke the CURRENT request's session (logout-local): the bearer is read HERE in CORE, so a domain never parses
    the auth header itself (identity + its token come from the seam, never domain-parsed input)."""
    from .store import session_revoke   # call-time import: a sibling core module; avoids any load-order coupling
    header = request.headers.get("authorization") or ""
    session_revoke(header[7:] if header.startswith("Bearer ") else "")


_TEST_ADMIN = "root"   # the fixed bootstrap admin recognized ONLY under the test seam (inert in production)


def is_admin(subject: str) -> bool:
    """True iff `subject` holds the 'admin' role — the cross-cutting ADMIN check, owned by CORE so ANY domain can
    gate an admin-only operation WITHOUT importing rbac (the boundary rule holds: domains -> core only). The role
    store ("rbac_roles") is a core-recognized cross-cutting namespace, exactly as sessions ("_sessions") are: rbac is
    the management SURFACE (assign/revoke roles), core owns the NOTION (read it here). PRODUCTION bootstrap is
    OUT-OF-BAND — the operator seeds rbac_roles[<a real, already-registered subject>] = ["admin"] at deploy time;
    there is NO env-NAME seed, because a claimable username was itself a privilege-escalation hole. The only
    auto-admin is the TEST seam: under APP_TEST_SESSIONS=1 (inert in production, like the test-session
    backdoor) the fixed test admin is recognized, so conformance/invariant tests can exercise
    admin paths without an out-of-band store seed."""
    from .store import get   # call-time import: a sibling core module; avoids any load-order coupling
    if os.getenv("APP_TEST_SESSIONS") == "1" and subject == _TEST_ADMIN:
        return True
    return "admin" in (get("rbac_roles", subject) or [])


def require_admin(request: Request) -> str:
    """The authenticated subject, REQUIRED to be an admin — else 401 (no/invalid identity) or 403 (valid identity,
    not an admin). An admin-only domain DEPENDS on this (`subject: str = Depends(require_admin)`): authn -> authz,
    resolved BEFORE the body is validated, so a non-admin gets 403 not the body's 422 — identical ×3 with go/node.
    """
    subject = require_identity(request)
    if not is_admin(subject):
        raise forbidden("this operation requires the admin role")
    return subject


def org_role(org: str, subject: str):
    """`subject`'s role within `org` ('owner' | 'admin' | 'member') or None — the cross-cutting ORG-MEMBERSHIP check,
    owned by CORE so a sibling team-management domain can authorize against org membership WITHOUT importing the
    org-management domain (the boundary rule holds: domains -> core only). SINGLE-SOURCE OWNERSHIP: the OWNER is
    DERIVED from orgs_records.owner (the ONE canonical owner field), NOT a membership row — so a transfer is a single
    atomic write to orgs_records and there can NEVER be two 'owner' rows. The membership store ("orgs_members"
    namespace, key "<slug>\x1f<handle>" -> a self-describing record {org, handle, role, status, ...}) carries ONLY
    non-owner roles BY CONSTRUCTION; a role is granted ONLY when status == 'active'. A 'pending' member (an invite the
    holder has not ACCEPTED with the single-use token) grants NOTHING — this closes the member-identity escalation
    (a manager could pre-name a raw handle an attacker then self-registers; the unaccepted invite confers no role).
    The owner is read from orgs_records FIRST + transfer re-asserts ownership in-lock, so a non-owner can never hold an
    'owner' row nor double-grant. Both stores are core-recognized cross-cutting namespaces (like "_sessions"/
    "rbac_roles"); orgs is the management SURFACE that writes them, core owns the NOTION (read it here). \x1f is
    un-forgeable (slugs/handles are well_formed)."""
    from .store import get   # call-time import: a sibling core module; avoids any load-order coupling
    rec = get("orgs_records", org)
    if rec is not None and rec.get("owner") == subject:
        return "owner"                                     # ownership is single-sourced in orgs_records.owner (derived)
    member = get("orgs_members", f"{org}\x1f{subject}")    # a record {org, handle, role, status, ...}; never an owner
    if member is not None and member.get("status") == "active":
        role = member.get("role")
        return role if role != "owner" else None           # ACCEPTED admin|member grants; a membership row NEVER confers 'owner' (single-source DEFENSE-IN-DEPTH — no writer emits it, but the seam refuses it regardless)
    return None                                            # no row, OR a pending (un-accepted) invite -> no role at all


def require_service(request: Request) -> str:
    """A trusted SERVICE caller — authenticated by a CONSTANT-TIME match of the Bearer token against the env
    SERVICE_TOKEN (a service secret, NOT a user session — identity-exempt; the cross-cutting generalization of admin's
    break-glass token). For server-side PRIMITIVES a user must not reach: a throttle that runs BEFORE the user is
    authenticated (rate limiting — login brute-force protection), trusted audit-event ingestion. A non-service caller
    is 401 — the same 401 for no header / wrong scheme / wrong token (non-enumerable). Compares FIXED-LENGTH sha256
    digests so the compare is length-independent (no length leak), identical ×3 with go/node."""
    want = os.getenv("SERVICE_TOKEN", "service_dev_token_change_me")   # env-backed, rotatable; identity-exempt
    header = request.headers.get("authorization") or ""
    token = header[7:] if header.startswith("Bearer ") else ""
    if not hmac.compare_digest(hashlib.sha256(token.encode()).digest(),
                               hashlib.sha256(want.encode()).digest()):
        raise unauthorized("service authorization required")
    return "service"
