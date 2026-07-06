"""auth — password authentication + the full session lifecycle, to the OWASP ASVS V2/V3 shape and INTEROP-READY
with the popular managed providers (the response envelope matches Supabase/Firebase/Auth0/Clerk/Cognito — see
INTEROP.md). Passwords are salted + hashed via the CENTRAL password_hash part (PBKDF2-HMAC-SHA256, env-tunable
iterations ≥ the ASVS floor); verify is constant-time and unknown-user == wrong-password (no enumeration, no timing
leak). Sessions are the core "<id>.<secret>" seam: absolute TTL + rotation (/refresh) + scoped logout. Registration
is ENUMERATION-SAFE (silent success); email verification + password reset are single-use expiring token flows; the
pre-auth endpoints are throttled via the core throttle seam. All state lives in the durable store (survives restart).
"""
import base64
import hmac
import os
import secrets

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, StrictStr, field_validator

from ..core import clock, store
from ..core.errors import bad_request, require_identity, revoke_current, too_many, unauthorized
from ..parts.digest import digest_hex
from ..parts.env_int import env_int
from ..parts.password_hash import hash_password, verify_password
from ..parts.well_formed import WellFormedStr

router = APIRouter(prefix="/auth", tags=["auth"])

_PW_MIN, _PW_MAX = 8, 128   # min(8) defends weak creds (ASVS 2.1.1); max(128) defends the unauth PBKDF2-DoS
# state in `store` (same namespaces + record shapes ×3): "auth_users" email -> {salt, hash, email_verified,
# created_at} · "auth_reset"/"auth_verify" rid -> {subject, secret_hash, exp} (single-use tokens) · "auth_outbox"
# "<kind>:<to>" -> {to, kind, token} (the delivery seam, drained by the email worker / read by the invariant test)


def _iterations() -> int:
    return env_int(os.getenv("AUTH_PBKDF2_ITERATIONS"), 200_000, 100_000)   # ≥ ASVS 2.4.3 floor; env-tunable (ratified 200k)


def _throttle(action: str, key: str, now: int) -> None:
    limit = env_int(os.getenv("AUTH_THROTTLE_LIMIT"), 10, 1)
    window = env_int(os.getenv("AUTH_THROTTLE_WINDOW"), 300, 1)
    if not store.throttle(f"auth:{action}:{key}", limit, window, now):
        raise too_many("too many requests — slow down")


class Credentials(BaseModel):
    email: WellFormedStr          # the identifier (interop envelope keys on email); central well_formed rule
    password: StrictStr

    @field_validator("password")
    @classmethod
    def _pw(cls, v: str) -> str:
        if not (_PW_MIN <= len(v) <= _PW_MAX):
            raise ValueError(f"password must be {_PW_MIN}-{_PW_MAX} characters")
        return v


class ResetConfirm(BaseModel):
    token: StrictStr
    password: StrictStr

    @field_validator("password")
    @classmethod
    def _pw(cls, v: str) -> str:
        if not (_PW_MIN <= len(v) <= _PW_MAX):
            raise ValueError(f"password must be {_PW_MIN}-{_PW_MAX} characters")
        return v


class EmailIn(BaseModel):
    email: WellFormedStr


class TokenIn(BaseModel):
    token: StrictStr


def _user_record(password: str, now: int) -> dict:
    salt = base64.b64encode(secrets.token_bytes(16)).decode()
    return {"salt": salt, "hash": hash_password(password, salt, _iterations()),
            "email_verified": False, "created_at": now}


def _user_out(email: str, rec: dict) -> dict:
    # id is the email (a non-enumerable handle — NOT a sequential next_id, audit MINOR-8)
    return {"id": email, "email": email, "email_verified": bool(rec.get("email_verified")),
            "created_at": rec.get("created_at", 0)}


def _envelope_body(token: str, email: str, rec: dict, now: int) -> dict:
    # the interop session envelope. access_token and refresh_token are the SAME rotating opaque server-side session
    # token (single-token model — /refresh rotates it): a DELIBERATE divergence from the AT/RT split, justified
    # because a server-side session is revocable immediately. See INTEROP.md.
    ttl = store.session_ttl_seconds()
    return {"access_token": token, "refresh_token": token, "token_type": "bearer",
            "expires_in": ttl, "expires_at": now + ttl, "user": _user_out(email, rec)}


def _envelope(email: str, rec: dict, now: int) -> dict:
    return _envelope_body(store.session_create(email, now), email, rec, now)


def _deliver(to: str, kind: str, token: str) -> None:
    # the delivery seam: queue the token for the email worker (a real mailer is a documented swap-point). It lands in
    # auth_outbox (the invariant test drains it as the "email worker"). The token is the email content, never logged.
    store.put("auth_outbox", f"{kind}:{to}", {"to": to, "kind": kind, "token": token})


def _mint(ns: str, subject: str, ttl: int, now: int) -> str:
    # a single-use, expiring "<rid>.<secret>" token; only sha256(secret) is stored at rest (a store leak is inert).
    rid = secrets.token_urlsafe(12)
    secret = secrets.token_urlsafe(32)
    store.put(ns, rid, {"subject": subject, "secret_hash": digest_hex(secret), "exp": now + ttl})
    return f"{rid}.{secret}"


def _consume(ns: str, token: str, now: int):
    # SINGLE-USE: atomically (do seam) verify + tombstone the token iff present, unexpired, secret matches (const-time).
    rid, _, secret = (token or "").partition(".")
    if not rid or not secret:
        return None
    out = {"subject": None}

    def fn(cur):
        if (cur and now < cur.get("exp", 0) and cur.get("secret_hash")
                and hmac.compare_digest(digest_hex(secret), cur["secret_hash"])):
            out["subject"] = cur.get("subject")
            return {"subject": cur.get("subject"), "secret_hash": "", "exp": 0}, None   # tombstone -> single-use
        return None, None

    store.do(ns, rid, fn)
    return out["subject"]


@router.post("/register", status_code=200)
def register(creds: Credentials, request: Request) -> dict:
    # mutation-auth: public — the signup door (no session yet). ENUMERATION-SAFE: the response is identical whether
    # the email is new or already registered (no 409 oracle), and PBKDF2 runs on BOTH paths so timing is flat; the
    # verify-email step is the real gate. claim-once via the atomic do seam (first writer wins; never overwrite).
    now = clock.current(request)
    _throttle("register", creds.email, now)
    record = _user_record(creds.password, now)   # PBKDF2 on both paths (flat timing) — computed before the claim
    created = store.do("auth_users", creds.email,
                       lambda cur: (record, True) if cur is None else (None, False))
    if created:
        _deliver(creds.email, "verify", _mint("auth_verify", creds.email, env_int(os.getenv("AUTH_VERIFY_TTL_SECONDS"), 86400, 60), now))
    return {"message": "if the email is unregistered, a verification link has been sent"}


@router.post("/login")
def login(creds: Credentials, request: Request) -> dict:
    # mutation-auth: public — login is public (no session yet); the password check IS the auth, run in constant time
    # even for an absent user (a random salt is hashed when missing) so emails cannot be enumerated. -> interop envelope.
    now = clock.current(request)
    _throttle("login", creds.email, now)
    user = store.get("auth_users", creds.email)
    salt = user["salt"] if user else base64.b64encode(secrets.token_bytes(16)).decode()
    valid = verify_password(creds.password, salt, _iterations(), user["hash"] if user else "")
    if user is None or not valid:
        raise unauthorized("invalid credentials")
    if os.getenv("AUTH_REQUIRE_VERIFIED") == "1" and not user.get("email_verified"):
        raise unauthorized("email not verified")
    return _envelope(creds.email, user, now)


@router.post("/refresh")
def refresh(body: TokenIn, request: Request) -> dict:
    # mutation-auth: refresh-token — public; the rotation token IS the credential. Rotates the opaque session (the
    # old token dies); presenting an already-rotated token is theft -> the session is revoked.
    now = clock.current(request)
    new = store.session_rotate(body.token, now)
    if new is None:
        raise unauthorized("invalid or expired token")
    subject = store.session_resolve(new)
    return _envelope_body(new, subject or "", store.get("auth_users", subject) or {}, now)


@router.post("/logout")
def logout(request: Request, subject: str = Depends(require_identity)) -> dict:
    # require_identity — only an authenticated caller logs out. ?scope=local (this session) | global (all sessions).
    if request.query_params.get("scope") == "global":
        store.session_revoke_all(subject)
    else:
        revoke_current(request)   # the bearer is read in CORE, never parsed in the domain
    return {"message": "logged out"}


@router.post("/password/reset/request", status_code=200)
def reset_request(body: EmailIn, request: Request) -> dict:
    # mutation-auth: public — ENUMERATION-SAFE: always 200, and a token is minted (one store write) on BOTH paths so
    # timing is flat; only a REAL account's token is delivered (we never email a reset link to a non-account).
    now = clock.current(request)
    _throttle("reset", body.email, now)
    token = _mint("auth_reset", body.email, env_int(os.getenv("AUTH_RESET_TTL_SECONDS"), 3600, 60), now)
    if store.get("auth_users", body.email) is not None:
        _deliver(body.email, "reset", token)
    else:
        store.put("auth_outbox", "__pad__", {"pad": True})   # equal store work on the absent path (timing flatness)
    return {"message": "if the email is registered, a reset link has been sent"}


@router.post("/password/reset/confirm", status_code=200)
def reset_confirm(body: ResetConfirm, request: Request) -> dict:
    # mutation-auth: reset-token — the single-use token IS the credential. Sets the new password AND revokes ALL the
    # subject's sessions (a reset ends every existing login — ASVS 3.3.3 / audit #8).
    now = clock.current(request)
    subject = _consume("auth_reset", body.token, now)
    if subject is None:
        raise bad_request("invalid or expired reset token")
    salt = base64.b64encode(secrets.token_bytes(16)).decode()
    new_hash = hash_password(body.password, salt, _iterations())     # PBKDF2 outside the do (do's fn must be pure)
    updated = store.do("auth_users", subject,                        # atomic RMW: no lost update vs a concurrent verify
                       lambda cur: ({**cur, "salt": salt, "hash": new_hash}, True) if cur else (None, False))
    if not updated:
        raise bad_request("invalid or expired reset token")
    store.session_revoke_all(subject)
    return {"message": "password reset; all sessions ended"}


@router.post("/verify/request", status_code=200)
def verify_request(request: Request, subject: str = Depends(require_identity)) -> dict:
    # require_identity — resend an email-verification token to the authenticated caller.
    now = clock.current(request)
    _throttle("verify", subject, now)
    _deliver(subject, "verify", _mint("auth_verify", subject, env_int(os.getenv("AUTH_VERIFY_TTL_SECONDS"), 86400, 60), now))
    return {"message": "verification link sent"}


@router.post("/verify/confirm", status_code=200)
def verify_confirm(body: TokenIn, request: Request) -> dict:
    # mutation-auth: verify-token — the single-use token IS the credential; marks the bound subject's email verified.
    now = clock.current(request)
    subject = _consume("auth_verify", body.token, now)
    if subject is None:
        raise bad_request("invalid or expired verification token")
    updated = store.do("auth_users", subject,                        # atomic RMW: no lost update vs a concurrent reset
                       lambda cur: ({**cur, "email_verified": True}, True) if cur else (None, False))
    if not updated:
        raise bad_request("invalid or expired verification token")
    return {"message": "email verified"}


@router.get("/me")
def me(request: Request, subject: str = Depends(require_identity)) -> dict:
    # identity from the core session seam: deny-by-default (no/invalid/expired token -> 401).
    return _user_out(subject, store.get("auth_users", subject) or {})
