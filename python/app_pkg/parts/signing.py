"""CENTRAL signing part — HMAC-SHA256 for every signer domain. Two schemes share ONE hmac primitive (`_hmac`):
  • Standard Webhooks  'v1,<b64>'  over '{id}.{timestamp}.{payload}'   (webhooks)
  • Stripe             't=..,v1=<hex>'  over '{timestamp}.{payload}'    (stripe, F5)
Every signer imports these and NEVER re-inlines HMAC — `hmac.new` lives in `_hmac` ALONE.
One contract, three languages: signing.go and signing.js implement the SAME functions; the three
sign byte-identically."""
import base64
import hashlib
import hmac


def _hmac(secret: str, message: str) -> bytes:
    """The ONE HMAC-SHA256 primitive (the no-drift seam — every scheme below routes through here)."""
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()


def sign_v1(secret: str, msg_id: str, timestamp: int, payload: str) -> str:
    return "v1," + base64.b64encode(_hmac(secret, f"{msg_id}.{timestamp}.{payload}")).decode()


_MAX_CANDIDATES = 32   # cap the v1 candidates a caller may submit on the PUBLIC /verify — a sender sends one v1 per
                       # active secret (a handful), never thousands; bound the per-request compare work (a DoS guard)


def verify_v1(secret: str, msg_id: str, timestamp: int, payload: str,
              sig_header: str, now: int, tolerance: int) -> bool:
    """Standard-Webhooks verify against ONE secret, accepting a SPACE-delimited MULTI-signature header
    'v1,<b64> v1,<b64> ...' (a sender signs with EVERY active secret during a rotation; keeping only one candidate would
    silently reject a valid rotated delivery — so accept if THIS secret matches ANY candidate). The multi-SECRET loop is
    the CALLER's (it tracks WHICH secret matched, to scope a replay-dedup). A '.' in msg_id is rejected (it is the
    '{id}.{ts}.{payload}' join delimiter — a dotted id is signature-confusion); a NON-POSITIVE timestamp is rejected
    (parity with stripe_verify — it also closes a far-negative ts that would overflow Go's int64 abs and bypass the
    window); a stale timestamp is rejected BEFORE any crypto; malformed / foreign-scheme candidates are SKIPPED (a bad
    sibling never sinks a valid one); the candidate count is CAPPED; each compare is constant-time. Back-compatible
    with a single 'v1,<b64>' header."""
    if "." in msg_id:                                    # the '.'-join delimiter -> a dotted id is signature-confusion
        return False
    if timestamp <= 0:                                   # non-positive ts -> reject (also closes the int64 abs-overflow ×3)
        return False
    if abs(now - timestamp) > tolerance:                 # stale -> reject before any crypto
        return False
    expected = sign_v1(secret, msg_id, timestamp, payload)
    seen = 0
    for piece in (sig_header or "").split(" "):
        if not piece.startswith("v1,"):                  # SKIP malformed / foreign-scheme (never sink a valid sibling)
            continue
        if hmac.compare_digest(expected, piece):         # constant-time per candidate
            return True
        seen += 1
        if seen >= _MAX_CANDIDATES:                      # CAP — bound the work a caller can force (DoS guard)
            break
    return False


def stripe_sign(secret: str, timestamp: int, payload: str) -> str:
    """Stripe's signed payload is '{timestamp}.{payload}', the digest hex-encoded (the 'v1=' value)."""
    return _hmac(secret, f"{timestamp}.{payload}").hex()


def stripe_verify(secret: str, header: str, payload: str, now: int, tolerance: int) -> bool:
    """Verify a 'Stripe-Signature: t=<ts>,v1=<hex>[,v1=<hex>...]' header against the payload, within the replay window.
    Collects EVERY v1 and accepts if ANY matches (Stripe sends one v1 per active secret during a secret roll — keeping
    only the last would silently reject a legitimate rotated delivery). Rejects a non-positive/pre-1970 timestamp and a
    timestamp outside the two-sided window BEFORE any crypto (replay protection; two-sided is a deliberate divergence
    from Stripe's one-sided check — a far-future timestamp must not bypass the window forever)."""
    timestamp = 0
    v1s = []
    for piece in (header or "").split(","):
        key, _, val = piece.partition("=")
        key = key.strip()
        val = val.strip()                                # strip BOTH sides so 't= 1000 ' / 'v1 = <hex>' parse IDENTICALLY ×3
        if key == "t":
            try:
                timestamp = int(val)
            except ValueError:
                timestamp = 0                            # malformed t -> 0 -> rejected by the ts<=0 guard below
        elif key == "v1":
            v1s.append(val)                              # collect ALL v1 (secret rotation sends several)
    if timestamp <= 0 or abs(now - timestamp) > tolerance:   # non-positive ts / stale -> reject before any crypto
        return False
    expected = stripe_sign(secret, timestamp, payload)
    return any(hmac.compare_digest(expected, v1) for v1 in v1s)   # constant-time per candidate; accept if ANY matches
