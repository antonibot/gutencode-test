"""file_store validators — the byte/name boundary, IDENTICAL in python/go/node (a divergence would make an object
un-addressable under one runtime). Three walls: the canonical-round-trip base64 rule (the accept set is
byte-identical x3), the RFC-2045 content_type token allowlist (CR/LF structurally impossible -> no download-header
injection), and the object-key grammar (contained x3, no path chars, <=1024 utf-8 bytes)."""
import base64
import re

from ...core.errors import invalid
from ...parts.well_formed import is_well_formed, make_well_formed

# base64: the canonical alphabet + padding shape. re.fullmatch (NEVER ^...$ — python's $ matches BEFORE a trailing
# \n, which would re-open the wall in one language).
_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")
# content_type: a strict RFC-2045 type/subtype token pair. CR/LF/NUL/C0/DEL/C1 are excluded STRUCTURALLY (an ASCII
# allowlist, not a denylist); no spaces, no ';' params, no '*'.
_CT = re.compile(r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}")

_MAX_KEY_BYTES = 1024   # the S3 key limit (utf-8 bytes) — tighter than well_formed's 1024 CODE POINTS; bounds the index row


def norm_key(raw: str) -> str:
    # CONTAIN before anything (a lone surrogate -> U+FFFD, aligning with go's decoder x3 — a raw surrogate would mint
    # x3-divergent composite keys AND 500 python on re-serialize), then the grammar: non-empty + no control chars
    # (is_well_formed) + <=1024 utf-8 BYTES + no '/' '\' and not '.'/'..'. An un-addressable / un-freeable quota slot
    # is the bug this closes: a stored 'a/b' key would be forever unreachable by GET/DELETE (raw '/' splits the
    # segment x3; %2F is rejected pre-routing), so it could mint a quota slot no request can ever free.
    key = make_well_formed(raw)
    if (not is_well_formed(key) or len(key.encode("utf-8")) > _MAX_KEY_BYTES
            or "/" in key or "\\" in key or key in (".", "..")):
        raise invalid("the object key is invalid")
    return key


def decode_b64(content_b64: str) -> bytes:
    # the ONE x3-identical rule: canonical-form round-trip. Pre-check the alphabet + length, decode, RE-ENCODE, and
    # require equality with the input — python b64decode(validate=True) ACCEPTS the non-canonical "QR==", go
    # StdEncoding accepts trailing-bit garbage AND embedded '\n', node accepts anything; the round-trip makes the
    # accept set BIT-EXACT x3 (the re-encoders are all canonical + padded) and the etag base canonical by construction.
    if not _B64.fullmatch(content_b64) or len(content_b64) % 4 != 0:
        raise invalid("content_b64 must be canonical base64")
    try:
        raw = base64.b64decode(content_b64, validate=True)
    except Exception:
        raise invalid("content_b64 must be canonical base64")
    if base64.b64encode(raw).decode() != content_b64:
        raise invalid("content_b64 must be canonical base64")
    return raw


def clean_content_type(raw) -> str:
    # the stored content_type is REFLECTED into the download Content-Type header, so it is allowlist-validated at
    # WRITE against the RFC-2045 token grammar (a `text/html\r\nSet-Cookie: ...` -> 422): CR/LF/controls are
    # structurally impossible under the ASCII allowlist, identical x3. Absent -> the octet-stream default.
    ct = raw if raw is not None else "application/octet-stream"
    if not isinstance(ct, str) or not _CT.fullmatch(ct):
        raise invalid("content_type must be a valid type/subtype token")
    return ct
