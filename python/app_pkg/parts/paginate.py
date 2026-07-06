"""CENTRAL paginate part — the bounded-page + opaque-cursor pagination every LIST endpoint shares: a
STABLE-ordered slice of `items` plus an OPAQUE base64url OFFSET cursor. One contract, three languages
(paginate.go / paginate.js implement the SAME functions with an identical scalar codec).

WHY a part: pagination's cross-language SUBTLETY is the cursor codec — a cursor is accepted ONLY if re-encoding
its decoded offset reproduces it byte-for-byte (rejects padding / trailing bytes / non-canonical base64) AND the
offset is within JS's exact-integer range (2^53-1), so all three languages accept/reject EVERY cursor identically.
The codec is exposed as three SCALAR functions (encode_cursor / decode_cursor / clamp_limit) so the shared vectors
prove ×3 agreement DIRECTLY; paginate() is the thin composite that rides on them (its slicing is trivial and is
exercised ×3 through every consuming domain's manifest tests). Offset pagination over a stable order; keyset is the
Postgres-swap upgrade.
"""
import base64

PAGE_DEFAULT, PAGE_MAX = 50, 200
MAX_OFFSET = (1 << 53) - 1   # cursor-offset ceiling, within JS's exact-integer range (cross-language agreement)


def encode_cursor(n: int) -> str:
    """The opaque forward cursor for offset n: base64url(str(n)), unpadded. n is always >= 0."""
    return base64.urlsafe_b64encode(str(n).encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> int:
    """A cursor -> its offset, or -1 if malformed. Accepted ONLY if CANONICAL (re-encoding reproduces it) and in
    [0, MAX_OFFSET] — so all three languages reject the same cursors (padding, trailing bytes, leading zero,
    over-range, non-numeric). -1 is the unambiguous reject sentinel (a real offset is always >= 0)."""
    try:
        n = int(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode())
    except Exception:
        return -1
    if not (0 <= n <= MAX_OFFSET) or encode_cursor(n) != cursor:   # canonical + bounded, identical ×3
        return -1
    return n


def clamp_limit(raw) -> int:
    """A raw limit string -> the effective page size in [1, PAGE_MAX], or 0 if malformed. Empty -> PAGE_DEFAULT.
    0 is the unambiguous reject sentinel (a valid limit is always >= 1); a non-canonical / < 1 limit rejects."""
    if raw in (None, ""):
        return PAGE_DEFAULT
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return 0
    if n < 1 or n > MAX_OFFSET or str(n) != str(raw):   # canonical + positive + BOUNDED (the cursor's ceiling — so
        return 0                                        # an over-range limit rejects identically ×3, not py-clamp/go-go/node-422)
    return min(n, PAGE_MAX)


def paginate(items, cursor, limit):
    """(page, next_cursor, ok). next_cursor is None when there is no next page; ok=False on a malformed
    cursor/limit. The composite riding on the vectored scalar codec — a bounded slice over a STABLE-ordered list."""
    lim = clamp_limit(limit)
    if lim == 0:
        return [], None, False
    offset = 0
    if cursor:
        off = decode_cursor(cursor)
        if off < 0:
            return [], None, False
        offset = off
    offset = min(offset, len(items))
    page = items[offset:offset + lim]
    nxt = encode_cursor(offset + lim) if offset + lim < len(items) else None
    return page, nxt, True
