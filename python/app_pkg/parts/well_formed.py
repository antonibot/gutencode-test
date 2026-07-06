"""CENTRAL well_formed part — the IDENTIFIER validator every name-accepting domain shares: a well-formed
identifier is a non-empty string containing no control characters (codepoints below 0x20). Why it exists once:
control bytes in identifiers enable log injection, lookalike store keys, and — when identifiers are joined into
composite keys — KEY FORGERY (the rbac tuple-delimiter class). One contract, three languages: well_formed.go
and well_formed.js implement the SAME function; the three behave identically."""


from typing import Annotated

from pydantic import AfterValidator, StrictStr


_MAX_LEN = 1024  # an identifier is bounded — a multi-KB value must never become a store key (the soft-DoS/OOM ceiling)


def is_well_formed(value) -> bool:
    """True iff value is a non-empty string of at most 1024 CODE POINTS with no control characters (< 0x20).
    python's len() already counts code points; go (utf8.RuneCountInString) and node ([...value].length) match it, so a
    multibyte / astral identifier is accepted/rejected IDENTICALLY ×3 — never writable under one runtime and unreadable
    under another. Multibyte boundary cases (astral codepoints, split surrogates) behave identically ×3."""
    return isinstance(value, str) and 0 < len(value) <= _MAX_LEN and all(ord(ch) >= 0x20 for ch in value)


def make_well_formed(value: str) -> str:
    """Return value with every LONE surrogate (a codepoint in U+D800..U+DFFF) replaced by U+FFFD, so the string is
    always UTF-8-serializable. A lone surrogate (e.g. from the JSON escape `\\ud800` decoded by json.loads) cannot be
    UTF-8-encoded, so without this the RESPONSE serialization raises AFTER the handler returns -> an uncontained
    5xx. Idempotent + identity on already-well-formed text (incl. astral codepoints). Go
    strings are ALWAYS valid UTF-8 (json substitutes U+FFFD at decode), so MakeWellFormed is identity there and the
    transform is exercised only where lone surrogates can EXIST (python/node) — proven by the consumer's invariant."""
    return "".join(chr(0xFFFD) if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in value)


def _require(value: str) -> str:
    if not is_well_formed(value):
        raise ValueError("must be non-empty with no control characters")
    return value


# python convenience around the one vectored contract: declare a model field as WellFormedStr and the identifier
# rule applies — no per-domain validator boilerplate (go/node call IsWellFormed/isWellFormed directly instead).
WellFormedStr = Annotated[StrictStr, AfterValidator(_require)]

# handler-side convenience for QUERY/PATH parameters (WellFormedStr covers model fields): validate-or-422 with
# a uniform message — the one place the rule's rejection is phrased.
def require_well_formed(value, what: str) -> str:
    if not is_well_formed(value):
        # imported at CALL time so this module also works when loaded standalone (no package parent), where a
        # module-level relative import would fail; in the app the package context is always present
        from ..core.errors import invalid
        raise invalid(f"{what} must be non-empty with no control characters")
    return value


_MAX_SAFE_INT = 9007199254740991  # 2**53-1: the magnitude every language holds EXACTLY (the strict-number ceiling)


def safe_number(name, value):
    """A JSON number made ×3-SAFE: reject a bool/non-number; reject an integral magnitude past 2^53 (python keeps it
    exact while go/node round to float64 — a silent ×3 divergence); normalize an integral float to an int so 5.0
    serializes as "5" like go/node (a real fraction stays a float). Raises invalid(...) on rejection (lazy core import,
    like require_well_formed). Lives here, not in a consumer, so a domain's typed number field AND the json sanitizer
    below share ONE ceiling — a part cannot import a part."""
    from ..core.errors import invalid
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise invalid(f"field '{name}' must be a number")
    if isinstance(value, float) and not value.is_integer():
        return value
    iv = int(value)
    if abs(iv) > _MAX_SAFE_INT:
        raise invalid(f"field '{name}' is out of the safe integer range")
    return iv


def sanitize_json(name, value):
    """An opaque JSON value made ×3-SAFE for durable storage: make_well_formed EVERY string (a lone surrogate -> U+FFFD,
    so the response never 5xxs on serialize and python/node match go's decode-time substitution), and the 2^53 ceiling
    on EVERY number (via safe_number — a >2^53 int can't be stored with divergent precision ×3). Recurses into objects
    (keys too) and arrays; identity on None/bool; raises invalid(...) on an out-of-range number. Lives WITH
    make_well_formed because a part cannot import a part."""
    if isinstance(value, str):
        return make_well_formed(value)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return safe_number(name, value)
    if isinstance(value, dict):
        return {make_well_formed(k): sanitize_json(name, v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_json(name, v) for v in value]
    return value   # None
