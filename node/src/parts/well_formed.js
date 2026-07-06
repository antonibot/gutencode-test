// CENTRAL well_formed part — the IDENTIFIER validator every name-accepting domain shares: a well-formed
// identifier is a non-empty string containing no control characters (codepoints below 0x20). Control bytes in
// identifiers enable log injection, lookalike store keys, and — when identifiers are joined into composite
// keys — KEY FORGERY. Same contract as well_formed.py / well_formed.go; the three behave identically.
// A complete, standalone ES module.

const MAX_LEN = 1024; // an identifier is bounded — a multi-KB value must never become a store key (soft-DoS/OOM ceiling)

// isWellFormed reports whether value is a non-empty string of at most 1024 CODE POINTS with no control chars (< 0x20).
// The cap counts code points ([...value].length), NOT UTF-16 units (value.length) — so a multibyte / astral identifier
// is accepted/rejected IDENTICALLY to python (len) and go (utf8.RuneCountInString); a shared store can't be writable
// under one runtime and un-readable under another. Multibyte boundary cases behave identically ×3.
export function isWellFormed(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  if ([...value].length > MAX_LEN) return false;
  for (const ch of value) {
    if (ch.codePointAt(0) < 0x20) return false;
  }
  return true;
}

// makeWellFormed returns value with every lone surrogate replaced by U+FFFD (UTF-8-serializable). A lone surrogate
// (e.g. from the decoded JSON escape `\uD800`) cannot be UTF-8-encoded, so without this the RESPONSE serialization
// throws after the handler returns -> an uncontained 5xx. Idempotent + identity on
// already-well-formed text (incl. astral codepoints). Same contract as well_formed.py / .go (Go is identity — its
// strings are always valid UTF-8). String.prototype.toWellFormed() does exactly the lone-surrogate -> U+FFFD swap.
export function makeWellFormed(value) {
  return value.toWellFormed();
}

const MAX_SAFE_INT = 9007199254740991; // 2**53-1: the magnitude every language holds EXACTLY (the strict-number ceiling)

// safeNumber makes a JSON number ×3-SAFE: reject a non-number (typeof bool !== 'number'); reject an integral magnitude
// past 2^53 (python keeps it exact while go/node round to float64). Returns [value, ''] or [null, message]; the message
// is byte-identical to python/go. Lives here, with makeWellFormed, so a domain's typed number field AND the json
// sanitizer below share ONE ceiling — a part cannot import a part.
export function safeNumber(name, value) {
  if (typeof value !== 'number') return [null, `field '${name}' must be a number`];
  if (Number.isInteger(value) && Math.abs(value) > MAX_SAFE_INT) return [null, `field '${name}' is out of the safe integer range`];
  return [value, ''];
}

// sanitizeJson makes an opaque JSON value ×3-SAFE for durable storage: makeWellFormed every string (a lone surrogate ->
// U+FFFD, matching go's decode-time substitution + preventing a serialize 5xx) and the 2^53 ceiling on every number
// (via safeNumber). Recurses keys + arrays; identity on null/bool. Lives WITH makeWellFormed (a part cannot import a part).
export function sanitizeJson(name, value) {
  if (typeof value === 'string') return [makeWellFormed(value), ''];
  if (typeof value === 'boolean') return [value, ''];
  if (typeof value === 'number') return safeNumber(name, value);
  if (Array.isArray(value)) {
    const out = [];
    for (const v of value) { const [sv, msg] = sanitizeJson(name, v); if (msg) return [null, msg]; out.push(sv); }
    return [out, ''];
  }
  if (value !== null && typeof value === 'object') {
    const out = Object.create(null); // null-proto: a literal "__proto__" key is stored as DATA, never pollutes the prototype
    for (const [k, v] of Object.entries(value)) { const [sv, msg] = sanitizeJson(name, v); if (msg) return [null, msg]; out[makeWellFormed(k)] = sv; }
    return [out, ''];
  }
  return [value, '']; // null
}
