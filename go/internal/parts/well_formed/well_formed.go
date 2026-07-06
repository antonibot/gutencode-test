// Package well_formed — the IDENTIFIER validator every name-accepting domain shares: a well-formed identifier
// is a non-empty string containing no control characters (codepoints below 0x20). Control bytes in identifiers
// enable log injection, lookalike store keys, and — when identifiers are joined into composite keys — KEY
// FORGERY. Same contract as well_formed.py / well_formed.js, proven by the shared vector suite.
package well_formed

import (
	"math"
	"unicode/utf8"
)

const maxLen = 1024 // an identifier is bounded — a multi-KB value must never become a store key (soft-DoS/OOM ceiling)

// IsWellFormed reports whether value is a non-empty string of at most 1024 CODE POINTS with no control chars (< 0x20).
// The cap counts code points (utf8.RuneCountInString), NOT UTF-8 bytes — so a multibyte identifier is accepted/rejected
// IDENTICALLY to python (len) and node ([...value].length); a shared store can't be writable under one runtime and
// un-readable under another. Multibyte boundary cases behave identically ×3.
func IsWellFormed(value string) bool {
	if value == "" || utf8.RuneCountInString(value) > maxLen {
		return false
	}
	for _, ch := range value {
		if ch < 0x20 {
			return false
		}
	}
	return true
}

// MakeWellFormed returns value with every lone surrogate replaced by U+FFFD (UTF-8-serializable). In Go this is
// IDENTITY: a Go string is always valid UTF-8 — a lone surrogate cannot be represented (the json decoder substitutes
// U+FFFD at the boundary), so there is nothing to replace. The transform is real only in python/node where a lone
// surrogate CAN exist (from a decoded `\uD800` JSON escape); the shared vectors assert identity on well-formed input
// ×3, and the consumer's invariant proves the python/node replacement. Same contract as well_formed.py / .js.
func MakeWellFormed(value string) string {
	return value
}

const maxSafeInt = 1<<53 - 1 // 9007199254740991 = 2^53-1: the magnitude every language holds EXACTLY (the strict-number ceiling)

// SafeNumber makes a JSON number ×3-SAFE: reject a non-number; reject an integral magnitude past 2^53 (python keeps it
// exact while go/node round to float64). Returns (value, "") or (nil, message) — the message is byte-identical to
// python/node. Lives here, with MakeWellFormed, so a domain's typed number field AND SanitizeJSON below share ONE
// ceiling (a part cannot import a part).
func SafeNumber(name string, value any) (any, string) {
	f, ok := value.(float64) // JSON numbers decode to float64 in Go; a bool/string/nil is not float64
	if !ok {
		return nil, "field '" + name + "' must be a number"
	}
	if f == math.Trunc(f) && math.Abs(f) > maxSafeInt {
		return nil, "field '" + name + "' is out of the safe integer range"
	}
	return value, ""
}

// SanitizeJSON makes an opaque JSON value ×3-SAFE for durable storage: MakeWellFormed every string (a lone surrogate ->
// U+FFFD, matching go's own decode-time substitution so python/node agree and the response never 5xxs) and the 2^53
// ceiling on every number (via SafeNumber). Recurses keys + arrays; identity on nil/bool. (Go: MakeWellFormed is
// identity — strings are always valid UTF-8.) Lives WITH MakeWellFormed because a part cannot import a part.
func SanitizeJSON(name string, value any) (any, string) {
	switch v := value.(type) {
	case string:
		return MakeWellFormed(v), ""
	case bool:
		return v, ""
	case float64: // every JSON number decodes to float64 in Go
		return SafeNumber(name, value)
	case map[string]any:
		out := map[string]any{}
		for k, val := range v {
			sv, msg := SanitizeJSON(name, val)
			if msg != "" {
				return nil, msg
			}
			out[MakeWellFormed(k)] = sv
		}
		return out, ""
	case []any:
		out := make([]any, len(v))
		for i, val := range v {
			sv, msg := SanitizeJSON(name, val)
			if msg != "" {
				return nil, msg
			}
			out[i] = sv
		}
		return out, ""
	default:
		return value, "" // nil
	}
}
