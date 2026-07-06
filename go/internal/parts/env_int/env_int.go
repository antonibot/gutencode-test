// Package env_int — parse an integer from a RAW environment value the SAME way in python/go/node, with a default
// and optional clamp bounds. A config knob must resolve IDENTICALLY x3, but bare int()/strconv.Atoi()/parseInt()
// disagree on the edges: parseInt('5x')==5 in node but errors in py/go; Atoi(' 5 ') errors but int(' 5 ') strips;
// AND a value past 2**53-1 diverges (go's int64 vs node's float vs python's unbounded int). The caller passes the
// raw value (os.Getenv(name)); this is the PURE parse+clamp. Rule: trim; an empty /
// non-integer / |value|>2**53-1 raw -> the default; THEN clamp by the optional bounds (none · floor · lo,hi).
package env_int

import (
	"regexp"
	"strconv"
	"strings"
)

const maxSafeInt = 9007199254740991 // 2**53 - 1 (JS Number.MAX_SAFE_INTEGER) — the x3-safe magnitude ceiling

var intRe = regexp.MustCompile(`^[+-]?\d+$`)

// EnvInt parses raw to an int (def when empty / non-integer / |n|>2**53-1), then clamps by 0, 1 (floor), or 2 (lo,hi) bounds.
func EnvInt(raw string, def int, bounds ...int) int {
	v := def
	if s := strings.TrimSpace(raw); intRe.MatchString(s) {
		if n, err := strconv.Atoi(s); err == nil && n <= maxSafeInt && n >= -maxSafeInt {
			v = n
		}
	}
	if len(bounds) >= 1 && v < bounds[0] {
		v = bounds[0]
	}
	if len(bounds) >= 2 && v > bounds[1] {
		v = bounds[1]
	}
	return v
}
