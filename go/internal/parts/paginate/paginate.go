// Package paginate — the bounded-page + opaque-cursor pagination every LIST endpoint shares: a STABLE-ordered
// slice of items plus an OPAQUE base64url OFFSET cursor. Same contract as paginate.py / paginate.js, the scalar
// codec identical in all three languages. The cross-language SUBTLETY is the cursor codec — a cursor is accepted
// ONLY if re-encoding its decoded offset reproduces it byte-for-byte (rejects padding / trailing bytes /
// non-canonical base64) AND the offset is within JS's exact-integer range (2^53-1), so all three languages
// accept/reject EVERY cursor identically. The codec is three SCALAR functions (EncodeCursor / DecodeCursor /
// ClampLimit) the vectors prove ×3; Paginate is the thin composite that rides on them.
package paginate

import (
	"encoding/base64"
	"strconv"
)

const PageDefault, PageMax = 50, 200
const MaxOffset = (1 << 53) - 1 // cursor-offset ceiling, within JS's exact-integer range (cross-language agreement)

// EncodeCursor: the opaque forward cursor for offset n: base64url(itoa(n)), unpadded. n is always >= 0.
func EncodeCursor(n int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(n)))
}

// DecodeCursor: a cursor -> its offset, or -1 if malformed. Accepted ONLY if CANONICAL (re-encoding reproduces it)
// and in [0, MaxOffset] — identical reject set ×3. -1 is the unambiguous reject sentinel (a real offset is >= 0).
func DecodeCursor(cursor string) int {
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(string(b))
	if err != nil || n < 0 || n > MaxOffset || EncodeCursor(n) != cursor { // canonical + bounded, identical ×3
		return -1
	}
	return n
}

// ClampLimit: a raw limit string -> the effective page size in [1, PageMax], or 0 if malformed. Empty ->
// PageDefault. 0 is the unambiguous reject sentinel (a valid limit is always >= 1); a non-canonical / < 1 rejects.
func ClampLimit(raw string) int {
	if raw == "" {
		return PageDefault
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > MaxOffset || strconv.Itoa(n) != raw { // canonical + positive + BOUNDED (×3-uniform reject over-range)
		return 0
	}
	if n > PageMax {
		n = PageMax
	}
	return n
}

// Paginate returns (page, nextCursor, ok). nextCursor is "" when there is no next page; ok=false on a malformed
// cursor/limit. The composite riding on the vectored scalar codec — a bounded slice over a STABLE-ordered slice.
func Paginate[T any](items []T, cursor, limit string) ([]T, string, bool) {
	lim := ClampLimit(limit)
	if lim == 0 {
		return nil, "", false
	}
	offset := 0
	if cursor != "" {
		off := DecodeCursor(cursor)
		if off < 0 {
			return nil, "", false
		}
		offset = off
	}
	if offset > len(items) {
		offset = len(items)
	}
	end := offset + lim
	if end > len(items) {
		end = len(items)
	}
	page := items[offset:end]
	if page == nil {
		page = []T{} // marshal an empty page as [] not null (parity with python/node)
	}
	next := ""
	if end < len(items) {
		next = EncodeCursor(end)
	}
	return page, next, true
}
