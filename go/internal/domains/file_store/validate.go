package file_store

// Byte/name validators for file_store — IDENTICAL in python/go/node. Three walls: the canonical-round-trip base64
// rule (byte-identical accept set x3), the RFC-2045 content_type token allowlist (CR/LF structurally impossible),
// and the object-key grammar (contained x3, no path chars, <=1024 utf-8 bytes).

import (
	"encoding/base64"
	"regexp"
	"strings"

	"app/internal/parts/well_formed"
)

var (
	fsB64Re = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	fsCtRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$`)
)

const fsMaxKeyBytes = 1024 // the S3 key limit (utf-8 bytes) — tighter than well_formed's 1024 CODE POINTS; bounds the index row

// fsNormKey CONTAINS a lone surrogate (identity in go — the JSON decoder already substituted U+FFFD) then applies
// the grammar; returns ("", false) on reject. `len` is UTF-8 BYTES (== py encode / node byteLength). Same rule x3.
func fsNormKey(raw string) (string, bool) {
	key := well_formed.MakeWellFormed(raw)
	if !well_formed.IsWellFormed(key) || len(key) > fsMaxKeyBytes ||
		strings.ContainsAny(key, "/\\") || key == "." || key == ".." {
		return "", false
	}
	return key, true
}

// fsDecodeB64 — the x3-identical canonical-round-trip rule: pre-check alphabet+length, decode, RE-ENCODE, require
// equality (go StdEncoding accepts trailing-bit garbage AND embedded '\n'; the round-trip makes the accept set
// bit-exact x3 and the etag base canonical). Returns (bytes, true) or (nil, false).
func fsDecodeB64(s string) ([]byte, bool) {
	if !fsB64Re.MatchString(s) || len(s)%4 != 0 {
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != s {
		return nil, false
	}
	return raw, true
}

// fsCleanContentType — the stored content_type is reflected on download, so a strict RFC-2045 token/token allowlist
// at write (CR/LF/controls structurally impossible). nil -> the octet-stream default. Returns (ct, true)|("", false).
func fsCleanContentType(raw *string) (string, bool) {
	ct := "application/octet-stream"
	if raw != nil {
		ct = *raw
	}
	if !fsCtRe.MatchString(ct) {
		return "", false
	}
	return ct, true
}
