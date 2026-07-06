// Package signing — HMAC-SHA256 signing: two schemes share ONE hmac primitive (hmacSha256 — the no-drift seam,
// the ONLY hmac.New in the app). Same contract as signing.py / signing.js, proven by the shared vector suite.
package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func hmacSha256(secret, message string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return mac.Sum(nil)
}

// SignV1 = "v1," + base64(HMAC(secret, "{id}.{timestamp}.{payload}")) — the Standard Webhooks shape.
func SignV1(secret, id string, timestamp int64, payload string) string {
	return "v1," + base64.StdEncoding.EncodeToString(hmacSha256(secret, fmt.Sprintf("%s.%d.%s", id, timestamp, payload)))
}

const maxCandidates = 32 // cap the v1 candidates a caller may submit on the PUBLIC /verify (bound the compare work — a DoS guard)

// VerifyV1 verifies against ONE secret, accepting a SPACE-delimited MULTI-signature 'v1,<b64> v1,<b64> ...' (a sender
// signs with every active secret during a rotation; accept if THIS secret matches ANY candidate). The multi-SECRET loop
// is the CALLER's (it tracks which secret matched, to scope a replay-dedup). A '.' in id is rejected (the
// '{id}.{ts}.{payload}' join delimiter — signature-confusion); a stale ts is rejected before any crypto; malformed /
// foreign-scheme candidates are SKIPPED; the count is CAPPED; each compare is constant-time. Back-compat with one 'v1,'.
func VerifyV1(secret, id string, timestamp int64, payload, sigHeader string, now, tolerance int64) bool {
	if strings.Contains(id, ".") { // the '.'-join delimiter -> a dotted id is signature-confusion
		return false
	}
	if timestamp <= 0 { // non-positive ts -> reject FIRST: a far-negative ts overflows `now - timestamp` to MinInt64,
		return false // whose abs stays negative and would slip under the window — the ts<=0 guard closes that bypass.
	}
	delta := now - timestamp
	if delta < 0 {
		delta = -delta
	}
	if delta > tolerance {
		return false
	}
	expected := SignV1(secret, id, timestamp, payload)
	seen := 0
	for _, piece := range strings.Split(sigHeader, " ") {
		if !strings.HasPrefix(piece, "v1,") { // SKIP malformed / foreign-scheme (never sink a valid sibling)
			continue
		}
		if hmac.Equal([]byte(expected), []byte(piece)) { // constant-time per candidate
			return true
		}
		seen++
		if seen >= maxCandidates { // CAP — bound the work a caller can force (DoS guard)
			break
		}
	}
	return false
}

// StripeSign = hex(HMAC(secret, "{timestamp}.{payload}")) — the Stripe 'v1=' value (signed payload = ts.body).
func StripeSign(secret string, timestamp int64, payload string) string {
	return hex.EncodeToString(hmacSha256(secret, fmt.Sprintf("%d.%s", timestamp, payload)))
}

// StripeVerify parses a "Stripe-Signature: t=<ts>,v1=<hex>[,v1=<hex>...]" header and constant-time checks it within the
// window. Collects EVERY v1 and accepts if ANY matches (secret rotation sends one v1 per active secret — keeping only
// the last would silently reject a rotated delivery). A non-positive/pre-1970 or out-of-window timestamp is rejected
// before any crypto (two-sided window — a deliberate divergence from Stripe's one-sided check). Same contract ×3.
func StripeVerify(secret, header, payload string, now, tolerance int64) bool {
	var timestamp int64
	v1s := []string{}
	for _, piece := range strings.Split(header, ",") {
		kv := strings.SplitN(piece, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1]) // strip BOTH sides so 't= 1000 ' / 'v1 = <hex>' parse IDENTICALLY ×3
		switch k {
		case "t":
			timestamp, _ = strconv.ParseInt(v, 10, 64) // malformed -> 0 -> caught by the ts<=0 guard
		case "v1":
			v1s = append(v1s, v) // collect ALL v1 (secret rotation sends several)
		}
	}
	delta := now - timestamp
	if delta < 0 {
		delta = -delta
	}
	if timestamp <= 0 || delta > tolerance {
		return false
	}
	expected := StripeSign(secret, timestamp, payload)
	for _, v1 := range v1s {
		if hmac.Equal([]byte(expected), []byte(v1)) { // constant-time per candidate; accept if ANY matches
			return true
		}
	}
	return false
}
