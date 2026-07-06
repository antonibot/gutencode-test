// Package core — the cross-cutting AUTH/IDENTITY session STORE seam (records · TTL · rotate+reuse-detection ·
// revoke · the subject index). Split out of runtime.go (same package core) to keep each file focused + within the
// file budget; the HTTP-layer guard RequireIdentity (which reads this) stays in runtime.go.
//
// Sessions live in CORE, not the auth domain, so ANY domain resolves the authenticated subject via RequireIdentity
// WITHOUT importing auth — the boundary rule holds (domains -> core only). auth DELEGATES session storage here. A
// read enforces expiry against the wall clock; `now` is threaded in (an int) only by create/rotate so tests drive
// expiry deterministically. ns "_sessions"/"_session_index" are core's own (domain code never writes them).
//
// A bearer is "<id>.<secret>": the row is keyed by the public id and only sha256(secret) is stored (a store/backup
// leak yields no usable token; the compare is constant-time). The row carries an absolute exp (idle-sliding) so a
// session is never immortal — every resolve enforces now < exp. Rotation mints a new secret +
// bumps gen; the JUST-ROTATED secret presented again is theft -> revoke; a secret matching neither current nor
// previous is only rejected. JSON field names are the cross-language contract (identical ×3 with python/node).
package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"time"
)

type sessionRecord struct {
	Subject    string `json:"subject"`
	SecretHash string `json:"secret_hash"`
	PrevHash   string `json:"prev_hash"`
	PrevAt     int64  `json:"prev_at"`
	Exp        int64  `json:"exp"`
	CreatedAt  int64  `json:"created_at"`
	Gen        int    `json:"gen"`
}

var coreSessions = NewKV[string, sessionRecord]("_sessions")
var coreSessionIndex = NewKV[string, []string]("_session_index") // subject -> [id...]; revoke-all is O(k)

func sessionTTL() int64 {
	if v, err := strconv.ParseInt(os.Getenv("SESSION_TTL_SECONDS"), 10, 64); err == nil && v >= 60 {
		return v
	}
	return 604800 // 7d (ASVS L1; set 43200=12h for L2)
}

func sessionRefresh() int64 {
	if v, err := strconv.ParseInt(os.Getenv("SESSION_REFRESH_SECONDS"), 10, 64); err == nil && v >= 1 {
		return v
	}
	return 86400
}

func sessionReuseGrace() int64 {
	if v, err := strconv.ParseInt(os.Getenv("SESSION_REUSE_GRACE_SECONDS"), 10, 64); err == nil && v >= 0 {
		return v
	}
	return 10
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func splitToken(token string) (string, string, bool) {
	i := strings.IndexByte(token, '.')
	if i <= 0 || i >= len(token)-1 {
		return "", "", false
	}
	return token[:i], token[i+1:], true
}

func sessionIndexAdd(subject, sid string) {
	coreSessionIndex.Do(subject, func(cur []string, _ bool) ([]string, bool) {
		for _, id := range cur {
			if id == sid {
				return cur, false
			}
		}
		return append(cur, sid), true
	})
}

func sessionIndexRemove(subject, sid string) {
	coreSessionIndex.Do(subject, func(cur []string, exists bool) ([]string, bool) {
		if !exists {
			return cur, false
		}
		out := make([]string, 0, len(cur))
		for _, id := range cur {
			if id != sid {
				out = append(out, id)
			}
		}
		return out, true
	})
}

// SessionCreate mints a durable "<id>.<secret>" bearer; only sha256(secret) is stored, exp = now + SESSION_TTL.
// `now` defaults to the wall clock when <= 0. Parity with python/node.
func SessionCreate(subject string, now int64) string {
	if now <= 0 {
		now = time.Now().Unix()
	}
	sid := randToken(16)
	secret := randToken(32)
	coreSessions.Set(sid, sessionRecord{
		Subject: subject, SecretHash: sha256Hex(secret), Exp: now + sessionTTL(), CreatedAt: now, Gen: 1,
	})
	sessionIndexAdd(subject, sid)
	return sid + "." + secret
}

// SessionResolve maps a "<id>.<secret>" bearer to its subject, enforcing now < exp (wall clock), a constant-time
// secret check, and throttled idle-sliding extension. TEST SEAM: under APP_TEST_SESSIONS=1 a "test:<subject>"
// token resolves to <subject> WITHOUT a stored session — INERT in production.
func SessionResolve(token string) (string, bool) {
	if os.Getenv("APP_TEST_SESSIONS") == "1" && strings.HasPrefix(token, "test:") {
		s := strings.TrimPrefix(token, "test:")
		return s, s != ""
	}
	now := time.Now().Unix()
	sid, secret, ok := splitToken(token)
	if !ok {
		return "", false
	}
	rec, found := coreSessions.Get(sid)
	if !found || now >= rec.Exp {
		return "", false
	}
	if !hmac.Equal([]byte(sha256Hex(secret)), []byte(rec.SecretHash)) {
		return "", false
	}
	ttl := sessionTTL()
	if rec.Exp-ttl+sessionRefresh() <= now {
		coreSessions.Do(sid, func(cur sessionRecord, exists bool) (sessionRecord, bool) {
			if !exists || now >= cur.Exp {
				return cur, false
			}
			cur.Exp = now + ttl
			return cur, true
		})
	}
	return rec.Subject, true
}

// SessionRotate rotates a session's secret (/refresh) -> a new "<id>.<secret>" with ok=true, else ok=false.
// Presenting the just-rotated (previous) secret is REUSE -> the session is revoked (theft detection); a secret
// matching neither current nor previous is only rejected.
func SessionRotate(token string, now int64) (string, bool) {
	if now <= 0 {
		now = time.Now().Unix()
	}
	sid, secret, ok := splitToken(token)
	if !ok {
		return "", false
	}
	newSecret := randToken(32)
	var newToken, subject string
	reuse := false
	coreSessions.Do(sid, func(cur sessionRecord, exists bool) (sessionRecord, bool) {
		if !exists || now >= cur.Exp {
			return cur, false
		}
		subject = cur.Subject
		sh := sha256Hex(secret)
		if hmac.Equal([]byte(sh), []byte(cur.SecretHash)) {
			cur.PrevHash = cur.SecretHash
			cur.PrevAt = now // when the prev secret was superseded (reuse-grace clock)
			cur.SecretHash = sha256Hex(newSecret)
			cur.Gen++
			cur.Exp = now + sessionTTL()
			newToken = sid + "." + newSecret
			return cur, true
		}
		// the just-rotated secret presented again: a benign concurrent/retried /refresh WITHIN the grace is rejected
		// but does NOT revoke (the session lives); a stale reuse AFTER the grace is theft -> revoke.
		if cur.PrevHash != "" && hmac.Equal([]byte(sh), []byte(cur.PrevHash)) && now-cur.PrevAt > sessionReuseGrace() {
			reuse = true
		}
		return cur, false
	})
	if reuse {
		coreSessions.Delete(sid)
		if subject != "" {
			sessionIndexRemove(subject, sid)
		}
		return "", false
	}
	if newToken == "" {
		return "", false
	}
	return newToken, true
}

// SessionRevoke drops a session (logout) by its public id; idempotent; also de-indexes the subject.
func SessionRevoke(token string) {
	sid, _, ok := splitToken(token)
	if !ok {
		return
	}
	rec, found := coreSessions.Get(sid)
	coreSessions.Delete(sid)
	if found && rec.Subject != "" {
		sessionIndexRemove(rec.Subject, sid)
	}
}

// SessionRevokeAll drops ALL of a subject's sessions (logout-all / post-password-reset) — O(k) via the index.
func SessionRevokeAll(subject string) {
	var ids []string
	coreSessionIndex.Do(subject, func(cur []string, exists bool) ([]string, bool) {
		ids = cur
		return []string{}, true
	})
	for _, sid := range ids {
		coreSessions.Delete(sid)
	}
}

// SessionTTLSeconds is the active absolute session TTL — auth reads it to fill the interop envelope's expires_in/at.
func SessionTTLSeconds() int64 { return sessionTTL() }

// ── the cross-cutting API-KEY identity resolver (a key AUTHENTICATES as its owner) ────────────────────────────
// api_keys_records is a domain-owned namespace CORE reads directly for cross-cutting identity — the SAME pattern as
// rbac_roles (IsAdmin) / orgs_records (OrgRole): core names the NAMESPACE, never the domain. A partial typed view
// over the api-key JSON (core reads only owner/secret_hash/status; the domain writes the full record).
type coreApiKey struct {
	Owner      string `json:"owner"`
	SecretHash string `json:"secret_hash"`
	Status     string `json:"status"`
}

var coreApiKeys = NewKV[string, coreApiKey]("api_keys_records")

// apiKeyDummyHash is compared when the key id is unknown, so an unknown id and a wrong secret are indistinguishable
// (non-enumerable) — the same posture the api-key /verify route proves.
var apiKeyDummyHash = sha256Hex("apikey-absent-record-filler")

// ApiKeyResolve maps an api-key bearer "ak_<id>_<secret>" to its owner subject (ok=true), else ("", false).
// Constant-time + non-enumerable (ALWAYS one hmac.Equal). The secret may contain '_' (base64url), so the parse is
// SplitN(_, 3). Reproduces the record hash with core's own sha256 (no part import). A v1 key authenticates AS its
// owner; scopes stay advisory. RequireIdentity calls this as a FALLBACK after a session miss, so sessions are unchanged.
func ApiKeyResolve(token string) (string, bool) {
	if !strings.HasPrefix(token, "ak_") {
		return "", false // cheap short-circuit: not a key -> stay on the 401 path
	}
	parts := strings.SplitN(token, "_", 3)
	if len(parts) != 3 {
		return "", false
	}
	keyID, secret := parts[1], parts[2]
	rec, found := coreApiKeys.Get(keyID) // an empty keyID misses -> found=false (matches python/node short-circuit)
	stored := apiKeyDummyHash
	if found {
		stored = rec.SecretHash
	}
	match := hmac.Equal([]byte(sha256Hex(secret)), []byte(stored)) // ALWAYS one constant-time compare (no timing oracle)
	if found && rec.Status == "active" && match {
		return rec.Owner, true
	}
	return "", false
}
