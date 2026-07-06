// Package auth — password authentication + the full session lifecycle, OWASP ASVS V2/V3-shaped and INTEROP-READY
// (the response envelope matches Supabase/Firebase/Auth0/Clerk/Cognito — see INTEROP.md). Passwords are salted +
// hashed via the CENTRAL password_hash part (PBKDF2-HMAC-SHA256, env-tunable iterations ≥ the ASVS floor); verify
// is constant-time and unknown-user == wrong-password (no enumeration, no timing leak). Sessions are the core
// "<id>.<secret>" seam (TTL + rotation + scoped logout). Registration is ENUMERATION-SAFE (silent success); email
// verify + password reset are single-use expiring token flows; pre-auth endpoints are throttled via the core seam.
// Store namespaces + record shapes match python/node; state survives a restart.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"unicode/utf8"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/env_int"
	"app/internal/parts/password_hash"
	"app/internal/parts/well_formed"
)

const pwMin, pwMax = 8, 128 // min(8) ASVS 2.1.1; max(128) defends the unauth PBKDF2-DoS — COUNTS RUNES (×3 parity)

type authUser struct {
	Salt          string `json:"salt"`
	Hash          string `json:"hash"`
	EmailVerified bool   `json:"email_verified"`
	CreatedAt     int64  `json:"created_at"`
}

type authToken struct {
	Subject    string `json:"subject"`
	SecretHash string `json:"secret_hash"`
	Exp        int64  `json:"exp"`
}

type outboxEntry struct {
	To    string `json:"to"`
	Kind  string `json:"kind"`
	Token string `json:"token"`
}

var (
	authUsers  = core.NewKV[string, authUser]("auth_users")
	authReset  = core.NewKV[string, authToken]("auth_reset")
	authVerify = core.NewKV[string, authToken]("auth_verify")
	authOutbox = core.NewKV[string, outboxEntry]("auth_outbox")
)

func iterations() int { return env_int.EnvInt(os.Getenv("AUTH_PBKDF2_ITERATIONS"), 200_000, 100_000) }

func pwOK(pw string) bool { n := utf8.RuneCountInString(pw); return n >= pwMin && n <= pwMax }


func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func randURL(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func splitDot(token string) (string, string, bool) {
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			if i == 0 || i == len(token)-1 {
				return "", "", false
			}
			return token[:i], token[i+1:], true
		}
	}
	return "", "", false
}

func throttleOK(w http.ResponseWriter, action, key string, now int64) bool {
	if !core.Throttle("auth:"+action+":"+key, env_int.EnvInt(os.Getenv("AUTH_THROTTLE_LIMIT"), 10, 1), int64(env_int.EnvInt(os.Getenv("AUTH_THROTTLE_WINDOW"), 300, 1)), now) {
		core.WriteProblem(w, 429, "too many requests — slow down")
		return false
	}
	return true
}

func decodeCreds(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	in, ok := core.DecodeJSON[struct {
		Email    *string `json:"email"`
		Password *string `json:"password"`
	}](w, r)
	if !ok {
		return "", "", false
	}
	if in.Email == nil || in.Password == nil || !well_formed.IsWellFormed(*in.Email) || !pwOK(*in.Password) {
		core.WriteProblem(w, 422, "invalid body")
		return "", "", false
	}
	return *in.Email, *in.Password, true
}

func userRecord(password string, now int64) authUser {
	salt := randB64(16)
	return authUser{Salt: salt, Hash: password_hash.HashPassword(password, salt, iterations()), EmailVerified: false, CreatedAt: now}
}

func userOut(email string, u authUser) map[string]any {
	return map[string]any{"id": email, "email": email, "email_verified": u.EmailVerified, "created_at": u.CreatedAt}
}

// the interop envelope. access_token == refresh_token == the rotating opaque server-side session token (single-token
// model; /refresh rotates it) — a DELIBERATE divergence from the AT/RT split (server-side sessions revoke immediately).
func envelopeBody(token, email string, u authUser, now int64) map[string]any {
	ttl := core.SessionTTLSeconds()
	return map[string]any{"access_token": token, "refresh_token": token, "token_type": "bearer",
		"expires_in": ttl, "expires_at": now + ttl, "user": userOut(email, u)}
}

func deliver(kind, to, token string) { authOutbox.Set(kind+":"+to, outboxEntry{To: to, Kind: kind, Token: token}) }

func mint(kv *core.KV[string, authToken], subject string, ttl, now int64) string {
	rid, secret := randURL(12), randURL(32)
	kv.Set(rid, authToken{Subject: subject, SecretHash: digest.DigestHex(secret), Exp: now + ttl})
	return rid + "." + secret
}

// consume — SINGLE-USE: atomically (Do seam) verify + tombstone the token iff present, unexpired, secret matches.
func consume(kv *core.KV[string, authToken], token string, now int64) (string, bool) {
	rid, secret, ok := splitDot(token)
	if !ok {
		return "", false
	}
	subject, found := "", false
	kv.Do(rid, func(cur authToken, exists bool) (authToken, bool) {
		if exists && now < cur.Exp && cur.SecretHash != "" && hmac.Equal([]byte(digest.DigestHex(secret)), []byte(cur.SecretHash)) {
			subject, found = cur.Subject, true
			return authToken{Subject: cur.Subject, SecretHash: "", Exp: 0}, true // tombstone -> single-use
		}
		return cur, false
	})
	return subject, found
}

func AuthRegister(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: public — ENUMERATION-SAFE signup: identical response new-or-existing, PBKDF2 on both paths.
	email, password, ok := decodeCreds(w, r)
	if !ok {
		return
	}
	now := core.TestNow(r)
	if !throttleOK(w, "register", email, now) {
		return
	}
	record := userRecord(password, now) // PBKDF2 on both paths (flat timing) before the claim
	created := false
	authUsers.Do(email, func(cur authUser, exists bool) (authUser, bool) {
		if exists {
			return cur, false
		}
		created = true
		return record, true
	})
	if created {
		deliver("verify", email, mint(authVerify, email, int64(env_int.EnvInt(os.Getenv("AUTH_VERIFY_TTL_SECONDS"), 86400, 60)), now))
	}
	core.WriteJSON(w, 200, map[string]any{"message": "if the email is unregistered, a verification link has been sent"})
}

func AuthLogin(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: public — constant-time password check even for an absent user (no enumeration). -> envelope.
	email, password, ok := decodeCreds(w, r)
	if !ok {
		return
	}
	now := core.TestNow(r)
	if !throttleOK(w, "login", email, now) {
		return
	}
	user, exists := authUsers.Get(email)
	salt := user.Salt
	if !exists {
		salt = randB64(16)
	}
	valid := password_hash.VerifyPassword(password, salt, iterations(), user.Hash)
	if !exists || !valid {
		core.WriteProblem(w, 401, "invalid credentials")
		return
	}
	if os.Getenv("AUTH_REQUIRE_VERIFIED") == "1" && !user.EmailVerified {
		core.WriteProblem(w, 401, "email not verified")
		return
	}
	core.WriteJSON(w, 200, envelopeBody(core.SessionCreate(email, now), email, user, now))
}

func AuthRefresh(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: refresh-token — the rotation token IS the credential; rotate (old dies); reuse -> revoke.
	in, ok := core.DecodeJSON[struct {
		Token *string `json:"token"`
	}](w, r)
	if !ok {
		return
	}
	if in.Token == nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	now := core.TestNow(r)
	newTok, rotated := core.SessionRotate(*in.Token, now)
	if !rotated {
		core.WriteProblem(w, 401, "invalid or expired token")
		return
	}
	subject, _ := core.SessionResolve(newTok)
	user, _ := authUsers.Get(subject)
	core.WriteJSON(w, 200, envelopeBody(newTok, subject, user, now))
}

func AuthLogout(w http.ResponseWriter, r *http.Request) {
	subject, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if r.URL.Query().Get("scope") == "global" {
		core.SessionRevokeAll(subject)
	} else {
		core.RevokeCurrent(r) // the bearer is read in CORE, never parsed in the domain
	}
	core.WriteJSON(w, 200, map[string]any{"message": "logged out"})
}

func AuthResetRequest(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: public — ENUMERATION-SAFE: always 200; token minted on both paths (flat timing); only a real
	// account's token is delivered (never email a reset link to a non-account).
	in, ok := core.DecodeJSON[struct {
		Email *string `json:"email"`
	}](w, r)
	if !ok {
		return
	}
	if in.Email == nil || !well_formed.IsWellFormed(*in.Email) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	now := core.TestNow(r)
	if !throttleOK(w, "reset", *in.Email, now) {
		return
	}
	token := mint(authReset, *in.Email, int64(env_int.EnvInt(os.Getenv("AUTH_RESET_TTL_SECONDS"), 3600, 60)), now)
	if _, exists := authUsers.Get(*in.Email); exists {
		deliver("reset", *in.Email, token)
	} else {
		authOutbox.Set("__pad__", outboxEntry{Kind: "pad"}) // equal store work on the absent path (timing flatness)
	}
	core.WriteJSON(w, 200, map[string]any{"message": "if the email is registered, a reset link has been sent"})
}

func AuthResetConfirm(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: reset-token — single-use token; set the new password AND revoke ALL sessions (ASVS 3.3.3 / #8).
	in, ok := core.DecodeJSON[struct {
		Token    *string `json:"token"`
		Password *string `json:"password"`
	}](w, r)
	if !ok {
		return
	}
	if in.Token == nil || in.Password == nil || !pwOK(*in.Password) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	now := core.TestNow(r)
	subject, consumed := consume(authReset, *in.Token, now)
	if !consumed {
		core.WriteProblem(w, 400, "invalid or expired reset token")
		return
	}
	salt := randB64(16)
	newHash := password_hash.HashPassword(*in.Password, salt, iterations()) // PBKDF2 outside the Do (fn must be pure)
	updated := false
	authUsers.Do(subject, func(cur authUser, exists bool) (authUser, bool) { // atomic RMW: no lost update vs verify
		if !exists {
			return cur, false
		}
		cur.Salt, cur.Hash, updated = salt, newHash, true
		return cur, true
	})
	if !updated {
		core.WriteProblem(w, 400, "invalid or expired reset token")
		return
	}
	core.SessionRevokeAll(subject)
	core.WriteJSON(w, 200, map[string]any{"message": "password reset; all sessions ended"})
}

func AuthVerifyRequest(w http.ResponseWriter, r *http.Request) {
	subject, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	now := core.TestNow(r)
	if !throttleOK(w, "verify", subject, now) {
		return
	}
	deliver("verify", subject, mint(authVerify, subject, int64(env_int.EnvInt(os.Getenv("AUTH_VERIFY_TTL_SECONDS"), 86400, 60)), now))
	core.WriteJSON(w, 200, map[string]any{"message": "verification link sent"})
}

func AuthVerifyConfirm(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: verify-token — single-use token; marks the bound subject's email verified.
	in, ok := core.DecodeJSON[struct {
		Token *string `json:"token"`
	}](w, r)
	if !ok {
		return
	}
	if in.Token == nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	now := core.TestNow(r)
	subject, consumed := consume(authVerify, *in.Token, now)
	if !consumed {
		core.WriteProblem(w, 400, "invalid or expired verification token")
		return
	}
	updated := false
	authUsers.Do(subject, func(cur authUser, exists bool) (authUser, bool) { // atomic RMW: no lost update vs reset
		if !exists {
			return cur, false
		}
		cur.EmailVerified, updated = true, true
		return cur, true
	})
	if !updated {
		core.WriteProblem(w, 400, "invalid or expired verification token")
		return
	}
	core.WriteJSON(w, 200, map[string]any{"message": "email verified"})
}

func AuthMe(w http.ResponseWriter, r *http.Request) {
	// identity from the core session seam: deny-by-default (no/invalid/expired token -> 401).
	subject, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	user, _ := authUsers.Get(subject)
	core.WriteJSON(w, 200, userOut(subject, user))
}
