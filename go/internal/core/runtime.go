// Package core is the runtime substrate every domain builds on: the durable store, the RFC 9457 error
// envelope, request decoding, id minting, the test-clock seam, and the observability/safety server wrap.
package core

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// MaxBodyBytes caps a request body (DoS guard); every decode path enforces it. 1 MiB is generous for JSON APIs.
const MaxBodyBytes = 1 << 20

// The DURABLE store backend lives behind a DRIVER (store_sqlite.go — the default; store_postgres.go when DATABASE_URL names Postgres), selected
// once by selectDriver() (store_factory.go) into the package var `driver`. core.go's KV[K,V] is the FACADE over it.

// problemDetail is the RFC 9457 problem+json envelope (mirrors the python and node runtimes).
type problemDetail struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

func WriteProblem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problemDetail{Type: "about:blank", Title: detail, Status: status, Detail: detail})
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// The SSE response MODE (WantsStream + Stream — the streaming sibling of WriteJSON) lives in stream.go, same
// package; statusRecorder below forwards http.Flusher so those frames actually leave per write.

// Fallback — the catch-all the app wiring registers at "/". An unknown path is a problem+json 404; a known
// path reached with the wrong method is a 405 (same semantics as the python and node runtimes — the default
// ServeMux 404 is text/plain, exactly the divergence the shape check exists to catch). `patterns` is the set of
// registered "METHOD /path" strings; we match the request path against their path part (params as wildcards).
func Fallback(patterns []string) http.HandlerFunc {
	type known struct{ re *regexp.Regexp }
	matchers := make([]known, 0, len(patterns))
	for _, p := range patterns {
		parts := strings.SplitN(p, " ", 2)
		if len(parts) != 2 {
			continue
		}
		re := regexp.QuoteMeta(parts[1])
		re = regexp.MustCompile(`\\\{[^/}]+\\\}`).ReplaceAllString(re, `[^/]+`) // {id} -> wildcard
		matchers = append(matchers, known{regexp.MustCompile("^" + re + "$")})
	}
	return func(w http.ResponseWriter, r *http.Request) {
		for _, k := range matchers {
			if k.re.MatchString(r.URL.Path) {
				WriteProblem(w, 405, "method not allowed")
				return
			}
		}
		WriteProblem(w, 404, "not found")
	}
}

// statusRecorder captures the status code so the access log can report it.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush forwards http.Flusher to the wrapped writer so a streaming (SSE) handler can push each frame as it is
// written — net/http's writer implements Flusher, but embedding the ResponseWriter INTERFACE hides the optional
// interfaces, so the wrapper must forward it explicitly or the type assertion fails and frames buffer to the end.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Wrap adds the cross-cutting server behaviour every app needs: a request id (X-Request-Id + log correlation),
// a structured access log line per request, a body-size cap, opt-in CORS (CORS_ALLOWED_ORIGINS), and a panic
// recover that becomes a problem+json 500 instead of a dropped connection. The app wiring wraps its mux with this.
func Wrap(h http.Handler) http.Handler {
	// CORS is OPT-IN via CORS_ALLOWED_ORIGINS — comma-separated exact origins (e.g.
	// "https://app.example.com,http://localhost:3000") or the single wildcard "*". Unset/empty disables it
	// entirely: no header is added and OPTIONS routes exactly as before. Parsed ONCE here; each request then
	// does an exact-string match against the list (never a pattern or suffix match).
	corsOrigins := splitCSV(os.Getenv("CORS_ALLOWED_ORIGINS"))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rid := requestID()
		w.Header().Set("X-Request-Id", rid)
		rawBody := r.Body // the un-capped body, kept so we can DRAIN a rejected oversize upload before the socket closes
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		r = r.WithContext(context.WithValue(r.Context(), ridKey{}, rid))
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		defer func() {
			if err := recover(); err != nil {
				if rec.status == 200 { // nothing written yet
					WriteProblem(rec, 500, "internal error")
				}
				logLine("error", rid, r.Method, r.URL.Path, rec.status, start, fmt.Sprintf("%v", err))
				return
			}
			logLine("info", rid, r.Method, r.URL.Path, rec.status, start, "")
		}()
		if len(corsOrigins) > 0 {
			// The CORS decision for this request: the allowlist entry to echo (the exact matched origin, or "*"),
			// else "". An unlisted Origin is NEVER echoed back — reflecting the caller's Origin would grant every
			// site access.
			origin := r.Header.Get("Origin")
			allowOrigin := ""
			if origin != "" {
				for _, o := range corsOrigins {
					if o == "*" || o == origin {
						allowOrigin = o
						break
					}
				}
			}
			// Answer a CORS preflight (OPTIONS + Origin + Access-Control-Request-Method) BEFORE the mux: 204
			// always, carrying the Access-Control-* grant only for an allowed origin — the browser treats the
			// bare 204 as a denial, and the allowlist is never revealed. An OPTIONS without both headers routes
			// as normal.
			if r.Method == http.MethodOptions && origin != "" && r.Header.Get("Access-Control-Request-Method") != "" {
				if allowOrigin != "" {
					hd := w.Header()
					hd.Set("Access-Control-Allow-Origin", allowOrigin)
					hd.Set("Access-Control-Allow-Methods", r.Header.Get("Access-Control-Request-Method"))
					allowHeaders := r.Header.Get("Access-Control-Request-Headers")
					if allowHeaders == "" {
						allowHeaders = "Authorization, Content-Type, Idempotency-Key"
					}
					hd.Set("Access-Control-Allow-Headers", allowHeaders)
					hd.Set("Access-Control-Max-Age", "600")
					if allowOrigin != "*" {
						hd.Set("Vary", "Origin") // the grant varies by Origin, so caches must key on it
					}
				}
				rec.WriteHeader(204)
				return
			}
			// An actual (non-preflight) request from an allowed origin carries the grant on EVERY response,
			// errors included — a browser app can only READ a 4xx/5xx body when the grant is present.
			if allowOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
				w.Header().Set("Access-Control-Expose-Headers", "X-Request-Id")
				if allowOrigin != "*" {
					w.Header().Set("Vary", "Origin")
				}
			}
		}
		// REJECT an ENCODED path separator (%2F / %5C) BEFORE the mux — the one real ×3 path-param drift: go/node
		// route THEN decode (so `%2F` is captured intact inside a {slug}), but python decodes BEFORE routing (so the
		// segment splits → mis-route/404). EscapedPath preserves the raw %2F (Go sets RawPath when decoding changes the
		// path); a non-structural %xx like %6D re-escapes away, so only the segment-splitters are rejected. Uniform 404.
		if esc := strings.ToLower(r.URL.EscapedPath()); strings.Contains(esc, "%2f") || strings.Contains(esc, "%5c") {
			WriteProblem(rec, 404, "not found")
			return // the deferred logLine records the 404
		}
		// REJECT an EMPTY path segment (a literal `//`) BEFORE the mux — the second ×3 router drift: go's
		// ServeMux canonicalizes `//` and 301-redirects to the cleaned path, but python ({param} = [^/]+) and node
		// (([^/]+)) never match an empty segment, so both 404. No valid route has an empty segment → uniform 404.
		if strings.Contains(r.URL.Path, "//") {
			WriteProblem(rec, 404, "not found")
			return
		}
		// REJECT a DUPLICATED query parameter (?x=1&x=2) BEFORE the mux — the frameworks disagree on a repeat
		// (starlette takes the LAST value, go/node the FIRST), so a duplicated scalar would page/filter differently
		// ×3. A uniform 422 (the canonical-input stance, like the dup-header reject) keeps every scalar identical ×3.
		for _, vals := range r.URL.Query() {
			if len(vals) > 1 {
				WriteProblem(rec, 422, "duplicate query parameter")
				return
			}
		}
		h.ServeHTTP(rec, r)
		// 413 cold-drain (live-server reset hardening): MaxBytesReader stops reading at the cap and sets
		// Connection: close. If the client is STILL uploading the oversize body when net/http then closes, Windows
		// RSTs the socket and the client gets `WinError 10054` instead of reading the 413 — the verifier's error-shape
		// probe (a >1 MiB POST) loses this race under full-bar load. Reading a BOUNDED remainder of the client's
		// upload (never unbounded — the DoS guard holds: a flood past the extra cap is still cut off) lets a
		// well-behaved client finish sending and read the 413 cleanly. The 413 RESPONSE is unchanged → parity ×3 holds.
		if rec.status == 413 {
			_, _ = io.Copy(io.Discard, io.LimitReader(rawBody, MaxBodyBytes))
		}
	})
}

// splitCSV parses a comma-separated env value into its non-empty trimmed entries ("" -> none).
func splitCSV(raw string) []string {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

type ridKey struct{}

func requestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// RequestID returns the per-request id (set by Wrap into the context) — the AU-3 'source' of a domain access audit,
// for correlation with the access log. "-" if absent (a handler reached outside Wrap, e.g. a direct unit call). x3.
func RequestID(r *http.Request) string {
	if rid, ok := r.Context().Value(ridKey{}).(string); ok {
		return rid
	}
	return "-"
}

// logLine — one structured JSON access log line to stderr (set LOG_LEVEL=silent to suppress).
func logLine(level, rid, method, path string, status int, start time.Time, errMsg string) {
	if os.Getenv("LOG_LEVEL") == "silent" {
		return
	}
	entry := map[string]any{
		"level": level, "request_id": rid, "method": method, "path": path,
		"status": status, "ms": time.Since(start).Milliseconds(),
	}
	if errMsg != "" {
		entry["error"] = errMsg
	}
	b, _ := json.Marshal(entry)
	fmt.Fprintln(os.Stderr, string(b))
}

// The core session STORE seam — records · TTL · rotate+reuse-detection · revoke · the subject index — lives in
// session.go (same package core). RequireIdentity below is the HTTP-layer guard that reads it.

// RequireIdentity returns the authenticated subject from the bearer token, or writes a 401 and returns ok=false.
// A scoping domain calls THIS instead of trusting a header/param — identity comes from a real session.
func RequireIdentity(w http.ResponseWriter, r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		WriteProblem(w, 401, "not authenticated")
		return "", false
	}
	subject, ok := SessionResolve(strings.TrimPrefix(header, "Bearer "))
	if !ok {
		subject, ok = ApiKeyResolve(strings.TrimPrefix(header, "Bearer ")) // session miss -> try an api-key bearer (owner identity)
	}
	if !ok {
		WriteProblem(w, 401, "invalid or expired token")
		return "", false
	}
	return subject, true
}

// RevokeCurrent revokes the CURRENT request's session (logout-local): the bearer is read HERE in CORE, so a domain
// never parses the auth header itself.
func RevokeCurrent(r *http.Request) {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && h[:7] == "Bearer " {
		SessionRevoke(h[7:])
	}
}

// ── the cross-cutting ADMIN seam (core owns the NOTION; rbac is the management surface) ──────────────────────
// The role store ("rbac_roles") is a core-recognized cross-cutting namespace, exactly as "_sessions" is: rbac is
// the management SURFACE (assign/revoke roles), core owns the NOTION — so ANY domain gates an admin-only operation
// WITHOUT importing rbac (the boundary rule holds: domains -> core only). Two KV handles on one namespace are just
// typed views over the same rows.
var coreRoles = NewKV[string, []string]("rbac_roles")

const coreTestAdmin = "root" // the fixed bootstrap admin recognized ONLY under the test seam (inert in production)

// IsAdmin reports whether `subject` holds the 'admin' role. PRODUCTION bootstrap is OUT-OF-BAND (the operator
// seeds rbac_roles[<a real, already-registered subject>]=["admin"] at deploy); there is NO env-NAME seed — a
// claimable username was a privilege-escalation hole. The only auto-admin is the TEST seam: under
// APP_TEST_SESSIONS=1 (inert in prod, like the test-session backdoor) the fixed test admin
// is recognized, so manifest/invariant tests can exercise admin paths without an out-of-band store seed.
func IsAdmin(subject string) bool {
	if os.Getenv("APP_TEST_SESSIONS") == "1" && subject == coreTestAdmin {
		return true
	}
	roles, _ := coreRoles.Get(subject)
	for _, role := range roles {
		if role == "admin" {
			return true
		}
	}
	return false
}

// RequireAdmin returns the authenticated subject REQUIRED to be an admin, else writes 401 (no/invalid identity) or
// 403 (valid identity, not an admin) and returns ok=false. An admin-only domain calls THIS: authn -> authz BEFORE
// decode, so a non-admin gets 403 not the body's 422 — identical ×3 with python/node.
func RequireAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	subject, ok := RequireIdentity(w, r)
	if !ok {
		return "", false
	}
	if !IsAdmin(subject) {
		WriteProblem(w, 403, "this operation requires the admin role")
		return "", false
	}
	return subject, true
}

// the cross-cutting ORG-MEMBERSHIP store: key "<slug>\x1f<handle>" -> role ("owner"|"admin"|"member"). orgs is the
// management SURFACE (add/remove members, set roles); core owns the NOTION so teams authorize against org membership
// WITHOUT importing orgs (boundary rule: domains -> core only). The \x1f delimiter is un-forgeable (slugs/handles
// are well_formed — no control chars). Same cross-cutting pattern as "_sessions" / "rbac_roles". A partial typed view
// over the membership JSON: core reads only Role+Status; orgs writes the full record (org/handle/invite_*).
type coreMember struct {
	Role   string `json:"role"`
	Status string `json:"status"`
}

var coreOrgMembers = NewKV[string, coreMember]("orgs_members")

// SINGLE-SOURCE OWNERSHIP: the OWNER is DERIVED from orgs_records.owner (the ONE canonical owner field), not a
// membership row — a partial typed view over the orgs_records JSON (Go ignores the unread fields). orgs writes the
// full record; core reads only owner. Same two-views-on-one-namespace pattern as coreOrgMembers above.
type coreOrgRec struct {
	Owner string `json:"owner"`
}

var coreOrgRecords = NewKV[string, coreOrgRec]("orgs_records")

// OrgRole returns `subject`'s role within `org` ("owner"|"admin"|"member") or ("", false) if not a member. The OWNER
// is derived from orgs_records.owner (single-source). A membership row grants its role ONLY when Status == "active":
// a "pending" invite (one the holder has not ACCEPTED with the single-use token) confers NOTHING — this closes the
// member-identity escalation (a manager could pre-name a raw handle an attacker then self-registers).
func OrgRole(org, subject string) (string, bool) {
	if rec, ok := coreOrgRecords.Get(org); ok && rec.Owner == subject {
		return "owner", true // ownership is single-sourced in orgs_records.owner (derived, not a membership row)
	}
	if m, ok := coreOrgMembers.Get(org + "\x1f" + subject); ok && m.Status == "active" && m.Role != "owner" {
		return m.Role, true // ACCEPTED admin|member grants; a membership row NEVER confers 'owner' (single-source defense-in-depth)
	}
	return "", false // no row, a pending invite, OR (defended) a stray owner-role row -> no role at all
}

// ── the cross-cutting SERVICE seam (a trusted service caller, not a user) ─────────────────────────────────────
// A CONSTANT-TIME match of the Bearer token against the env SERVICE_TOKEN — a service secret, NOT a user session
// (identity-exempt; the cross-cutting generalization of admin's break-glass token). For server-side PRIMITIVES a
// user must not reach: a throttle that runs BEFORE the user is authenticated (rate limiting — login brute-force
// protection), trusted audit-event ingestion. A non-service caller is 401 — the same 401 for no header / wrong
// scheme / wrong token (non-enumerable). Compares FIXED-LENGTH sha256 digests so the compare is length-independent
// (no length leak), identical ×3 with python/node.
func RequireService(w http.ResponseWriter, r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	token := ""
	if strings.HasPrefix(header, "Bearer ") {
		token = strings.TrimPrefix(header, "Bearer ")
	}
	want := EnvOr("SERVICE_TOKEN", "service_dev_token_change_me") // env-backed, rotatable; identity-exempt
	got := sha256.Sum256([]byte(token))
	exp := sha256.Sum256([]byte(want))
	if !hmac.Equal(got[:], exp[:]) {
		WriteProblem(w, 401, "service authorization required")
		return "", false
	}
	return "service", true
}
