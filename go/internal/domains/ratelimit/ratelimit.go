// Package ratelimit — fixed-window rate limiting. The dangerous property is that THE LIMIT HOLDS: at most LIMIT
// requests per key per window, the (LIMIT+1)th is 429, and — the part naive limiters get wrong — the consume is
// ONE atomic consume-or-deny read-modify-write through (*KV).Do, so concurrent processes cannot race past the
// limit (a Get-then-Set limiter is breachable under load; this one is not). Windows derive from the test-clock
// seam; the counter is durable, so a restart never resets a window. LIMIT and WINDOW are env knobs. Store names
// and the row model match the python/node impls.
package ratelimit

import (
	"encoding/json"
	"fmt"
	"net/http"

	"app/internal/core"
	"app/internal/parts/env_int"
	"app/internal/parts/well_formed"
)

var (
	ratelimitLimit  = env_int.EnvInt(core.EnvOr("RATELIMIT_LIMIT", ""), 5)
	ratelimitWindow = env_int.EnvInt(core.EnvOr("RATELIMIT_WINDOW", ""), 60)
	ratelimitWindows   = core.NewKV[string, int]("ratelimit_windows")
)

func RatelimitCheck(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: service — a server-side throttle PRIMITIVE, NOT a user action, gated by the trusted SERVICE
	// seam (core.RequireService), NOT RequireIdentity: the throttle runs BEFORE the user is authenticated (login
	// brute-force protection throttles the username on the login attempt itself, pre-auth) and its subject is the
	// caller-supplied `key` (an ip/username/api-key) which the trusted service vouches for. Body-only precedence is
	// PARSE -> AUTH -> SEMANTIC: decode raw JSON FIRST (413/malformed), THEN RequireService, THEN validate the key —
	// so an unauthenticated ill-typed body is 401 not 422, ×3. The `mutation-auth: service` declaration + the
	// RequireService call sit in one handler — the declaration cannot drift from the enforcement.
	// body-only precedence PARSE -> AUTH -> SEMANTIC: decode the key as RAW JSON FIRST (only malformed JSON / 413
	// fails here), THEN RequireService, THEN type+well_formed-check the key — so an unauthenticated ill-typed body
	// (e.g. {"key": 7}) is 401 not 422, exactly like python's Depends + node, ×3 (mirrors audit_log's append).
	in, ok := core.DecodeJSON[struct {
		Key *json.RawMessage `json:"key"`
	}](w, r)
	if !ok {
		return
	}
	if _, ok := core.RequireService(w, r); !ok { // AUTH: trusted service caller, BEFORE the semantic key check
		return
	}
	var key string
	if in.Key == nil || json.Unmarshal(*in.Key, &key) != nil || !well_formed.IsWellFormed(key) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	windowID := core.TestNow(r) / int64(ratelimitWindow)
	// ATOMIC consume-or-deny: read the count and increment it in ONE exclusive transaction — two processes
	// racing the same key cannot both see count==LIMIT-1 and both pass. fn stays pure (no store calls inside).
	remaining := -1
	ratelimitWindows.Do(fmt.Sprintf("%s:%d", key, windowID), func(count int, exists bool) (int, bool) {
		if count >= ratelimitLimit {
			return count, false // deny: leave the row untouched
		}
		remaining = ratelimitLimit - (count + 1)
		return count + 1, true
	})
	if remaining < 0 {
		core.WriteProblem(w, 429, "rate limit exceeded")
		return
	}
	core.WriteJSON(w, 200, map[string]any{"allowed": true, "remaining": remaining})
}
