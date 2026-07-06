// Package feature_flags — deterministic percentage rollout via stable hash bucketing. The dangerous property
// is STABLE BUCKETING: a subject's bucket is a fixed function of (key, subject) through the digest part, so
// evaluation is DETERMINISTIC and MONOTONIC under rollout increase (raising the percentage only ADMITS more
// subjects — no flapping). rollout 0..100; bucket 0..99; enabled iff bucket < rollout. Matches python/node;
// durable.
//
// WRITES ARE ADMIN-ONLY: a feature flag is a control-plane kill-switch — an anonymous flip is a live P0.
// Create + SetRollout require the 'admin' role (the core RequireAdmin seam): no token 401, non-admin 403. The
// precedence differs by route shape, identical to python/node:
//   - Create (body-only): PARSE -> AUTH -> SEMANTIC. Decode the body as raw JSON FIRST (only malformed JSON / a
//     413 fails here, and the body MUST be drained before replying), THEN RequireAdmin, THEN strict per-field
//     validation (rollout via RequireIntRaw on the raw bytes) — so an unauthenticated ill-typed body is 401, ×3.
//   - SetRollout (path+body): AUTH FIRST, then the rollout int (RequireIntRaw), then the path-404 load — a
//     no-token request is 401 before any 422/404, matching python's Depends firing before path validation.
// READS (Get, Evaluate) stay OPEN: evaluate is the runtime hot path consuming apps call per request.
package feature_flags

import (
	"encoding/json"
	"net/http"
	"strconv"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/well_formed"
)

type featureFlagsRecord struct {
	Key     string `json:"key"`
	Rollout int    `json:"rollout"`
}

var featureFlagsRecords = core.NewKV[string, featureFlagsRecord]("feature_flags_records")

func featureFlagsBucket(key, subject string) int {
	// first 32 bits of sha256(key:subject) mod 100 — fixed per (key, subject), identical x3
	n, _ := strconv.ParseInt(digest.DigestHex(key, subject)[:8], 16, 64)
	return int(n % 100)
}

func featureFlagsValidRollout(v *json.RawMessage) (int, bool) {
	if v == nil {
		return 0, false
	}
	n, ok := core.RequireIntRaw(*v) // STRICT: an integer literal, not 5.0 / "5" / true (×3 with python StrictInt)
	if !ok || n < 0 || n > 100 {
		return 0, false
	}
	return n, true
}

func FeatureFlagsCreate(w http.ResponseWriter, r *http.Request) {
	// PARSE: decode the body FIRST (only malformed JSON / a 413 fails here, and the body must be drained before any
	// reply) — per-field type checks are SEMANTIC and run AFTER auth, exactly like python's pydantic, ×3.
	in, ok := core.DecodeJSON[struct {
		Key     *string          `json:"key"`
		Rollout *json.RawMessage `json:"rollout"`
	}](w, r)
	if !ok {
		return
	}
	if _, ok := core.RequireAdmin(w, r); !ok { // AUTH: admin-only, BEFORE any semantic validation -> ill-typed body is 401
		return
	}
	if in.Key == nil || !well_formed.IsWellFormed(*in.Key) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	rollout := 0
	if in.Rollout != nil {
		v, valid := featureFlagsValidRollout(in.Rollout)
		if !valid {
			core.WriteProblem(w, 422, "rollout must be an integer 0..100")
			return
		}
		rollout = v
	}
	rec := featureFlagsRecord{Key: *in.Key, Rollout: rollout}
	// claim-once via the Do seam: a Get-then-Set RACES — two concurrent creates of one key both pass the check and
	// the second overwrites the first. Do holds the write lock across read+write; first writer wins.
	created := false
	featureFlagsRecords.Do(*in.Key, func(cur featureFlagsRecord, exists bool) (featureFlagsRecord, bool) {
		if exists {
			return cur, false
		}
		created = true
		return rec, true
	})
	if !created {
		core.WriteProblem(w, 409, "flag key taken")
		return
	}
	core.WriteJSON(w, 201, rec)
}

func featureFlagsLoad(w http.ResponseWriter, r *http.Request) (featureFlagsRecord, bool) {
	key := r.PathValue("key")
	if !well_formed.IsWellFormed(key) {
		core.WriteProblem(w, 422, "the flag key must be non-empty with no control characters")
		return featureFlagsRecord{}, false
	}
	flag, exists := featureFlagsRecords.Get(key)
	if !exists {
		core.WriteProblem(w, 404, "flag not found")
		return featureFlagsRecord{}, false
	}
	return flag, true
}

func FeatureFlagsGet(w http.ResponseWriter, r *http.Request) {
	// read-scope: global — app-global flag config (admins set the rollout via require_admin; any caller reads the flag state).
	if flag, ok := featureFlagsLoad(w, r); ok {
		core.WriteJSON(w, 200, flag)
	}
}

func FeatureFlagsSetRollout(w http.ResponseWriter, r *http.Request) {
	if _, ok := core.RequireAdmin(w, r); !ok { // AUTH FIRST (path+body): a no-token request is 401 before any 422/404, ×3
		return
	}
	in, ok := core.DecodeJSON[struct {
		Rollout *json.RawMessage `json:"rollout"`
	}](w, r)
	if !ok {
		return
	}
	rollout, valid := featureFlagsValidRollout(in.Rollout)
	if !valid {
		core.WriteProblem(w, 422, "rollout must be an integer 0..100")
		return
	}
	flag, found := featureFlagsLoad(w, r)
	if !found {
		return
	}
	flag.Rollout = rollout
	featureFlagsRecords.Set(flag.Key, flag)
	core.WriteJSON(w, 200, flag)
}

func FeatureFlagsEvaluate(w http.ResponseWriter, r *http.Request) {
	// read-scope: global — deterministic flag evaluation for a caller-supplied subject; app-global config, no per-owner data.
	flag, ok := featureFlagsLoad(w, r)
	if !ok {
		return
	}
	subject := r.URL.Query().Get("subject")
	if !well_formed.IsWellFormed(subject) {
		core.WriteProblem(w, 422, "the subject query parameter is required")
		return
	}
	enabled := featureFlagsBucket(flag.Key, subject) < flag.Rollout
	core.WriteJSON(w, 200, map[string]any{"key": flag.Key, "subject": subject, "enabled": enabled})
}
