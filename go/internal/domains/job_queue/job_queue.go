// Package jobs — the async job QUEUE: enqueue background work; a trusted worker pool CLAIMS the next ready job (an
// exclusive lease), then COMPLETEs or FAILs it; a failed job retries with deterministic backoff until dead-lettered.
// Dangerous properties, all proven (same ×3 as jobs.py / jobs.js):
// (1) AT-MOST-ONCE CLAIM: a ready job is leased to AT MOST ONE worker — the claim is a single-key Do()-CAS, so two
//     workers racing the same job cannot both win (I-CLAIM-ONCE). The pick is the lowest-id ready job, sorted BEFORE
//     the CAS (All() is rowid order, not stable ×3).
// (2) COMPLETION-AUTH (the fencing token): claim mints a rotating lease_token; complete/fail REQUIRE it and the CAS
//     asserts token==current AND status==running — a STALE worker (lease expired, job reclaimed) cannot complete/
//     reset the new claimant's job (I-COMPLETE-AUTH). Acquire-exclusivity is NOT release-safety.
// (3) BOUNDED RETRY: delivered at most max_attempts times whether the failure is EXPLICIT (fail) or a CRASH (lease
//     lapses, job reclaimed) — Attempts increments at CLAIM, and BOTH the fail path AND the reclaim path dead-letter
//     at Attempts>=Max (I-RETRY-BOUNDED). A poison job that crashes the worker cannot retry forever.
// (4) DETERMINISTIC BACKOFF: run_at = now + min(base * 2^min(attempts,30), cap) — no jitter, identical ×3
//     (I-BACKOFF-DET); the clamped exponent + bounded env keep base*2^attempt from overflowing int64 / losing precision.
// (5) OWNER-SCOPED reads: enqueue stamps owner from the authenticated subject (never a body field); get/list return
//     ONLY the caller's jobs, a cross-owner id is 404. The worker pool (claim/complete/fail) is the trusted SERVICE
//     seam — cross-owner infrastructure, authorized by the service token + the lease.
// (6) PAYLOAD CONTAINED: the opaque payload is ×3-safe via well_formed.SanitizeJSON (lone surrogate -> U+FFFD, the
//     2^53 ceiling) — durable storage never crashes serialization nor diverges ×3 (I-PAYLOAD-SAFE).
// State: the durable store (ns "job_queue_records", key str(id)); at-least-once delivery (handlers MUST be idempotent).
// See INTEROP.md for the SQS / River / BullMQ / Sidekiq mapping.
package job_queue

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/env_int"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

const (
	jobsNS             = "job_queue_records"
	jobsSeq            = "job_queue_job"
	jobsLeaseRoute     = "/job_queue/lease"
	jobsMaxAttemptsCap = 1000     // a per-job max_attempts override is clamped to [1, this] — the hard delivery bound
	jobsDelayCap       = 31536000 // a delay is clamped to [0, 1 year]
	jobsShiftCap       = 30       // 2^30 ceiling on the backoff exponent so base*2^attempt can't overflow int64
)

type jobsRecord struct {
	Id          int            `json:"id"`
	Owner       string         `json:"owner"`
	Kind        string         `json:"kind"`
	Payload     map[string]any `json:"payload"`
	Queue       string         `json:"queue"`
	Status      string         `json:"status"`
	Attempts    int            `json:"attempts"`
	MaxAttempts int            `json:"max_attempts"`
	RunAt       int            `json:"run_at"`
	LeaseUntil  int            `json:"lease_until"`
	LeaseToken  string         `json:"lease_token"`
	CreatedAt   int            `json:"created_at"`
	UpdatedAt   int            `json:"updated_at"`
	LastError   string         `json:"last_error"`
}

var jobsKV = core.NewKV[string, jobsRecord](jobsNS)

func jobsClamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

var (
	jobsDefaultMaxAttempts = env_int.EnvInt(core.EnvOr("JOB_QUEUE_MAX_ATTEMPTS", ""), 20, 1, jobsMaxAttemptsCap)
	jobsBackoffBase        = env_int.EnvInt(core.EnvOr("JOB_QUEUE_BACKOFF_BASE_SECONDS", ""), 2, 1, 3600)
	jobsBackoffCap         = env_int.EnvInt(core.EnvOr("JOB_QUEUE_BACKOFF_CAP_SECONDS", ""), 3600, jobsBackoffBase, 86400)
	jobsVisibility         = env_int.EnvInt(core.EnvOr("JOB_QUEUE_VISIBILITY_SECONDS", ""), 300, 1, 86400)
)

// jobsBackoff: run_at delta = min(base * 2^min(attempts, 30), cap) — DETERMINISTIC, no jitter; the clamped exponent
// keeps base*2^shift < 2^53 so the value is identical ×3.
func jobsBackoff(attempts int) int {
	shift := attempts
	if shift > jobsShiftCap {
		shift = jobsShiftCap
	}
	d := jobsBackoffBase * (1 << uint(shift))
	if d > jobsBackoffCap {
		d = jobsBackoffCap
	}
	return d
}

func jobsClaimable(rec jobsRecord, now int) bool {
	return (rec.Status == "queued" && rec.RunAt <= now) || (rec.Status == "running" && rec.LeaseUntil <= now)
}

func jobsPublic(rec jobsRecord) map[string]any {
	// the owner-facing view — every field EXCEPT lease_token (the worker's fencing capability, returned only by claim)
	return map[string]any{"id": rec.Id, "owner": rec.Owner, "kind": rec.Kind, "payload": rec.Payload,
		"queue": rec.Queue, "status": rec.Status, "attempts": rec.Attempts, "max_attempts": rec.MaxAttempts,
		"run_at": rec.RunAt, "lease_until": rec.LeaseUntil, "created_at": rec.CreatedAt, "updated_at": rec.UpdatedAt,
		"last_error": rec.LastError}
}

func JobsEnqueue(w http.ResponseWriter, r *http.Request) {
	// PARSE -> AUTH -> SEMANTIC (identical ×3): decode raw FIRST (only malformed/413 fails here), THEN identity, THEN
	// the strict per-field validation — so an unauthenticated ill-typed body is 401, never a 422 that leaks the shape.
	raw, ok := core.DecodeJSON[json.RawMessage](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	var in struct {
		Kind         *string         `json:"kind"`
		Payload      map[string]any  `json:"payload"`
		Queue        *string         `json:"queue"`
		MaxAttempts  json.RawMessage `json:"max_attempts"`
		DelaySeconds json.RawMessage `json:"delay_seconds"`
	}
	if json.Unmarshal(raw, &in) != nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	if in.Kind == nil || !well_formed.IsWellFormed(*in.Kind) {
		core.WriteProblem(w, 422, "kind must be non-empty with no control characters")
		return
	}
	queue := "default"
	if in.Queue != nil {
		queue = *in.Queue
	}
	if !well_formed.IsWellFormed(queue) {
		core.WriteProblem(w, 422, "queue must be non-empty with no control characters")
		return
	}
	payload := map[string]any{}
	if in.Payload != nil {
		sp, msg := well_formed.SanitizeJSON("payload", in.Payload) // opaque + ×3-safe (surrogate -> U+FFFD, 2^53 ceiling)
		if msg != "" {
			core.WriteProblem(w, 422, msg)
			return
		}
		if m, mok := sp.(map[string]any); mok {
			payload = m
		}
	}
	maxAttempts := jobsDefaultMaxAttempts
	if len(in.MaxAttempts) > 0 && string(in.MaxAttempts) != "null" {
		v, vok := core.RequireIntRaw(in.MaxAttempts) // strict body int (rejects "5"/5.0/>2^53 ×3)
		if !vok || v < 1 || v > jobsMaxAttemptsCap {  // a client override is range-CHECKED (reject, not silently clamped)
			core.WriteProblem(w, 422, "max_attempts must be between 1 and 1000")
			return
		}
		maxAttempts = v
	}
	delay := 0
	if len(in.DelaySeconds) > 0 && string(in.DelaySeconds) != "null" {
		v, vok := core.RequireIntRaw(in.DelaySeconds)
		if !vok || v < 0 || v > jobsDelayCap {
			core.WriteProblem(w, 422, "delay_seconds must be between 0 and 31536000")
			return
		}
		delay = v
	}
	now := int(core.TestNow(r))
	jid := core.NextID(jobsSeq)
	rec := jobsRecord{Id: jid, Owner: owner, Kind: *in.Kind, Payload: payload, Queue: queue, Status: "queued",
		Attempts: 0, MaxAttempts: maxAttempts, RunAt: now + delay, LeaseUntil: 0, LeaseToken: "",
		CreatedAt: now, UpdatedAt: now, LastError: ""} // owner/id/status/run_at/lease_* server-set, never the body
	jobsKV.Set(strconv.Itoa(jid), rec)
	core.WriteJSON(w, 201, jobsPublic(rec))
}

func JobsClaim(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: service — the worker pool is a trusted SERVICE, not an end user; gated by core.RequireService.
	if _, ok := core.RequireService(w, r); !ok {
		return
	}
	now := int(core.TestNow(r))
	// unbounded-safe: + unscoped-read: the claim scans ALL jobs across owners to pick the lowest-id ready one — a
	// trusted SERVICE-pool operation (cross-owner infrastructure, NOT a per-user read); O(n) is the documented
	// store-swap-at-scale limit (a ready-index is the v2 upgrade). The sort is REQUIRED: All() is rowid order, not
	// stable ×3, and the manifest asserts the exact claimed job — pin id-ascending before picking.
	candidates := []jobsRecord{}
	for _, j := range jobsKV.All() {
		if jobsClaimable(j, now) {
			candidates = append(candidates, j)
		}
	}
	sort.Slice(candidates, func(i, k int) bool { return candidates[i].Id < candidates[k].Id })
	for _, cand := range candidates {
		var claimed *jobsRecord
		jobsKV.Do(strconv.Itoa(cand.Id), func(cur jobsRecord, exists bool) (jobsRecord, bool) {
			if !exists || !jobsClaimable(cur, now) {
				return cur, false // vanished, or another worker took it in the lock -> skip
			}
			if cur.Attempts >= cur.MaxAttempts {
				cur.Status = "dead"
				cur.LeaseToken = ""
				cur.LeaseUntil = 0
				cur.UpdatedAt = now
				return cur, true // dead-letter write, but NOT a claim (claimed stays nil) [I-RETRY-BOUNDED]
			}
			cur.Attempts++
			cur.Status = "running"
			cur.LeaseUntil = now + jobsVisibility
			cur.LeaseToken = digest.ScopedKey(jobsLeaseRoute, strconv.Itoa(cur.Id), strconv.Itoa(cur.Attempts))
			cur.UpdatedAt = now
			c := cur
			claimed = &c
			return cur, true
		})
		if claimed != nil {
			view := jobsPublic(*claimed)
			view["lease_token"] = claimed.LeaseToken // the worker needs the token to finish
			core.WriteJSON(w, 200, view)
			return
		}
	}
	w.WriteHeader(204) // nothing ready (the worker polls again)
}

// jobsFinish decodes {lease_token, error}, auth FIRST (service), then runs `mutate` under the single-key CAS — the
// shared body of complete + fail. mutate(cur) returns (next, outcome) where outcome is "ok"/"not_found"/"conflict".
func jobsFinish(w http.ResponseWriter, r *http.Request, mutate func(cur jobsRecord, token, errMsg string, now int) (jobsRecord, string)) {
	raw, ok := core.DecodeJSON[json.RawMessage](w, r)
	if !ok {
		return
	}
	// AUTH (RequireService) is done by the CALLER (JobsComplete/JobsFail) so the mutation-auth declaration + the
	// service call live in the SAME handler; jobsFinish does PARSE -> path -> SEMANTIC.
	id, idok := jobsPathID(r)
	if !idok {
		core.WriteProblem(w, 422, "invalid job id")
		return
	}
	var in struct {
		LeaseToken *string `json:"lease_token"`
		Error      *string `json:"error"`
	}
	if json.Unmarshal(raw, &in) != nil || in.LeaseToken == nil {
		core.WriteProblem(w, 422, "lease_token is required")
		return
	}
	errMsg := ""
	if in.Error != nil {
		errMsg = well_formed.MakeWellFormed(*in.Error)
	}
	now := int(core.TestNow(r))
	outcome := "not_found"
	var result jobsRecord
	jobsKV.Do(strconv.Itoa(id), func(cur jobsRecord, exists bool) (jobsRecord, bool) {
		if !exists {
			outcome = "not_found"
			return cur, false
		}
		if cur.Status != "running" || cur.LeaseToken != *in.LeaseToken {
			outcome = "conflict" // stale/wrong token or not running -> the stale worker is fenced [I-COMPLETE-AUTH]
			return cur, false
		}
		next, o := mutate(cur, *in.LeaseToken, errMsg, now)
		outcome = o
		result = next
		return next, true
	})
	switch outcome {
	case "not_found":
		core.WriteProblem(w, 404, "job not found")
	case "conflict":
		core.WriteProblem(w, 409, "job is not held under this lease")
	default:
		core.WriteJSON(w, 200, jobsPublic(result))
	}
}

// jobsPathID parses the {job_id} path segment as a STRICT integer -> (id, true), or (0, false) on a non-integer
// segment (the caller returns 422 — parity with python IntPath / node intParam, the ledger pattern).
func jobsPathID(r *http.Request) (int, bool) {
	id, err := strconv.Atoi(r.PathValue("job_id"))
	if err != nil {
		return 0, false
	}
	return id, true
}

func JobsComplete(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: service — only the trusted worker pool finishes a job, and only under the CURRENT lease token.
	if _, ok := core.RequireService(w, r); !ok {
		return
	}
	jobsFinish(w, r, func(cur jobsRecord, token, errMsg string, now int) (jobsRecord, string) {
		cur.Status = "done"
		cur.LeaseToken = ""
		cur.UpdatedAt = now
		return cur, "ok"
	})
}

func JobsFail(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: service — only the lease holder may fail a job; a failed job retries (backoff) or dead-letters.
	if _, ok := core.RequireService(w, r); !ok {
		return
	}
	jobsFinish(w, r, func(cur jobsRecord, token, errMsg string, now int) (jobsRecord, string) {
		cur.LeaseToken = ""
		cur.LastError = errMsg
		cur.UpdatedAt = now
		if cur.Attempts >= cur.MaxAttempts {
			cur.Status = "dead" // bound reached -> dead-letter [I-RETRY-BOUNDED]
			return cur, "ok"
		}
		cur.Status = "queued"
		cur.RunAt = now + jobsBackoff(cur.Attempts) // deterministic backoff [I-BACKOFF-DET]
		return cur, "ok"
	})
}

func JobsGet(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	id, idok := jobsPathID(r)
	if !idok {
		core.WriteProblem(w, 422, "invalid job id")
		return
	}
	rec, exists := jobsKV.Get(strconv.Itoa(id))
	if !exists || rec.Owner != owner { // cross-owner id -> 404 (existence never leaks)
		core.WriteProblem(w, 404, "job not found")
		return
	}
	core.WriteJSON(w, 200, jobsPublic(rec))
}

func JobsList(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	// SCOPED read: only the caller's jobs leave the store (filtered on the authenticated owner FIELD), id-sorted, then
	// a BOUNDED page; a stranger gets an empty page, never 403.
	mine := make([]jobsRecord, 0)
	for _, j := range jobsKV.All() {
		if j.Owner == owner {
			mine = append(mine, j)
		}
	}
	sort.Slice(mine, func(i, k int) bool { return mine[i].Id < mine[k].Id })
	views := make([]map[string]any, len(mine))
	for i, j := range mine {
		views[i] = jobsPublic(j)
	}
	q := r.URL.Query()
	page, next, valid := paginate.Paginate(views, q.Get("cursor"), q.Get("limit"))
	if !valid {
		core.WriteProblem(w, 422, "invalid cursor or limit")
		return
	}
	var nc any
	if next != "" {
		nc = next
	}
	core.WriteJSON(w, 200, map[string]any{"results": page, "next_cursor": nc})
}
