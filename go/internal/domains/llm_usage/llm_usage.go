// Package llm_usage — a per-call LLM token + cost METER. Matches python/node; durable. Dangerous property = COST
// INTEGRITY: (1) COST SERVER-DERIVED, never client-supplied — the event carries TOKENS only (no cost field); cost is
// computed from a fixed code-reviewed PRICE TABLE; unknown (provider,model) or an unpriced dimension is 422,
// deny-by-default (never $0/free, never under-count). (2) NO DOUBLE-COUNT — idempotent on (owner, identifier) via the
// scoped_key + claim_once seam; a same-identifier retry with ANY different cost-input is 409 (the provider-inclusive
// body-hash, computed over the request AS SENT — an omitted `at` hashes as a sentinel, never the server-minted
// default, so a byte-identical retry replays 201 even across a wall-clock second tick). (3) APPEND-ONLY (no
// update/delete route). (4) AGGREGATE DERIVED on read (GET /summary). (5) OWNER-SCOPED
// (owner = require_identity, not a client field). (6) INTEGER-EXACT: rate is nanodollars-per-1000-tokens (real
// per-token rates are sub-nanodollar); cost = tokens × rate / 1000, the intermediate ×3-safe; a per-dimension token
// ceiling rejects an absurd count. Every route require_identity.
package llm_usage

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strconv"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/env_int"
	"app/internal/parts/idempotent_claim"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

const llmRoute = "POST /llm_usage/events" // the dedup-slot discriminator (per-operation, owner-scoped slot)

func llmReplay() int64    { return int64(env_int.EnvInt(os.Getenv("LLM_USAGE_REPLAY_WINDOW"), 300, 1)) }
func llmMaxTokens() int64 { return int64(env_int.EnvInt(os.Getenv("LLM_USAGE_MAX_TOKENS"), 10000000, 1)) }

// THE PRICE TABLE (policy, code-reviewed) — (provider, model) -> {dimension: nanodollars-per-1000-tokens}. Integer
// rate (real per-token rates are sub-nanodollar); per-1000 keeps tokens×rate within the ×3-safe range. Same data +
// same cost ×3 (the manifest cost cases pin it). NEVER empty.
var llmPrices = map[[2]string]map[string]int64{
	{"openai", "gpt-4o"}:               {"input": 2500000, "output": 10000000, "cache_read": 1250000},
	{"openai", "gpt-4o-mini"}:          {"input": 150000, "output": 600000, "cache_read": 75000},
	{"anthropic", "claude-3-5-sonnet"}: {"input": 3000000, "output": 15000000, "cache_read": 300000, "cache_write": 3750000},
	{"anthropic", "claude-sonnet-4-6"}: {"input": 3000000, "output": 15000000, "cache_read": 300000, "cache_write": 3750000},
	{"anthropic", "claude-3-5-haiku"}:  {"input": 800000, "output": 4000000, "cache_read": 80000, "cache_write": 1000000},
	// the offline provider's row: exists so the metering wire is provable offline (armed via AI_USAGE_METER_FAKE);
	// every rate 0 — a priced-at-zero provider is EXPLICIT policy, not a silent $0 (an unknown model still 422s).
	{"fake", "fake"}: {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "reasoning": 0},
}

// the event token field -> the price dimension (FIXED order -> a deterministic ×3 body-hash)
var llmDims = []struct{ field, dim string }{
	{"input_tokens", "input"}, {"output_tokens", "output"}, {"cache_read_input_tokens", "cache_read"},
	{"cache_creation_input_tokens", "cache_write"}, {"reasoning_tokens", "reasoning"},
}

type llmEvent struct {
	Id                       int    `json:"id"`
	Owner                    string `json:"owner"`
	Identifier               string `json:"identifier"`
	Provider                 string `json:"provider"`
	Model                    string `json:"model"`
	InputTokens              int64  `json:"input_tokens"`
	OutputTokens             int64  `json:"output_tokens"`
	CacheReadInputTokens     int64  `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int64  `json:"cache_creation_input_tokens"`
	ReasoningTokens          int64  `json:"reasoning_tokens"`
	At                       int64  `json:"at"`
	CostNanodollars          int64  `json:"cost_nanodollars"`
	BodyHash                 string `json:"body_hash"`
}

var llmEvents = core.NewKV[string, llmEvent]("llm_usage_events")

func absI64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// llmTok parses an OPTIONAL token field: absent -> 0; else a STRICT int (RequireIntRaw bounds ±2^53 ×3) that is >= 0.
func llmTok(w http.ResponseWriter, raw json.RawMessage) (int64, bool) {
	if raw == nil {
		return 0, true
	}
	v, ok := core.RequireIntRaw(raw)
	if !ok || v < 0 {
		core.WriteProblem(w, 422, "invalid body")
		return 0, false
	}
	return int64(v), true
}

func llmTokenForDim(e llmEvent, dim string) int64 {
	switch dim {
	case "input":
		return e.InputTokens
	case "output":
		return e.OutputTokens
	case "cache_read":
		return e.CacheReadInputTokens
	case "cache_write":
		return e.CacheCreationInputTokens
	case "reasoning":
		return e.ReasoningTokens
	}
	return 0
}

// llmDeriveCost: cost_nanodollars = Σ_dim tokens × rate / 1000 (integer-EXACT). Unknown (provider,model) or an
// unpriced dimension with tokens>0 -> ("", false) for a 422. A per-dimension ceiling rejects an absurd count.
func llmDeriveCost(e llmEvent, maxTok int64) (int64, string, bool) {
	rates, ok := llmPrices[[2]string{e.Provider, e.Model}]
	if !ok {
		return 0, "no price for this provider/model", false
	}
	var cost int64
	for _, d := range llmDims {
		n := llmTokenForDim(e, d.dim)
		if n == 0 {
			continue
		}
		if n > maxTok {
			return 0, d.field + " exceeds the per-call ceiling", false
		}
		rate, has := rates[d.dim]
		if !has {
			return 0, "no price for the " + d.dim + " dimension of this model", false
		}
		cost += n * rate / 1000 // per-dim floor < 1 nanodollar; intermediate n*rate is ×3-safe (per-1000)
	}
	return cost, "", true
}

func llmBodyHash(e llmEvent, atSent any) string {
	// over ALL cost-determining fields AS THE CLIENT SENT THEM — provider + model + every token dim + at + cost
	// (provider IS in the hash). atSent is the CLIENT's at (int64), or the "-" sentinel when omitted (an int never
	// renders as a bare "-") — the server-minted default must NEVER enter the hash: it is wall-clock-quantized, so two
	// byte-identical no-`at` retries straddling a second boundary would fingerprint differently and 409 instead of
	// replaying a legitimate client retry. Matches python/node exactly.
	return digest.DigestHex("provider", e.Provider, "model", e.Model, "in", e.InputTokens, "out", e.OutputTokens,
		"cr", e.CacheReadInputTokens, "cw", e.CacheCreationInputTokens, "re", e.ReasoningTokens, "at", atSent, "cost", e.CostNanodollars)
}

func llmPublic(e llmEvent) map[string]any {
	return map[string]any{"id": e.Id, "identifier": e.Identifier, "provider": e.Provider, "model": e.Model,
		"input_tokens": e.InputTokens, "output_tokens": e.OutputTokens, "cache_read_input_tokens": e.CacheReadInputTokens,
		"cache_creation_input_tokens": e.CacheCreationInputTokens, "reasoning_tokens": e.ReasoningTokens,
		"at": e.At, "cost_nanodollars": e.CostNanodollars}
}

func LlmUsageRecord(w http.ResponseWriter, r *http.Request) {
	raw, ok := core.DecodeJSON[json.RawMessage](w, r) // PARSE first (413/422 + drain), then AUTH, then SEMANTIC — ×3
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	var in struct {
		Identifier *string         `json:"identifier"`
		Provider   *string         `json:"provider"`
		Model      *string         `json:"model"`
		Input      json.RawMessage `json:"input_tokens"`
		Output     json.RawMessage `json:"output_tokens"`
		CacheRead  json.RawMessage `json:"cache_read_input_tokens"`
		CacheCrea  json.RawMessage `json:"cache_creation_input_tokens"`
		Reasoning  json.RawMessage `json:"reasoning_tokens"`
		At         json.RawMessage `json:"at"`
	}
	if json.Unmarshal(raw, &in) != nil || in.Identifier == nil || !well_formed.IsWellFormed(*in.Identifier) ||
		in.Provider == nil || !well_formed.IsWellFormed(*in.Provider) || in.Model == nil || !well_formed.IsWellFormed(*in.Model) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	e := llmEvent{Owner: owner, Identifier: *in.Identifier, Provider: *in.Provider, Model: *in.Model}
	var ok1, ok2, ok3, ok4, ok5 bool
	if e.InputTokens, ok1 = llmTok(w, in.Input); !ok1 {
		return
	}
	if e.OutputTokens, ok2 = llmTok(w, in.Output); !ok2 {
		return
	}
	if e.CacheReadInputTokens, ok3 = llmTok(w, in.CacheRead); !ok3 {
		return
	}
	if e.CacheCreationInputTokens, ok4 = llmTok(w, in.CacheCrea); !ok4 {
		return
	}
	if e.ReasoningTokens, ok5 = llmTok(w, in.Reasoning); !ok5 {
		return
	}
	now := core.TestNow(r)
	e.At = now                 // the STORED/returned time; the hash gets `at` AS SENT
	var atSent any = "-"       // the client omitted `at` — the sentinel, never the server-minted default
	if in.At != nil {
		v, vok := core.RequireIntRaw(in.At)
		if !vok {
			core.WriteProblem(w, 422, "invalid body")
			return
		}
		e.At = int64(v)
		atSent = int64(v)
	}
	if absI64(e.At-now) > llmReplay() { // validate `at` BEFORE the body-hash (anti-backdate)
		core.WriteProblem(w, 422, "at is outside the replay window")
		return
	}
	prior, status, msg := llmCommit(e, atSent) // the shared recording core (derive cost, fingerprint, claim exactly-once)
	if status != 201 {
		core.WriteProblem(w, status, msg)
		return
	}
	core.WriteJSON(w, 201, llmPublic(prior))
}

// llmCommit — THE transport-free recording CORE shared by the HTTP route AND the in-process usage sink (the ONE
// writer of llm_usage_events; one namespace writer, one price authority). Derives the SERVER cost (422 on unknown/
// unpriced), fingerprints the body AS SENT, and claims the (owner, identifier) slot exactly-once. Returns (settled
// record, status, detail): 201 = recorded/replayed · 409/422 = refused (the route renders it as problem+json, the
// sink returns it as a contained error). `atSent` is the client's at or the "-" sentinel; `e.At` is the stored time.
func llmCommit(e llmEvent, atSent any) (llmEvent, int, string) {
	cost, msg, cok := llmDeriveCost(e, llmMaxTokens()) // SERVER-derived (anti-self-billing); 422 on unknown/unpriced
	if !cok {
		return e, 422, msg
	}
	e.CostNanodollars = cost
	e.BodyHash = llmBodyHash(e, atSent)
	scoped := digest.ScopedKey(llmRoute, e.Owner, e.Identifier) // owner-scoped dedup slot (private to the caller)
	prior, settled := llmEvents.Get(scoped)
	if !settled {
		e.Id = core.NextID("llm_usage_event") // mint BEFORE the claim (a race loser's id is a harmless gap)
		prior = idempotent_claim.ClaimOnce(llmEvents, scoped, e)
	}
	if prior.Owner != e.Owner { // defense-in-depth (the scoped slot already isolates callers)
		return prior, 409, "identifier is not owned by this caller"
	}
	if prior.BodyHash != e.BodyHash { // same identifier, different cost-inputs -> 409
		return prior, 409, "identifier reused with a different body"
	}
	return prior, 201, ""
}

// llmRecordEvent — THE usage-sink recorder registered into the core hook (the SAME writer as the HTTP route). A
// producer calls core.UsageRecord(owner, call, now); core forwards it here. The sink omits the client `at` (the "-"
// sentinel), so a byte-identical retry replays across a wall-clock tick. A refused event (unpriced/409) returns an
// error, so the core seam CONTAINS + logs it and the producer's run continues (a broken meter never breaks a chat).
func llmRecordEvent(owner string, call core.UsageCall, now int64) error {
	e := llmEvent{Owner: owner, Identifier: call.Identifier, Provider: call.Provider, Model: call.Model,
		InputTokens: call.InputTokens, OutputTokens: call.OutputTokens, CacheReadInputTokens: call.CacheReadInputTokens,
		CacheCreationInputTokens: call.CacheCreationInputTokens, ReasoningTokens: call.ReasoningTokens, At: now}
	if _, status, msg := llmCommit(e, "-"); status != 201 {
		return errors.New(msg)
	}
	return nil
}

// self-register the recorder into the core usage hook (guaranteed pre-serve — the app imports every domain package
// to mount routes before the server listens), so no request can race an unregistered sink.
func init() { core.RegisterUsageSink(llmRecordEvent) }

type llmOptTS struct {
	set bool
	v   int64
}

func llmParseTS(s string) (llmOptTS, bool) {
	if s == "" {
		return llmOptTS{}, true
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > core.MaxSafeInt || n < -core.MaxSafeInt { // strict integer epoch, bounded ×3
		return llmOptTS{}, false
	}
	return llmOptTS{true, n}, true
}

type llmGroup struct {
	Provider, Model           string
	In, Out, Cr, Cw, Re, Cost int64
}

func LlmUsageSummary(w http.ResponseWriter, r *http.Request) {
	// unbounded-safe: scalar aggregate — sums the OWNER's events into per-(provider,model) totals + a grand total; no
	// raw collection returned (the O(n) scan is the documented store-swap-at-scale limit). OWNER-ISOLATION enforced.
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	frm, fok := llmParseTS(q.Get("from"))
	to, tok := llmParseTS(q.Get("to"))
	if !fok || !tok {
		core.WriteProblem(w, 422, "from/to must be an integer epoch")
		return
	}
	model := q.Get("model")
	groups := map[[2]string]*llmGroup{}
	var total llmGroup
	for _, rec := range llmEvents.All() {
		if rec.Owner != owner {
			continue
		}
		if (frm.set && rec.At < frm.v) || (to.set && rec.At > to.v) || (model != "" && rec.Model != model) {
			continue
		}
		key := [2]string{rec.Provider, rec.Model}
		g := groups[key]
		if g == nil {
			g = &llmGroup{Provider: rec.Provider, Model: rec.Model}
			groups[key] = g
		}
		g.In += rec.InputTokens
		g.Out += rec.OutputTokens
		g.Cr += rec.CacheReadInputTokens
		g.Cw += rec.CacheCreationInputTokens
		g.Re += rec.ReasoningTokens
		g.Cost += rec.CostNanodollars
		total.In += rec.InputTokens
		total.Out += rec.OutputTokens
		total.Cr += rec.CacheReadInputTokens
		total.Cw += rec.CacheCreationInputTokens
		total.Re += rec.ReasoningTokens
		total.Cost += rec.CostNanodollars
	}
	keys := make([][2]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	byModel := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		byModel = append(byModel, llmGroupJSON(groups[k]))
	}
	out := llmGroupJSON(&total)
	delete(out, "provider")
	delete(out, "model")
	out["by_model"] = byModel
	core.WriteJSON(w, 200, out)
}

func llmGroupJSON(g *llmGroup) map[string]any {
	return map[string]any{"provider": g.Provider, "model": g.Model, "input_tokens": g.In, "output_tokens": g.Out,
		"cache_read_input_tokens": g.Cr, "cache_creation_input_tokens": g.Cw, "reasoning_tokens": g.Re, "cost_nanodollars": g.Cost}
}

func LlmUsageEvents(w http.ResponseWriter, r *http.Request) {
	// OWNER-scoped audit trail, BOUNDED through paginate. NEVER the body_hash; ordered by id.
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	mine := []map[string]any{}
	recs := []llmEvent{}
	for _, rec := range llmEvents.All() {
		if rec.Owner == owner {
			recs = append(recs, rec)
		}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Id < recs[j].Id })
	for _, rec := range recs {
		mine = append(mine, llmPublic(rec))
	}
	q := r.URL.Query()
	page, next, valid := paginate.Paginate(mine, q.Get("cursor"), q.Get("limit"))
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
