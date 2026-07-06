package ai_memory

// Store model, namespaces, caps, and pure helpers for the ai_memory domain. The package overview + the HTTP handlers
// live in ai_memory.go. Store namespaces + the counter name match the python/node impls.

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"

	"app/internal/core"
	"app/internal/parts/env_int"
	"app/internal/parts/well_formed"
)

type amEntry struct {
	ID         int   `json:"id"`
	CreatedAt  int64 `json:"created_at"`
	ExpiresAt  int64 `json:"expires_at"` // 0 = never expires
	Importance int   `json:"importance"`
}

type amMemory struct {
	ID         int               `json:"id"`
	Owner      string            `json:"owner"`
	Scope      string            `json:"scope"`
	Content    string            `json:"content"`
	Tags       []string          `json:"tags"`
	Metadata   map[string]string `json:"metadata"`
	Importance int               `json:"importance"`
	CreatedAt  int64             `json:"created_at"`
	ExpiresAt  int64             `json:"expires_at"`
}

var (
	amOwner = core.NewKV[string, []string]("ai_memory_owner")  // "<owner>"           -> [scope]   (bounds the scope COUNT)
	amScope = core.NewKV[string, []amEntry]("ai_memory_scope") // "<owner>\x1f<scope>" -> [amEntry] (the liveness set)
	amMem   = core.NewKV[string, amMemory]("ai_memory_memory") // "<owner>\x1f<id>"    -> amMemory
)

const (
	amMaxTagBytes   = 128
	amMaxScopeBytes = 256
)

func amMaxScopes() int        { return env_int.EnvInt(os.Getenv("AI_MEMORY_MAX_SCOPES"), 100, 1) }
func amMaxMemories() int      { return env_int.EnvInt(os.Getenv("AI_MEMORY_MAX_MEMORIES"), 1000, 1) }
func amMaxTags() int          { return env_int.EnvInt(os.Getenv("AI_MEMORY_MAX_TAGS"), 20, 1) }
func amMaxContentBytes() int  { return env_int.EnvInt(os.Getenv("AI_MEMORY_MAX_CONTENT_BYTES"), 16384, 1) }
func amMaxMetadataBytes() int { return env_int.EnvInt(os.Getenv("AI_MEMORY_MAX_METADATA_BYTES"), 4096, 1) }

func amMKey(owner string, id int) string { return owner + "\x1f" + strconv.Itoa(id) }
func amSKey(owner, scope string) string  { return owner + "\x1f" + scope }

func amContains(scopes []string, s string) bool { // the per-owner scope list is the authoritative scope registry
	for _, x := range scopes {
		if x == s {
			return true
		}
	}
	return false
}

// amClean — reject a control char (< 0x20, so the \x1f key separator can't be forged) -> 422; then contain a lone
// surrogate (>= 0x20) so the key + echo are UTF-8-safe (identity in go). ("", false) on reject.
func amClean(w http.ResponseWriter, raw, what string) (string, bool) {
	if !well_formed.IsWellFormed(raw) {
		core.WriteProblem(w, 422, "the "+what+" must be non-empty with no control characters")
		return "", false
	}
	cleaned := well_formed.MakeWellFormed(raw)
	if len(cleaned) > amMaxScopeBytes {
		core.WriteProblem(w, 422, "the "+what+" is too large")
		return "", false
	}
	return cleaned, true
}

func amCleanTags(w http.ResponseWriter, tags *[]string) ([]string, bool) {
	out := []string{}
	if tags == nil {
		return out, true
	}
	if len(*tags) > amMaxTags() {
		core.WriteProblem(w, 422, "too many tags")
		return nil, false
	}
	for _, t := range *tags {
		if !well_formed.IsWellFormed(t) {
			core.WriteProblem(w, 422, "a tag must be non-empty with no control characters")
			return nil, false
		}
		cleaned := well_formed.MakeWellFormed(t) // CONTAIN before store
		if len(cleaned) > amMaxTagBytes {
			core.WriteProblem(w, 422, "a tag is too large")
			return nil, false
		}
		out = append(out, cleaned)
	}
	return out, true
}

func amCleanMetadata(w http.ResponseWriter, metadata *map[string]json.RawMessage) (map[string]string, bool) {
	out := map[string]string{}
	if metadata == nil {
		return out, true
	}
	for k, raw := range *metadata {
		var vp *string
		// a metadata VALUE must be a JSON STRING: a number/bool/object/array (Unmarshal error) OR an explicit null
		// (vp==nil) is 422 -> identical x3 (py Dict[str,StrictStr] / node typeof==='string' both reject these; a bare
		// map[string]string would coerce null to "").
		if err := json.Unmarshal(raw, &vp); err != nil || vp == nil {
			core.WriteProblem(w, 422, "metadata values must be strings")
			return nil, false
		}
		// contain the KEY and VALUE (a surrogate in a KEY is a stored 5xx poison a re-read 500s on).
		out[well_formed.MakeWellFormed(k)] = well_formed.MakeWellFormed(*vp)
	}
	// byte-cap = raw UTF-8 byte-SUM over the CONTAINED, COLLAPSED `out` (go's json decode already collapses distinct
	// surrogate keys to one U+FFFD entry) -> identical x3 with py/node summing their post-containment dict, and NOT a
	// json serialization (go Marshal HTML-escapes <>& + sorts keys, which would diverge).
	total := 0
	for k, v := range out {
		total += len(k) + len(v)
	}
	if total > amMaxMetadataBytes() {
		core.WriteProblem(w, 422, "metadata is too large")
		return nil, false
	}
	return out, true
}

// amExpiresAt — DERIVED, server-computed (a smuggled expires_at is discarded). 0 = never. Guard the overflow BEFORE the
// add (node loses precision AT 2^53 in the add) then clamp to 2^53-1 -> identical x3.
func amExpiresAt(now, ttl int64, ttlSet bool) int64 {
	if !ttlSet {
		return 0
	}
	if ttl > core.MaxSafeInt-now {
		return core.MaxSafeInt
	}
	return now + ttl
}

func amExpired(expiresAt, now int64) bool { return expiresAt != 0 && now > expiresAt } // AT the boundary is LIVE

// amEvictKey — the eviction order as a comparable tuple: EXPIRED-FIRST (live 0<1), then lowest importance, oldest,
// lowest id. All-integer => identical x3.
func amEvictKey(e amEntry, now int64) [4]int64 {
	live := int64(1)
	if amExpired(e.ExpiresAt, now) {
		live = 0
	}
	return [4]int64{live, int64(e.Importance), e.CreatedAt, int64(e.ID)}
}

func amLess(a, b [4]int64) bool {
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func amPublic(rec amMemory) map[string]any {
	out := map[string]any{"id": rec.ID, "scope": rec.Scope, "content": rec.Content, "tags": rec.Tags,
		"metadata": rec.Metadata, "importance": rec.Importance, "created_at": rec.CreatedAt}
	if rec.ExpiresAt != 0 {
		out["expires_at"] = rec.ExpiresAt
	}
	return out
}

// amFold — ASCII-only case fold (A-Z -> a-z); non-ASCII bytes (>= 0x80, never in 0x41-0x5A) stay BYTE-EXACT -> x3.
func amFold(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

// amReserveScope — reserve `scope` in the per-owner index; return true iff REJECTED (a NEW scope past MAX_SCOPES).
func amReserveScope(owner, scope string) bool {
	mx := amMaxScopes()
	rejected := false
	amOwner.Do(owner, func(cur []string, exists bool) ([]string, bool) {
		for _, s := range cur {
			if s == scope {
				return cur, false // already present
			}
		}
		if len(cur) >= mx {
			rejected = true
			return cur, false // reject past cap
		}
		return append(cur, scope), true
	})
	return rejected
}

// amAppendEvict — append `entry` to the per-scope index; if past MAX_MEMORIES evict the min amEvictKey. Returns the
// evicted id (0 = none).
func amAppendEvict(owner, scope string, entry amEntry, now int64) int {
	mx := amMaxMemories()
	evicted := 0
	amScope.Do(amSKey(owner, scope), func(cur []amEntry, exists bool) ([]amEntry, bool) {
		// unbounded-safe: bounded at MAX_MEMORIES by the importance-weighted, expired-first eviction below — deliberately NOT a positional drop-oldest tail-slice (age != staleness in a long-term store).
		next := append(cur, entry)
		if len(next) > mx {
			vi, vk := 0, amEvictKey(next[0], now)
			for i := 1; i < len(next); i++ {
				if k := amEvictKey(next[i], now); amLess(k, vk) {
					vi, vk = i, k
				}
			}
			evicted = next[vi].ID
			next = append(next[:vi], next[vi+1:]...)
		}
		return next, true
	})
	return evicted
}
