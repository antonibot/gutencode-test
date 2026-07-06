// Package ai_memory — a long-term, owner-scoped agent-memory store (package shape). Dangerous property:
// RETENTION-ENFORCED / BOUNDED — a memory past its retention (TTL-expired, cap-evicted, forgotten) is deterministically
// not retrievable; an owner's store can't grow unbounded (per-owner MAX_SCOPES x per-scope MAX_MEMORIES). Matches
// python/node; durable; see python/router.py for the full contract; the store model + helpers are in store.go. Same
// DECISIONS in all three languages.
package ai_memory

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"app/internal/core"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

func AiMemoryAdd(w http.ResponseWriter, r *http.Request) {
	in, ok := core.DecodeJSON[struct {
		Content    *string            `json:"content"` // the only text field; a smuggled owner/id/expires_at is ignored
		Scope      *string            `json:"scope"`
		Tags       *[]string          `json:"tags"`     // a numeric tag fails the []string decode -> 422 (x3)
		Metadata   *map[string]json.RawMessage `json:"metadata"` // each value must be a JSON string; number/bool/null/object -> 422 (x3)
		Importance *json.RawMessage   `json:"importance"`
		TTLSeconds *json.RawMessage   `json:"ttl_seconds"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r) // mutation-auth: identity — owner is the token subject, never a body field
	if !ok {
		return
	}
	if in.Content == nil || *in.Content == "" {
		core.WriteProblem(w, 422, "content is required")
		return
	}
	content := well_formed.MakeWellFormed(*in.Content) // CONTAIN before store; go len = UTF-8 bytes (== py encode / node byteLength)
	if len(content) > amMaxContentBytes() {
		core.WriteProblem(w, 422, "content is too large")
		return
	}
	scopeRaw := "default"
	if in.Scope != nil {
		scopeRaw = *in.Scope
	}
	scope, ok := amClean(w, scopeRaw, "scope")
	if !ok {
		return
	}
	tags, ok := amCleanTags(w, in.Tags)
	if !ok {
		return
	}
	metadata, ok := amCleanMetadata(w, in.Metadata)
	if !ok {
		return
	}
	importance := 0
	if in.Importance != nil {
		v, valid := core.RequireIntRaw(*in.Importance) // strict int in 2^53 (float/string/>2^53 -> 422)
		if !valid || v < 0 {
			core.WriteProblem(w, 422, "importance must be a non-negative integer")
			return
		}
		importance = v
	}
	ttl, ttlSet := int64(0), false
	if in.TTLSeconds != nil {
		v, valid := core.RequireIntRaw(*in.TTLSeconds)
		if !valid || v < 1 {
			core.WriteProblem(w, 422, "ttl_seconds must be a positive integer")
			return
		}
		ttl, ttlSet = int64(v), true
	}
	now := core.TestNow(r)
	expiresAt := amExpiresAt(now, ttl, ttlSet)
	id := core.NextID("ai_memory_id") // server-mint; a rejected add wastes it as a benign gap
	if amReserveScope(owner, scope) {
		core.WriteProblem(w, 422, "too many scopes")
		return
	}
	evicted := amAppendEvict(owner, scope, amEntry{ID: id, CreatedAt: now, ExpiresAt: expiresAt, Importance: importance}, now)
	// the row, written AFTER the Do seams (pure callbacks); a crash here leaves a benign skew the read-side check hides.
	amMem.Set(amMKey(owner, id), amMemory{ID: id, Owner: owner, Scope: scope, Content: content, Tags: tags,
		Metadata: metadata, Importance: importance, CreatedAt: now, ExpiresAt: expiresAt})
	if evicted != 0 {
		amMem.Delete(amMKey(owner, evicted))
	}
	out := map[string]any{"id": id, "scope": scope, "created_at": now}
	if expiresAt != 0 {
		out["expires_at"] = expiresAt
	}
	core.WriteJSON(w, 201, out)
}

func AiMemoryList(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	scopeRaw := q.Get("scope")
	if scopeRaw == "" {
		scopeRaw = "default"
	}
	scope, ok := amClean(w, scopeRaw, "scope")
	if !ok {
		return
	}
	now := core.TestNow(r)
	// read-scope: owner. The OWNER index is authoritative for scope existence: a scope not listed for this owner has NO
	// retrievable memories, so gating here keeps the retrievable set bounded even if a concurrent forget_scope||add
	// orphaned the scope index (the two-key race, closed on the RETRIEVABLE surface). [I-RACE-FORGET-SCOPE]
	entries := []amEntry{}
	if ownerScopes, _ := amOwner.Get(owner); amContains(ownerScopes, scope) {
		entries, _ = amScope.Get(amSKey(owner, scope))
	}
	rows := []amMemory{}
	for _, e := range entries {
		if amExpired(e.ExpiresAt, now) {
			continue
		}
		if rec, exists := amMem.Get(amMKey(owner, e.ID)); exists { // read-side check hides an index/row torn window
			rows = append(rows, rec)
		}
	}
	if tag := q.Get("tag"); tag != "" {
		needle := well_formed.MakeWellFormed(tag)
		kept := []amMemory{}
		for _, rec := range rows {
			for _, t := range rec.Tags {
				if t == needle {
					kept = append(kept, rec)
					break
				}
			}
		}
		rows = kept
	}
	if qq := q.Get("q"); qq != "" {
		needle := amFold(well_formed.MakeWellFormed(qq))
		kept := []amMemory{}
		for _, rec := range rows {
			if strings.Contains(amFold(rec.Content), needle) {
				kept = append(kept, rec)
			}
		}
		rows = kept
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].CreatedAt != rows[j].CreatedAt {
			return rows[i].CreatedAt > rows[j].CreatedAt // newest-first
		}
		return rows[i].ID < rows[j].ID // tie: id asc
	})
	views := make([]map[string]any, len(rows))
	for i, rec := range rows {
		views[i] = amPublic(rec)
	}
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

func AiMemoryGet(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id")) // STRICT path int: rejects "1.0"/"abc"/control chars -> 422
	if err != nil {
		core.WriteProblem(w, 422, "invalid id")
		return
	}
	// unbounded-safe: a single memory by key; OWNER-scoped (not-yours == 404). The index is LIVENESS-AUTHORITATIVE: an
	// expired OR evicted/torn (not-in-index) memory is 404, never resurrected.
	rec, exists := amMem.Get(amMKey(owner, id))
	if !exists {
		core.WriteProblem(w, 404, "memory not found")
		return
	}
	now := core.TestNow(r)
	// liveness = scope still in the OWNER index (race-safe) AND id in the scope index AND not expired. The owner-index
	// gate makes an orphan row (scope removed by a concurrent forget_scope) non-retrievable. [I-RACE-FORGET-SCOPE]
	ownerScopes, _ := amOwner.Get(owner)
	inIndex := false
	if amContains(ownerScopes, rec.Scope) {
		if idx, _ := amScope.Get(amSKey(owner, rec.Scope)); idx != nil {
			for _, e := range idx {
				if e.ID == id {
					inIndex = true
					break
				}
			}
		}
	}
	if amExpired(rec.ExpiresAt, now) || !inIndex {
		core.WriteProblem(w, 404, "memory not found")
		return
	}
	core.WriteJSON(w, 200, amPublic(rec))
}

func AiMemoryForget(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // mutation-auth: identity — forget ONE memory (not-yours == 404)
	if !ok {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid id")
		return
	}
	rec, exists := amMem.Get(amMKey(owner, id))
	if !exists {
		core.WriteProblem(w, 404, "memory not found") // idempotent re-delete / cross-owner -> 404
		return
	}
	amScope.Do(amSKey(owner, rec.Scope), func(cur []amEntry, exists bool) ([]amEntry, bool) {
		next := []amEntry{}
		for _, e := range cur {
			if e.ID != id { // a filtered REBUILD into a FRESH slice (shrinks — not append(cur,...))
				next = append(next, e)
			}
		}
		return next, true
	})
	amMem.Delete(amMKey(owner, id))
	w.WriteHeader(204)
}

func AiMemoryForgetScope(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // mutation-auth: identity — forget a WHOLE scope
	if !ok {
		return
	}
	scopeRaw := r.URL.Query().Get("scope")
	if scopeRaw == "" {
		core.WriteProblem(w, 422, "scope is required") // no silent wipe-all
		return
	}
	scope, ok := amClean(w, scopeRaw, "scope")
	if !ok {
		return
	}
	// OWNER-FIRST (B): remove the scope from the owner index atomically BEFORE reaping its index + rows. Reads gate on
	// the owner index, so the scope's memories are non-retrievable the instant this returns; a concurrent add that
	// re-reserves the scope re-counts it (a bounded counted-but-empty slot) instead of an uncounted-retrievable orphan.
	amOwner.Do(owner, func(cur []string, exists bool) ([]string, bool) {
		next := []string{}
		for _, s := range cur {
			if s != scope { // filtered REBUILD (frees the scope slot; shrinks — not append(cur,...))
				next = append(next, s)
			}
		}
		return next, true
	})
	entries, _ := amScope.Get(amSKey(owner, scope))
	for _, e := range entries {
		amMem.Delete(amMKey(owner, e.ID))
	}
	amScope.Delete(amSKey(owner, scope))
	w.WriteHeader(204)
}
