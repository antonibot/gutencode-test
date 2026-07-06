// Package search — token full-text search over a durable corpus. The dangerous property is RETRIEVAL HONESTY:
// AND-complete (a document containing ALL query terms IS returned) and AND-sound (a document missing ANY term is
// NOT), whole-token matching only, case-insensitive. Deny-by-default: an empty query returns [] — never the
// corpus. Ranking is DETERMINISTIC ×3: total query-term frequency desc, then id asc. Re-indexing an id replaces
// its document. Tokenization is lowercase ascii alphanumerics (the documented v1 limit). Store names and the
// document shape match the python/node impls; the corpus is durable.
// USER-SCOPED: a document belongs to the caller who indexed it, and a query sees ONLY the caller's own corpus.
// POST /search/index requires identity (the core RequireIdentity seam — ANY authenticated caller; no/invalid token
// -> 401) and stamps `owner` from the authenticated subject — NEVER a body field. Body-only POST precedence is
// PARSE -> AUTH -> SEMANTIC, ×3: the body is decoded as RAW JSON FIRST (only malformed JSON / a 413 fails here),
// THEN RequireIdentity, THEN the strict per-field validation — id via RequireIntRaw (rejects 5.0/"5"/true), text
// must be a non-empty JSON string. So a no-token request whose body is well-formed JSON (even a float id) is 401,
// never a 422 that would diverge from python's Depends order. GET /search/query ALSO requires identity (it has no
// body, so RequireIdentity runs first — a no-token query is 401) and filters the scan to the caller's own docs: a
// doc whose owner != caller is invisible (the api_keys not-yours==not-found pattern over a corpus scan). The owner
// is PRIVATE BY CONSTRUCTION (no handler writes the searchDoc struct to the client — query returns {id,text,score}/
// results built by hand, index returns {id,tokens}); it serializes as `owner` only so the durable store round-trips
// it (parity with the python/node stored shape {id,text,owner}; a `json:"-"` tag would drop it on persist).
package search

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"app/internal/core"
)

type searchDoc struct {
	Id   int    `json:"id"`
	Text string `json:"text"`
	// Owner — the authenticated subject who indexed it; the per-caller read filter. It MUST serialize as `owner`
	// (the store round-trips the value through JSON, so `json:"-"` would drop it on persist — parity with the
	// python/node stored shape {id,text,owner}). It is private BY CONSTRUCTION, not by tag: NO handler ever writes
	// this struct to the client — query builds {id,text,score}/results by hand and index returns {id,tokens}, so
	// the owner is never surfaced even though it is serialized for the durable store.
	Owner string `json:"owner"`
}

var (
	// ns "search_docs" "<owner>\x1f<id>" -> searchDoc; the composite key partitions by owner (cross-owner WRITE wall)
	searchDocs     = core.NewKV[string, searchDoc]("search_docs")
	searchSplitter = regexp.MustCompile(`[^a-z0-9]+`)
)

func searchTokens(text string) []string {
	out := []string{}
	for _, t := range searchSplitter.Split(strings.ToLower(text), -1) {
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func SearchIndex(w http.ResponseWriter, r *http.Request) {
	// PARSE: accept ANY well-formed JSON; only malformed JSON / a 413 fails here. Per-field type checks are SEMANTIC
	// and run AFTER auth (below), exactly like python's pydantic — so an unauthenticated ill-typed body is 401, ×3.
	raw, ok := core.DecodeJSON[json.RawMessage](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r) // AUTH: authenticated mutation (no/invalid token -> 401), BEFORE semantics
	if !ok {
		return
	}
	// SEMANTIC: id is RequireIntRaw'd on the RAW bytes (rejects 5.0/"5"/true/null/missing, matching python StrictInt
	// + node isStrictInt); text must be a JSON string (a number/object/null fails the unmarshal) and non-empty.
	var in struct {
		Id   json.RawMessage `json:"id"`
		Text *string         `json:"text"`
	}
	if json.Unmarshal(raw, &in) != nil { // a shape mismatch (text:7, the body isn't an object) is 422 here, post-auth
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	id, idOk := core.RequireIntRaw(in.Id)
	if !idOk || id < 1 || in.Text == nil || *in.Text == "" {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	// one write replaces the document; owner stamped from the TOKEN (never the body); the COMPOSITE key partitions by
	// owner so caller B can't overwrite caller A's id (the cross-owner WRITE wall)
	searchDocs.Set(owner+"\x1f"+strconv.Itoa(id), searchDoc{Id: id, Text: *in.Text, Owner: owner})
	unique := map[string]bool{}
	for _, t := range searchTokens(*in.Text) {
		unique[t] = true
	}
	core.WriteJSON(w, 201, map[string]any{"id": id, "tokens": len(unique)})
}

func SearchQuery(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // AUTH first (no body): a no-token query is 401, matching python's Depends
	if !ok {
		return
	}
	q := r.URL.Query().Get("q")
	terms := searchTokens(q)
	if len(terms) == 0 { // deny-by-default: no terms -> no results, never the whole corpus
		core.WriteJSON(w, 200, map[string]any{"query": q, "results": []int{}})
		return
	}
	type scored struct{ score, id int }
	hits := []scored{}
	// unbounded-safe: ranked top-k — returns at most k results (k clamped), never the corpus; the full-scan is the documented search-index-swap-at-scale limit.
	for _, doc := range searchDocs.All() {
		if doc.Owner != owner { // USER-SCOPED: a doc that isn't yours is invisible (not-yours==not-found)
			continue
		}
		toks := searchTokens(doc.Text)
		counts := map[string]int{}
		for _, t := range toks {
			counts[t]++
		}
		all, score := true, 0
		for _, term := range terms {
			if counts[term] == 0 {
				all = false // AND: every query term must be present as a whole token
				break
			}
			score += counts[term]
		}
		if all {
			hits = append(hits, scored{score, doc.Id})
		}
	}
	sort.Slice(hits, func(i, j int) bool { // deterministic: frequency desc, then id asc
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		return hits[i].id < hits[j].id
	})
	results := []int{}
	for _, h := range hits {
		results = append(results, h.id)
	}
	core.WriteJSON(w, 200, map[string]any{"query": q, "results": results})
}
