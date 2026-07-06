// Package vectorstore — embeddings + retrieval, the RAG backbone. The dangerous property is RETRIEVAL
// GROUNDING: an exact-text query MUST self-match as the top hit, the ordering is DETERMINISTIC (score desc,
// ties by id asc — identical ×3), and a query returns at most k hits. The offline embedder is the shared
// `embedding` part (an 8-bucket codepoint histogram of the lowercased text — pure integer counts, so every cosine
// is bit-identical across languages); the real embedder + vector DB swap in behind the same routes. Scores are
// floats and deliberately NOT pinned in the contract; it pins the TOP id. Vectors are durable.
//
// IDENTITY + READ-SCOPING + WRITE-PARTITION: both routes are body-only POST mutations. The precedence is PARSE ->
// AUTH -> SEMANTIC, identical ×3: the body is decoded FIRST (DecodeJSON drains the stream + emits 413/422 for
// oversize/malformed JSON — replying before the body is read aborts the connection mid-upload), THEN
// RequireIdentity runs (no/invalid token -> 401), THEN the strict field validation — so an unauthenticated caller
// with an otherwise-422 body gets 401, never a 422 that leaks the body shape. A document is USER-SCOPED two ways: at
// index the OWNER is stamped from the authenticated subject (never a body field) and the store key is the COMPOSITE
// <owner>\x1f<id> (caller B can NEVER overwrite caller A's id — the cross-owner WRITE wall; the \x1f separator is a
// control char IsWellFormed rejects, so the key can't be forged); at query the scan is filtered to ONLY the caller's
// own docs (a doc whose owner != caller is skipped, never appearing in hits — the tenancy not-yours==not-found
// pattern). The owner field is INTERNAL — never surfaced in the query response. Store names/shapes match python/node.
package vectorstore

import (
	"encoding/json"
	"net/http"
	"sort"

	"app/internal/core"
	"app/internal/parts/embedding"
	"app/internal/parts/well_formed"
)

type vectorstoreDoc struct {
	Id     string `json:"id"`
	Text   string `json:"text"`
	Vector []int  `json:"vector"`
	Owner  string `json:"owner"` // the authenticated indexer; PRIVATE — scopes the query scan, never returned
}

var vectorstoreDocs = core.NewKV[string, vectorstoreDoc]("vectorstore_docs")

func VectorstoreIndex(w http.ResponseWriter, r *http.Request) {
	// PARSE first (413/422 + drain), then AUTH (no/invalid token -> 401), then SEMANTIC field validation. ×3.
	in, ok := core.DecodeJSON[struct {
		Id   *string `json:"id"`
		Text *string `json:"text"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r) // authenticated mutation (no/invalid token -> 401)
	if !ok {
		return
	}
	if in.Id == nil || !well_formed.IsWellFormed(*in.Id) || in.Text == nil || *in.Text == "" {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	// owner derived from the token, never client-set; the COMPOSITE key partitions by owner so B can't overwrite A's id
	vectorstoreDocs.Set(owner+"\x1f"+*in.Id, vectorstoreDoc{Id: *in.Id, Text: *in.Text, Vector: embedding.Embed(*in.Text), Owner: owner})
	core.WriteJSON(w, 201, map[string]any{"id": *in.Id, "indexed": true})
}

func VectorstoreQuery(w http.ResponseWriter, r *http.Request) {
	// PARSE: accept ANY well-formed JSON (only malformed JSON / a 413 fails here); per-field checks are SEMANTIC and
	// run AFTER auth, exactly like python's pydantic — so an unauthenticated otherwise-422 body is 401, ×3.
	raw, ok := core.DecodeJSON[json.RawMessage](w, r)
	if !ok {
		return
	}
	caller, ok := core.RequireIdentity(w, r) // AUTH (a POST is a mutation): no/invalid token -> 401, BEFORE validation
	if !ok {
		return
	}
	// SEMANTIC: k is decoded as RAW bytes then RequireIntRaw'd, so "100"/2.0/"many" are rejected HERE (after auth) —
	// json.Number would have unquoted "100" -> 100 (diverging from python StrictInt + node isStrictInt). Strict ×3.
	var in struct {
		Query *string         `json:"query"`
		K     json.RawMessage `json:"k"`
	}
	if json.Unmarshal(raw, &in) != nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	k := 3
	if in.K != nil {
		v, valid := core.RequireIntRaw(in.K) // STRICT: integer literal only, rejects a quoted "100" (×3 with python StrictInt)
		if !valid || v < 1 || v > 50 {
			core.WriteProblem(w, 422, "k must be an integer between 1 and 50")
			return
		}
		k = v
	}
	if in.Query == nil || *in.Query == "" {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	qv := embedding.Embed(*in.Query)
	type hit struct {
		Id    string  `json:"id"`
		Text  string  `json:"text"`
		Score float64 `json:"score"`
	}
	hits := []hit{}
	// unbounded-safe: ranked top-k — returns at most k hits (k clamped), never the corpus; the full-scan is the documented embeddings-index-swap-at-scale limit.
	for _, d := range vectorstoreDocs.All() {
		if d.Owner != caller { // read-scoping: skip any doc not owned by the caller (not-yours == not-found)
			continue
		}
		hits = append(hits, hit{Id: d.Id, Text: d.Text, Score: embedding.Cosine(qv, d.Vector)}) // owner stays internal — not in the hit
	}
	sort.Slice(hits, func(i, j int) bool { // DETERMINISTIC: score desc, ties by id asc
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].Id < hits[j].Id
	})
	if len(hits) > k {
		hits = hits[:k] // at most k hits, ever
	}
	var top any
	if len(hits) > 0 {
		top = hits[0].Id
	}
	core.WriteJSON(w, 200, map[string]any{"top": top, "hits": hits})
}
