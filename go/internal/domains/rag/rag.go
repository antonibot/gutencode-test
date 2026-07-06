// Package rag — a retrieval pipeline (chunk -> embed -> rank -> cite) over an owner-scoped document corpus. The
// dangerous property is CITATION SOUNDNESS + GROUNDING: every query hit carries a source span {doc_id, start, end}
// that is an in-bounds window into the CURRENT stored document (0 <= start <= end <= len), the hit text is exactly
// that window's code points, and an exact-chunk-text query self-matches at cosine 1.0 — so an answer is always
// traceable to a real source chunk and a citation can never be fabricated or stale. Ranking is DETERMINISTIC (score
// desc, ties by chunk_id asc — identical ×3; scores are floats, NOT pinned) and a query returns at most k hits.
//
// IDENTITY + ISOLATION: both routes are body-only POST mutations. PARSE -> AUTH -> SEMANTIC, identical ×3: the body
// is decoded FIRST (DecodeJSON drains + 413/422), THEN RequireIdentity (no/invalid token -> 401), THEN field
// validation — so an unauthenticated otherwise-422 body is 401, never a 422 that leaks shape. A document is
// USER-SCOPED two ways: the store key is the composite <owner>\x1f<doc_id> (caller B can NEVER overwrite caller A's
// doc_id — the \x1f separator is a control char well_formed rejects, so it can't be forged), and the query scan
// filters on the authenticated owner FIELD (another owner's chunks are invisible). The owner is stamped from the
// token, never a body field, never surfaced in a hit. Store names/shapes match the python/node impls.
package rag

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"

	"app/internal/core"
	"app/internal/parts/chunking"
	"app/internal/parts/embedding"
	"app/internal/parts/env_int"
	"app/internal/parts/well_formed"
)

type ragChunk struct {
	Ordinal int   `json:"ordinal"`
	Start   int   `json:"start"`
	End     int   `json:"end"`
	Vector  []int `json:"vector"`
}

type ragDoc struct {
	Id     string     `json:"id"`
	Owner  string     `json:"owner"` // the authenticated indexer; PRIVATE — scopes the query scan, never returned
	Text   string     `json:"text"`
	Chunks []ragChunk `json:"chunks"`
}

type ragSource struct {
	DocId string `json:"doc_id"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

type ragHit struct {
	ChunkId string    `json:"chunk_id"`
	Text    string    `json:"text"`
	Score   float64   `json:"score"`
	Source  ragSource `json:"source"`
}

var ragDocs = core.NewKV[string, ragDoc]("rag_documents")

var (
	ragChunkSize    = env_int.EnvInt(os.Getenv("RAG_CHUNK_SIZE"), 400, 1)
	ragChunkOverlap = env_int.EnvInt(os.Getenv("RAG_CHUNK_OVERLAP"), 80, 0)
	ragMaxChunks    = env_int.EnvInt(os.Getenv("RAG_MAX_CHUNKS"), 1000, 1)
)

func init() {
	// fail-loud at startup: the stride size-overlap must be >= 1 (else no progress / an infinite chunk loop), ×3
	if !(ragChunkOverlap >= 0 && ragChunkOverlap < ragChunkSize) {
		panic("RAG_CHUNK_OVERLAP must satisfy 0 <= RAG_CHUNK_OVERLAP < RAG_CHUNK_SIZE")
	}
}

func RagIngest(w http.ResponseWriter, r *http.Request) {
	// PARSE first (413/422 + drain), then AUTH (401), then SEMANTIC field validation. ×3.
	in, ok := core.DecodeJSON[struct {
		DocId *string `json:"doc_id"`
		Text  *string `json:"text"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r) // authenticated mutation (no/invalid token -> 401)
	if !ok {
		return
	}
	if in.DocId == nil || !well_formed.IsWellFormed(*in.DocId) || in.Text == nil || *in.Text == "" {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	// contain the text BEFORE it is chunked / embedded / stored (lone surrogate -> U+FFFD; Go decode already substitutes)
	text := well_formed.MakeWellFormed(*in.Text)
	n := chunking.ChunkCount(text, ragChunkSize, ragChunkOverlap)
	if n > ragMaxChunks {
		core.WriteProblem(w, 422, "document too large") // soft-DoS ceiling -> 422
		return
	}
	chunks := make([]ragChunk, n)
	for i := 0; i < n; i++ {
		start := chunking.ChunkStart(ragChunkSize, ragChunkOverlap, i)
		end := chunking.ChunkEnd(text, ragChunkSize, ragChunkOverlap, i)
		chunks[i] = ragChunk{Ordinal: i, Start: start, End: end, Vector: embedding.Embed(chunking.ChunkSlice(text, start, end))}
	}
	// owner from the token, never client-set; the composite key partitions by owner so B can't overwrite A's doc_id.
	// a blind Set REPLACES the whole record (re-ingest = last-writer-wins; NOT a get-then-put RMW)
	ragDocs.Set(owner+"\x1f"+*in.DocId, ragDoc{Id: *in.DocId, Owner: owner, Text: text, Chunks: chunks})
	core.WriteJSON(w, 201, map[string]any{"doc_id": *in.DocId, "chunks": n})
}

func RagQuery(w http.ResponseWriter, r *http.Request) {
	raw, ok := core.DecodeJSON[json.RawMessage](w, r)
	if !ok {
		return
	}
	caller, ok := core.RequireIdentity(w, r) // AUTH (a POST is a mutation): no/invalid token -> 401, BEFORE validation
	if !ok {
		return
	}
	// SEMANTIC: k is decoded as RAW bytes then RequireIntRaw'd, so "100"/2.0/"many" are rejected HERE (after auth). Strict ×3.
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
		v, valid := core.RequireIntRaw(in.K) // STRICT: integer literal only (×3 with python StrictInt + node isStrictInt)
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
	qv := embedding.Embed(well_formed.MakeWellFormed(*in.Query)) // contain the query too — a lone-surrogate query embeds identically ×3
	hits := []ragHit{}
	// unbounded-safe: ranked top-k — at most k hits (k clamped), never the corpus; the full-scan is the documented
	// embeddings-index-swap-at-scale limit. read-scope: only the caller's own docs (owner FIELD == caller).
	for _, d := range ragDocs.All() {
		if d.Owner != caller { // read-scoping: another owner's chunks are invisible (cross-corpus leak wall)
			continue
		}
		for _, c := range d.Chunks {
			hits = append(hits, ragHit{ // owner/vector/ordinal stay internal — never in the hit
				ChunkId: d.Id + "#" + strconv.Itoa(c.Ordinal),
				Text:    chunking.ChunkSlice(d.Text, c.Start, c.End),
				Score:   embedding.Cosine(qv, c.Vector),
				Source:  ragSource{DocId: d.Id, Start: c.Start, End: c.End},
			})
		}
	}
	sort.Slice(hits, func(i, j int) bool { // DETERMINISTIC: score desc, ties by chunk_id asc
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].ChunkId < hits[j].ChunkId
	})
	if len(hits) > k {
		hits = hits[:k] // at most k hits, ever (clamp — no panic when k > len)
	}
	var top any
	if len(hits) > 0 {
		top = hits[0].ChunkId
	}
	core.WriteJSON(w, 200, map[string]any{"top": top, "hits": hits})
}
