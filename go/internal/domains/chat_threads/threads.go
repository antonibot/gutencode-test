// Package chat_threads — a durable, owner-scoped AI-chat history store (package shape). Dangerous property:
// APPEND-ONLY ORDERED HISTORY + OWNER ISOLATION + BOUNDED BOTH WAYS — a message's position is a server-minted,
// per-thread strictly-monotonic seq (minted in ONE atomic read-modify-write on the thread row, so racing appends
// serialize to distinct consecutive seqs); history is immutable (no message edit/delete route); messages-per-
// thread AND threads-per-owner are both capped, reject-past-cap 422 (dropping a user's chat history is data loss,
// so history is never evicted); not-yours == 404 on every surface; the cascade delete frees the cap slot FIRST.
// Matches python/node; durable; see python/router.py for the full contract; the store model + helpers live in
// store.go, the transcript handlers in messages.go. Same names + DECISIONS in all three languages.
package chat_threads

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"

	"app/internal/core"
	"app/internal/parts/paginate"
)

func ChatThreadsCreate(w http.ResponseWriter, r *http.Request) {
	in, ok := core.DecodeJSON[struct {
		Title    *string                     `json:"title"`
		Metadata *map[string]json.RawMessage `json:"metadata"`
	}](w, r) // a smuggled owner/id/last_seq/created_at is simply never decoded (allowlist input)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r) // mutation-auth: identity — owner is the token subject, never a body field
	if !ok {
		return
	}
	title, ok := ctCleanTitle(w, in.Title)
	if !ok {
		return
	}
	metadata, ok := ctCleanMetadata(w, in.Metadata)
	if !ok {
		return
	}
	now := core.TestNow(r)
	id := core.NextID("chat_threads_id") // server-mint (globally unique); a cap-rejected create wastes it as a benign gap
	if ctReserveSlot(owner, id) {        // bound the thread COUNT first: index-FIRST also means a crash here leaves
		core.WriteProblem(w, 422, "too many threads") // a ghost cap slot, never an uncounted thread
		return
	}
	rec := ctThread{ID: id, Owner: owner, Title: title, Metadata: metadata, CreatedAt: now, UpdatedAt: now, LastSeq: 0}
	ctThreads.Set(ctTKey(owner, id), rec) // ONE write — the row is born consistent
	core.WriteJSON(w, 201, ctThreadPublic(rec))
}

func ChatThreadsList(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // read-scope: owner — the caller's own threads via the OWNER INDEX (never a store-wide scan)
	if !ok {
		return
	}
	tids, _ := ctIndex.Get(owner)
	rows := []ctThread{}
	for _, tid := range tids {
		if rec, exists := ctThreads.Get(ctTKey(owner, tid)); exists { // read-side check hides a create-tear ghost slot
			rows = append(rows, rec)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].UpdatedAt != rows[j].UpdatedAt {
			return rows[i].UpdatedAt > rows[j].UpdatedAt // newest activity first (an append bumps updated_at)
		}
		return rows[i].ID > rows[j].ID // tie: newest id first (all-integer -> identical across the languages)
	})
	views := make([]map[string]any, len(rows))
	for i, rec := range rows {
		views[i] = ctThreadPublic(rec)
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

func ChatThreadsGet(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // read-scope: owner — the composite key includes the owner (not-yours == 404)
	if !ok {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id")) // STRICT path int: rejects "1.0"/"abc"/control chars -> 422
	if err != nil {
		core.WriteProblem(w, 422, "invalid id")
		return
	}
	rec, exists := ctThreads.Get(ctTKey(owner, id))
	if !exists || !ctInIndex(owner, id) { // liveness-gated: a delete-tear ghost is 404, never resurrected
		core.WriteProblem(w, 404, "thread not found")
		return
	}
	core.WriteJSON(w, 200, ctThreadPublic(rec))
}

func ChatThreadsUpdate(w http.ResponseWriter, r *http.Request) {
	in, ok := core.DecodeJSON[struct {
		Title    *string                     `json:"title"`
		Metadata *map[string]json.RawMessage `json:"metadata"`
	}](w, r) // a smuggled owner/id/last_seq is simply never decoded
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r) // mutation-auth: identity — rename/retag ONE of the caller's threads
	if !ok {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid id")
		return
	}
	if in.Title == nil && in.Metadata == nil { // {} — and, by null parity, {"title": null} — is a no-op request: reject loudly
		core.WriteProblem(w, 422, "nothing to update: provide title and/or metadata")
		return
	}
	title, titleSet := "", false
	if in.Title != nil {
		title, ok = ctCleanTitle(w, in.Title)
		if !ok {
			return
		}
		titleSet = true
	}
	metadata, metaSet := map[string]string{}, false
	if in.Metadata != nil {
		metadata, ok = ctCleanMetadata(w, in.Metadata)
		if !ok {
			return
		}
		metaSet = true
	}
	now := core.TestNow(r)
	if !ctInIndex(owner, id) { // liveness gate: absent / not-yours / delete-tear ghost -> 404
		core.WriteProblem(w, 404, "thread not found")
		return
	}
	missing := false
	var updated ctThread
	ctThreads.Do(ctTKey(owner, id), func(cur ctThread, exists bool) (ctThread, bool) {
		if !exists {
			missing = true
			return cur, false
		}
		if titleSet {
			cur.Title = title
		}
		if metaSet {
			cur.Metadata = metadata
		}
		cur.UpdatedAt = now
		updated = cur
		return cur, true // RMW through the atomic seam — never get-then-put; messages are untouched
	})
	if missing {
		core.WriteProblem(w, 404, "thread not found")
		return
	}
	core.WriteJSON(w, 200, ctThreadPublic(updated))
}

func ChatThreadsDelete(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // mutation-auth: identity — the cascade delete, owner-index-FIRST
	if !ok {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid id")
		return
	}
	rec, exists := ctThreads.Get(ctTKey(owner, id))
	if !exists || !ctInIndex(owner, id) { // not-yours / absent / already-deleted -> 404 (re-delete is 404)
		core.WriteProblem(w, 404, "thread not found")
		return
	}
	// (a) free the cap slot + make the thread non-listable atomically (every read gates on the index)
	ctIndex.Do(owner, func(cur []int, exists bool) ([]int, bool) {
		next := []int{}
		for _, t := range cur {
			if t != id { // a filtered REBUILD into a fresh slice (shrinks — not a grow)
				next = append(next, t)
			}
		}
		return next, true
	})
	// (b) remove the row (get/append/messages now 404) — re-read first so the reap covers the freshest accepted seq
	if fresh, still := ctThreads.Get(ctTKey(owner, id)); still {
		rec = fresh
	}
	ctThreads.Delete(ctTKey(owner, id))
	// (c) reap the message rows (best-effort, behind the liveness gate — a crash here leaves unreachable orphans only)
	for seq := 1; seq <= rec.LastSeq; seq++ {
		ctMsgs.Delete(ctMKey(owner, id, seq))
	}
	w.WriteHeader(204)
}
