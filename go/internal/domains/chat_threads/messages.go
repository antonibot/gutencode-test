package chat_threads

// The append-only transcript: POST appends one immutable turn (the seq is minted inside ONE atomic
// read-modify-write on the thread row, so racing appends serialize and a smuggled body seq is never read); GET
// reads the turns back in replay order (seq ASC by construction — a direct walk of the per-seq slots, no
// store-wide scan). The thread lifecycle handlers live in threads.go; the store model + helpers in store.go.

import (
	"encoding/json"
	"net/http"
	"strconv"

	"app/internal/core"
	"app/internal/parts/paginate"
)

func ChatThreadsAppend(w http.ResponseWriter, r *http.Request) {
	in, ok := core.DecodeJSON[struct {
		Role     *string                     `json:"role"`
		Content  *string                     `json:"content"`
		Metadata *map[string]json.RawMessage `json:"metadata"`
	}](w, r) // a smuggled seq/owner/thread_id/created_at is simply never decoded (allowlist input) [derived: seq]
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r) // mutation-auth: identity — append one immutable turn to the caller's OWN thread
	if !ok {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid id")
		return
	}
	if in.Role == nil || !ctRole(*in.Role) { // the CLOSED role set, exact lowercase ("User" -> 422)
		core.WriteProblem(w, 422, "role must be one of user|assistant|system|tool")
		return
	}
	content, ok := ctCleanContent(w, in.Content)
	if !ok {
		return
	}
	metadata, ok := ctCleanMetadata(w, in.Metadata)
	if !ok {
		return
	}
	now := core.TestNow(r)
	if !ctInIndex(owner, id) { // liveness gate: absent / not-yours / deleted -> 404
		core.WriteProblem(w, 404, "thread not found")
		return
	}
	missing, full, seq := false, false, 0
	ctThreads.Do(ctTKey(owner, id), func(cur ctThread, exists bool) (ctThread, bool) {
		if !exists {
			missing = true
			return cur, false
		}
		if cur.LastSeq >= ctMaxMessages() {
			full = true
			return cur, false // reject past the cap — history is never evicted
		}
		cur.LastSeq++       // the seq mint: bounded by the cap, and every increment costs an accepted request,
		cur.UpdatedAt = now // so it can never approach the integer ceiling; the bump lifts the thread in the list
		seq = cur.LastSeq
		return cur, true
	})
	if missing {
		core.WriteProblem(w, 404, "thread not found")
		return
	}
	if full {
		core.WriteProblem(w, 422, "thread is full")
		return
	}
	rec := ctMessage{Seq: seq, ThreadID: id, Owner: owner, Role: *in.Role, Content: content, Metadata: metadata, CreatedAt: now}
	ctMsgs.Set(ctMKey(owner, id, seq), rec) // the slot is written ONCE, after the mint (the Do callback stays pure);
	core.WriteJSON(w, 201, ctMessagePublic(rec)) // a crash between mint and write is a seq GAP — never a reorder
}

func ChatThreadsMessages(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // read-scope: owner — the transcript in replay order (seq ASC by construction)
	if !ok {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid id")
		return
	}
	rec, exists := ctThreads.Get(ctTKey(owner, id))
	if !exists || !ctInIndex(owner, id) { // liveness-gated: absent / not-yours / deleted -> 404 (orphans unreachable)
		core.WriteProblem(w, 404, "thread not found")
		return
	}
	views := []map[string]any{}
	for seq := 1; seq <= rec.LastSeq; seq++ { // a direct walk of the per-seq slots — no store-wide scan, so
		if msg, hit := ctMsgs.Get(ctMKey(owner, id, seq)); hit { // cross-owner isolation holds by key construction
			views = append(views, ctMessagePublic(msg)) // a mint-tear gap is skipped (order intact, count honest)
		}
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
