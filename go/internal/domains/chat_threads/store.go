package chat_threads

// Store model, namespaces, caps, and pure helpers for the chat_threads domain. The HTTP handlers live in
// threads.go (the thread lifecycle) and messages.go (the append-only transcript). Store namespaces + the counter
// name match the python/node impls.

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"unicode/utf8"

	"app/internal/core"
	"app/internal/parts/env_int"
	"app/internal/parts/well_formed"
)

type ctThread struct {
	ID        int               `json:"id"`
	Owner     string            `json:"owner"`
	Title     string            `json:"title"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt int64             `json:"created_at"`
	UpdatedAt int64             `json:"updated_at"`
	LastSeq   int               `json:"last_seq"`
}

type ctMessage struct {
	Seq       int               `json:"seq"`
	ThreadID  int               `json:"thread_id"`
	Owner     string            `json:"owner"`
	Role      string            `json:"role"`
	Content   string            `json:"content"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt int64             `json:"created_at"`
}

var (
	ctIndex   = core.NewKV[string, []int]("chat_threads_index")       // "<owner>"                  -> [thread id] (liveness + the thread-COUNT bound)
	ctThreads = core.NewKV[string, ctThread]("chat_threads_thread")   // "<owner>\x1f<id>"          -> ctThread
	ctMsgs    = core.NewKV[string, ctMessage]("chat_threads_message") // "<owner>\x1f<id>\x1f<seq>" -> ctMessage (one immutable slot per seq)
)

const (
	ctMaxTitleBytes     = 256 // a title is a display line (a fixed structural bound)
	ctMaxMetaPairs      = 16  // metadata bounds: the field's settled numbers (16 pairs, 64-char keys, 512-char values)
	ctMaxMetaKeyChars   = 64
	ctMaxMetaValueChars = 512
)

func ctMaxThreads() int      { return env_int.EnvInt(os.Getenv("CHAT_THREADS_MAX_THREADS"), 500, 1) }
func ctMaxMessages() int     { return env_int.EnvInt(os.Getenv("CHAT_THREADS_MAX_MESSAGES"), 1000, 1) }
func ctMaxContentBytes() int { return env_int.EnvInt(os.Getenv("CHAT_THREADS_MAX_CONTENT_BYTES"), 16384, 1) }

func ctTKey(owner string, id int) string { return owner + "\x1f" + strconv.Itoa(id) } // owner-partitioned rows (B can't reach A's id)
func ctMKey(owner string, id, seq int) string {
	return owner + "\x1f" + strconv.Itoa(id) + "\x1f" + strconv.Itoa(seq)
}

// ctRole — the CLOSED role set, exact lowercase ("User" is 422; a case-fold would drift across the languages).
func ctRole(role string) bool {
	return role == "user" || role == "assistant" || role == "system" || role == "tool"
}

// ctInIndex — the per-owner thread index is LIVENESS-AUTHORITATIVE: a thread is live only while its id is IN the
// index; every per-thread surface gates on it, so a delete's crash residue is never resurrected.
func ctInIndex(owner string, id int) bool {
	tids, _ := ctIndex.Get(owner)
	for _, t := range tids {
		if t == id {
			return true
		}
	}
	return false
}

// ctCleanTitle — nil/absent -> "" (an untitled thread; null parity with python/node). A NON-empty title is a
// display LINE: reject control characters (the shared identifier rule), contain a lone surrogate (identity in
// go — the JSON decode already substituted U+FFFD), cap bytes. ("", false) after a reject.
func ctCleanTitle(w http.ResponseWriter, raw *string) (string, bool) {
	if raw == nil || *raw == "" {
		return "", true
	}
	if !well_formed.IsWellFormed(*raw) {
		core.WriteProblem(w, 422, "the title must have no control characters")
		return "", false
	}
	cleaned := well_formed.MakeWellFormed(*raw)
	if len(cleaned) > ctMaxTitleBytes { // go len = UTF-8 bytes (== py encode / node byteLength)
		core.WriteProblem(w, 422, "the title is too large")
		return "", false
	}
	return cleaned, true
}

// ctCleanMetadata — every value must be a JSON STRING: a number/bool/object/array (an Unmarshal error) OR an
// explicit null (vp == nil) is 422, matching py Dict[str,StrictStr] / node typeof checks. Keys AND values are
// CONTAINED, then the CONTAINED, COLLAPSED map is bounded: pair count + per-key/per-value CODE-POINT lengths —
// go's JSON decode already collapsed distinct lone-surrogate keys into one U+FFFD entry, which is why python and
// node count their post-containment dict.
func ctCleanMetadata(w http.ResponseWriter, metadata *map[string]json.RawMessage) (map[string]string, bool) {
	out := map[string]string{}
	if metadata == nil {
		return out, true
	}
	for k, raw := range *metadata {
		var vp *string
		if err := json.Unmarshal(raw, &vp); err != nil || vp == nil {
			core.WriteProblem(w, 422, "metadata values must be strings")
			return nil, false
		}
		out[well_formed.MakeWellFormed(k)] = well_formed.MakeWellFormed(*vp)
	}
	if len(out) > ctMaxMetaPairs {
		core.WriteProblem(w, 422, "too many metadata entries")
		return nil, false
	}
	for k, v := range out {
		if utf8.RuneCountInString(k) > ctMaxMetaKeyChars {
			core.WriteProblem(w, 422, "a metadata key is too long")
			return nil, false
		}
		if utf8.RuneCountInString(v) > ctMaxMetaValueChars {
			core.WriteProblem(w, 422, "a metadata value is too long")
			return nil, false
		}
	}
	return out, true
}

// ctCleanContent — message content is free TEXT (multi-line chat turns are the norm), never a key component
// (keys are the owner + server-minted digits): CONTAIN a lone surrogate (identity in go) and cap bytes; control
// characters ride along as data, exactly like a queue payload.
func ctCleanContent(w http.ResponseWriter, raw *string) (string, bool) {
	if raw == nil || *raw == "" {
		core.WriteProblem(w, 422, "content must be a non-empty string")
		return "", false
	}
	cleaned := well_formed.MakeWellFormed(*raw)
	if len(cleaned) > ctMaxContentBytes() {
		core.WriteProblem(w, 422, "content is too large")
		return "", false
	}
	return cleaned, true
}

func ctThreadPublic(rec ctThread) map[string]any {
	return map[string]any{"id": rec.ID, "title": rec.Title, "metadata": rec.Metadata,
		"created_at": rec.CreatedAt, "updated_at": rec.UpdatedAt, "last_seq": rec.LastSeq}
}

func ctMessagePublic(rec ctMessage) map[string]any {
	return map[string]any{"seq": rec.Seq, "thread_id": rec.ThreadID, "role": rec.Role, "content": rec.Content,
		"metadata": rec.Metadata, "created_at": rec.CreatedAt}
}

// ctReserveSlot — append `id` to the per-owner thread index; returns true iff REJECTED (past MAX_THREADS).
func ctReserveSlot(owner string, id int) bool {
	mx := ctMaxThreads()
	rejected := false
	ctIndex.Do(owner, func(cur []int, exists bool) ([]int, bool) {
		if len(cur) >= mx {
			rejected = true
			return cur, false // reject: leave unwritten (the thread-COUNT bound)
		}
		// unbounded-safe: the per-owner thread list is bounded at MAX_THREADS by the reject-past-cap guard above — a create past the cap is a loud 422, never an eviction (evicting a thread would silently delete a user's chat history); bounding the number of threads bounds the KEY-SPACE, so the per-owner total is capped at MAX_THREADS x MAX_MESSAGES by construction.
		return append(cur, id), true
	})
	return rejected
}
