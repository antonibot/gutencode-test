package file_store

// file_store HTTP handlers — REAL byte objects behind a swappable provider: base64-in-JSON upload, raw-bytes
// download (the stored Content-Type reflected + the stored-XSS defense headers), JSON meta/list/delete, per-owner
// file-COUNT AND total-BYTES quotas. The row (never the index) is the content authority for GET/meta; the index is
// the delete-existence authority. Same names + DECISIONS as the python/node impls.

import (
	"net/http"
	"strconv"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/paginate"
)

func FileStorePut(w http.ResponseWriter, r *http.Request) {
	// PARSE first (DecodeJSON enforces the body cap + drains the stream), THEN auth, THEN validate -> admit -> write.
	in, ok := core.DecodeJSON[struct {
		Key         *string `json:"key"`
		ContentB64  *string `json:"content_b64"`
		ContentType *string `json:"content_type"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r) // mutation-auth: identity — owned by the caller, never a body field
	if !ok {
		return
	}
	if in.Key == nil || in.ContentB64 == nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	key, ok := fsNormKey(*in.Key)
	if !ok {
		core.WriteProblem(w, 422, "the object key is invalid")
		return
	}
	ct, ok := fsCleanContentType(in.ContentType)
	if !ok {
		core.WriteProblem(w, 422, "content_type must be a valid type/subtype token")
		return
	}
	raw, ok := fsDecodeB64(*in.ContentB64)
	if !ok {
		core.WriteProblem(w, 422, "content_b64 must be canonical base64")
		return
	}
	size := len(raw) // derived: size — recomputed server-side; a smuggled value is ignored
	if size > fsMaxBytes() {
		core.WriteProblem(w, 422, "file too large")
		return
	}
	etag := digest.DigestHex(*in.ContentB64) // content-addressed over the CANONICAL b64
	createdAt := core.TestNow(r)
	switch fsAdmit(owner, key, size) { // RMW through the atomic index seam — never get-then-put
	case "count":
		core.WriteProblem(w, 422, "file count limit reached")
		return
	case "quota":
		core.WriteProblem(w, 422, "storage quota exceeded")
		return
	}
	p := fsProvider()
	p.Put(owner, key, fsRow{Owner: owner, Key: key, ContentB64: *in.ContentB64, ContentType: ct,
		Size: size, Etag: etag, CreatedAt: createdAt}) // THEN the row (outside the Do — a tear lands on the SAFE side)
	core.WriteJSON(w, 201, map[string]any{"key": key, "provider": p.Name(), "size": size,
		"etag": etag, "content_type": ct, "created_at": createdAt})
}

func FileStoreList(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // read-scope: owner — served from the per-owner INDEX (one point-read, codepoint order)
	if !ok {
		return
	}
	entries, _ := fsIndex.Get(owner)
	q := r.URL.Query()
	page, next, valid := paginate.Paginate(entries, q.Get("cursor"), q.Get("limit")) // BOUNDED; size is the reservation
	if !valid {
		core.WriteProblem(w, 422, "invalid cursor or limit")
		return
	}
	var nc any
	if next != "" {
		nc = next
	}
	core.WriteJSON(w, 200, map[string]any{"results": page, "next_cursor": nc}) // fsEntry marshals to {key,size}
}

func FileStoreMeta(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // read-scope: owner
	if !ok {
		return
	}
	key, ok := fsNormKey(r.PathValue("file_key"))
	if !ok {
		core.WriteProblem(w, 422, "the object key is invalid")
		return
	}
	row, found := fsProvider().Get(owner, key) // row authority: a cross-owner key is a different composite -> 404
	if !found {
		core.WriteProblem(w, 404, "object not found")
		return
	}
	core.WriteJSON(w, 200, map[string]any{"key": row.Key, "size": row.Size, "etag": row.Etag,
		"content_type": row.ContentType, "created_at": row.CreatedAt})
}

func FileStoreGet(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // read-scope: owner — AUTH before the path grammar (a no-token probe is 401 x3)
	if !ok {
		return
	}
	key, ok := fsNormKey(r.PathValue("file_key"))
	if !ok {
		core.WriteProblem(w, 422, "the object key is invalid")
		return
	}
	row, found := fsProvider().Get(owner, key) // the REAL-bytes download; not-yours == not-found (row authority)
	if !found {
		core.WriteProblem(w, 404, "object not found")
		return
	}
	body, _ := fsDecodeB64(row.ContentB64) // the stored b64 is canonical by construction -> always decodes
	h := w.Header()
	h.Set("Content-Type", row.ContentType)           // the stored type, reflected
	h.Set("ETag", `"`+row.Etag+`"`)                  // content-addressed, RFC 9110 quoted
	h.Set("X-Content-Type-Options", "nosniff")       // stored-XSS defense: never sniff a text/html payload
	h.Set("Content-Disposition", "attachment")       // ... and force download (bare token — no filename param)
	h.Set("Content-Length", strconv.Itoa(len(body))) // explicit x3 (go auto-CLs only small bodies; node always chunks)
	w.WriteHeader(200)
	_, _ = w.Write(body)
}

func FileStoreDelete(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // mutation-auth: identity
	if !ok {
		return
	}
	key, ok := fsNormKey(r.PathValue("file_key"))
	if !ok {
		core.WriteProblem(w, 422, "the object key is invalid")
		return
	}
	fsProvider().Delete(owner, key) // row delete FIRST (idempotent)
	if !fsRelease(owner, key) {     // index release LAST — the existence authority (a phantom is clearable)
		core.WriteProblem(w, 404, "object not found")
		return
	}
	w.WriteHeader(204)
}
