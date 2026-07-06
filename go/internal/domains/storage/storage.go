// Package storage — object storage behind a swappable provider port (ports-and-adapters). USER-SCOPED: a
// stored object belongs to its uploader (core.RequireIdentity), so every route is deny-by-default authenticated
// (no token -> 401) and an object is addressed by (owner, key) — caller A's `a.txt` and caller B's `a.txt` are
// DISTINCT objects (no cross-owner overwrite), the list returns ONLY the caller's own keys, and a cross-owner
// get/delete is 404 (byte-indistinguishable from missing — existence never leaks across owners). The dangerous
// property is INTEGRITY: round-trips are byte-for-byte and the etag is CONTENT-ADDRESSED (sha256 of the payload
// via the digest part), so corruption or substitution is always visible. The provider is selected ONCE
// (STORAGE_PROVIDER env, providers.go): 'store' = the durable runtime store seam (default + the deterministic
// oracle; objects survive a restart), 's3' = a fail-loud customization stub. Handlers never name a backend.
// Store names and the object shape match the python/node impls.
package storage

import (
	"net/http"

	"app/internal/core"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

func storageKey(w http.ResponseWriter, raw string) (string, bool) {
	if !well_formed.IsWellFormed(raw) {
		core.WriteProblem(w, 422, "object key must be non-empty with no control characters")
		return "", false
	}
	return raw, true
}

func StoragePut(w http.ResponseWriter, r *http.Request) {
	// PARSE first: DecodeJSON enforces the body cap (413) and drains the stream — replying (incl. a 401) before the
	// body is read aborts the connection mid-upload. Identity is checked NEXT, before any validation or write.
	in, ok := core.DecodeJSON[struct {
		Key     *string `json:"key"`
		Content *string `json:"content"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r) // AUTH: the object is owned by the caller
	if !ok {
		return
	}
	// the key is an IDENTIFIER; the content is an opaque payload — a zero-byte object is valid
	if in.Key == nil || !well_formed.IsWellFormed(*in.Key) || in.Content == nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	core.WriteJSON(w, 201, storageProvider().Put(owner, *in.Key, *in.Content)) // stored under the (owner, key) pair
}

func StorageList(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	// SCOPED read: only the caller's own bare keys ever leave the store (owner-filtered, prefix stripped), then a
	// BOUNDED page over that stable-ordered owner key set via the shared paginate part (the provider returns the
	// full owner list; bounding happens here, one layer up — so the provider signature stays stable across adapters).
	q := r.URL.Query()
	page, next, valid := paginate.Paginate(storageProvider().Keys(owner), q.Get("cursor"), q.Get("limit"))
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

func StorageGet(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // AUTH before path-422: a no-token control-char probe is 401, ×3
	if !ok {
		return
	}
	key, ok := storageKey(w, r.PathValue("object_key"))
	if !ok {
		return
	}
	obj, found := storageProvider().Get(owner, key)
	if !found {
		core.WriteProblem(w, 404, "object not found") // not-yours == not-found: another owner's object is under a different key
		return
	}
	core.WriteJSON(w, 200, obj)
}

func StorageDelete(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // AUTH before path-422: a no-token control-char probe is 401, ×3
	if !ok {
		return
	}
	key, ok := storageKey(w, r.PathValue("object_key"))
	if !ok {
		return
	}
	if !storageProvider().Delete(owner, key) {
		core.WriteProblem(w, 404, "object not found") // not-yours == not-found: a cross-owner delete can't destroy another's object
		return
	}
	w.WriteHeader(204)
}
