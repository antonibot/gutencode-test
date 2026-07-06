package file_store

// Store model, namespaces, env knobs, the composite key, the atomic quota/count index, and the swappable provider
// port (the storage idiom) for the file_store domain. The HTTP handlers live in file_store.go; the byte/name
// validators in validate.go. Store namespaces + the DECISIONS match the python/node impls.

import (
	"os"
	"sort"

	"app/internal/core"
	"app/internal/parts/env_int"
)

const fsSep = "\x1f" // the unit separator — forbidden in user keys by the grammar, so the composite key can't be forged

func fsOKey(owner, key string) string { return owner + fsSep + key } // owner FIRST: addressed by (owner, key)

// fsRow — the WHOLE object under the owner-composed key; born consistent (size/etag written WITH the content).
type fsRow struct {
	Owner       string `json:"owner"`
	Key         string `json:"key"`
	ContentB64  string `json:"content_b64"`
	ContentType string `json:"content_type"`
	Size        int    `json:"size"`
	Etag        string `json:"etag"`
	CreatedAt   int64  `json:"created_at"`
}

// fsEntry — one {key, size} slot in the per-owner index (the quota RESERVATION ledger, codepoint-sorted by key).
type fsEntry struct {
	Key  string `json:"key"`
	Size int    `json:"size"`
}

var (
	fsObjects = core.NewKV[string, fsRow]("file_store_objects")   // "<owner>\x1f<key>" -> fsRow
	fsIndex   = core.NewKV[string, []fsEntry]("file_store_index") // "<owner>" -> [{key,size}] (the quota + COUNT authority)
)

func fsMaxBytes() int      { return env_int.EnvInt(os.Getenv("FILE_STORE_MAX_BYTES"), 524288, 1, 786000) }
func fsMaxKeys() int       { return env_int.EnvInt(os.Getenv("FILE_STORE_MAX_KEYS"), 1000, 1, 10000) }
func fsMaxTotalBytes() int { return env_int.EnvInt(os.Getenv("FILE_STORE_MAX_TOTAL_BYTES"), 52428800, 1, 1<<40) }

// fsAdmit — ATOMIC quota/count admission through the index Do seam: the new-vs-existing decision AND the old size
// are read from the entries INSIDE the callback (never a pre-Do row read — a TOCTOU under concurrent replace that
// also double-counts over a create-tear). The callback is PURE (the row write happens OUTSIDE, in the handler).
// Returns "ok" | "count" | "quota".
func fsAdmit(owner, key string, size int) string {
	mxKeys, mxTotal := fsMaxKeys(), fsMaxTotalBytes()
	result := "ok"
	fsIndex.Do(owner, func(cur []fsEntry, _ bool) ([]fsEntry, bool) {
		total, old := 0, -1
		for i, e := range cur {
			total += e.Size // total < MAX_KEYS*MAX_BYTES < 2^33 << 2^53 (safe accumulator x3)
			if e.Key == key {
				old = i
			}
		}
		if old >= 0 { // REPLACE: a delta on the existing reservation
			if total-cur[old].Size+size > mxTotal {
				result = "quota"
				return cur, false
			}
			next := make([]fsEntry, len(cur))
			copy(next, cur)
			next[old].Size = size
			return next, true
		}
		if len(cur) >= mxKeys { // the file-COUNT cap (the partition-COUNT bound)
			result = "count"
			return cur, false
		}
		if total+size > mxTotal { // the total-BYTES quota
			result = "quota"
			return cur, false
		}
		// unbounded-safe: the per-owner entries list is bounded at FILE_STORE_MAX_KEYS by the reject-past-cap guard above (a create past the cap is a loud 422, never an eviction — dropping a user's file is data loss); bounding the COUNT bounds the per-owner key-space, and each entry's bytes are bounded by the 1024-byte key cap, so the index row is bounded by construction.
		next := append(cur, fsEntry{Key: key, Size: size})
		sort.Slice(next, func(i, j int) bool { return next[i].Key < next[j].Key }) // codepoint order (utf-8 byte order == codepoint order)
		return next, true
	})
	return result
}

// fsRelease — remove the key's entry from the owner index; returns true iff it was present (the DELETE existence
// authority, so a phantom entry with no row is user-clearable), read-modified atomically through Do.
func fsRelease(owner, key string) bool {
	found := false
	fsIndex.Do(owner, func(cur []fsEntry, _ bool) ([]fsEntry, bool) {
		kept := make([]fsEntry, 0, len(cur))
		for _, e := range cur {
			if e.Key != key {
				kept = append(kept, e)
			}
		}
		if len(kept) == len(cur) {
			return cur, false
		}
		found = true
		return kept, true
	})
	return found
}

// the provider seam (the storage idiom) — selected ONCE. 'store' = durable rows; 's3' = the FAIL-LOUD stub.
type fsBackend interface {
	Put(owner, key string, row fsRow)
	Get(owner, key string) (fsRow, bool)
	Delete(owner, key string)
	Name() string
}

type fsDurable struct{}

func (fsDurable) Put(owner, key string, row fsRow) { fsObjects.Set(fsOKey(owner, key), row) }
func (fsDurable) Get(owner, key string) (fsRow, bool) {
	return fsObjects.Get(fsOKey(owner, key))
}
func (fsDurable) Delete(owner, key string) { fsObjects.Delete(fsOKey(owner, key)) }
func (fsDurable) Name() string             { return "store" }

type fsS3 struct{}

// USER-SCOPED: a real adapter receives the AUTHENTICATED owner — namespace your bucket/prefix by it (an "<owner>/"
// key prefix), exactly as fsDurable composes "<owner>\x1f<key>".
func (fsS3) fail() {
	panic("the s3 provider is a customization stub - wire a real client here (or set FILE_STORE_PROVIDER=store)")
}
func (s fsS3) Put(owner, key string, row fsRow) { s.fail() }
func (s fsS3) Get(owner, key string) (fsRow, bool) {
	s.fail()
	return fsRow{}, false
}
func (s fsS3) Delete(owner, key string) { s.fail() }
func (fsS3) Name() string               { return "s3" }

var fsInstance fsBackend

func fsProvider() fsBackend {
	if fsInstance == nil {
		if core.EnvOr("FILE_STORE_PROVIDER", "store") == "s3" {
			if core.EnvOr("FILE_STORE_S3_BUCKET", "") == "" || core.EnvOr("FILE_STORE_S3_ENDPOINT", "") == "" {
				panic("FILE_STORE_PROVIDER=s3 requires FILE_STORE_S3_BUCKET and FILE_STORE_S3_ENDPOINT") // fail loud
			}
			fsInstance = fsS3{}
		} else {
			fsInstance = fsDurable{}
		}
	}
	return fsInstance
}
