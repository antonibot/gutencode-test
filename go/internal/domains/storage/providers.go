// storage providers — the swappable seam (ports-and-adapters). The PROVIDER interface is the contract; the
// selection happens ONCE here (STORAGE_PROVIDER env), never at call sites. USER-SCOPED: the store key is the
// composite "<owner>\x1f<user-key>" (owner FIRST; the user key is well_formed — no control chars — so it can
// never contain the \x1f unit separator, and the composite key CANNOT be forged to reach another owner's object),
// and the stored ROW stamps its owner so the list filters on the authenticated owner and returns BARE keys. The
// public object shape ({key,content,size,etag}) is unchanged — owner is internal. The 'store' provider keeps
// whole objects in the durable runtime store seam; the 's3' provider is the FAIL-LOUD customization stub:
// selecting it unconfigured (or unwired) panics -> a loud 500, never a silent black-hole store.
package storage

import (
	"sort"

	"app/internal/core"
	"app/internal/parts/digest"
)

const storageSep = "\x1f" // the unit separator — forbidden in user keys by well_formed, so the composite key can't be forged

func storageOKey(owner, key string) string {
	return owner + storageSep + key // owner FIRST: the row is addressed by (owner, key), never by the user key alone
}

// the PUBLIC object shape (the GET response body) — unchanged by the USER-SCOPED migration
type storageObject struct {
	Key     string `json:"key"`
	Content string `json:"content"`
	Size    int    `json:"size"`
	Etag    string `json:"etag"`
}

// the STORED row stamps the owner (internal scoping metadata) alongside the public object
type storageRow struct {
	Owner   string `json:"owner"`
	Key     string `json:"key"`
	Content string `json:"content"`
	Size    int    `json:"size"`
	Etag    string `json:"etag"`
}

func (row storageRow) object() storageObject {
	return storageObject{Key: row.Key, Content: row.Content, Size: row.Size, Etag: row.Etag} // owner stays internal
}

type storagePutResult struct {
	Key      string `json:"key"`
	Provider string `json:"provider"`
	Size     int    `json:"size"`
	Etag     string `json:"etag"`
}

type storageBackend interface {
	Put(owner, key, content string) storagePutResult
	Get(owner, key string) (storageObject, bool)
	Delete(owner, key string) bool
	Keys(owner string) []string
}

var storageObjects = core.NewKV[string, storageRow]("storage_objects")

type durableStorage struct{}

func (durableStorage) Put(owner, key, content string) storagePutResult {
	row := storageRow{Owner: owner, Key: key, Content: content, Size: len(content), Etag: digest.DigestHex(content)}
	storageObjects.Set(storageOKey(owner, key), row) // the WHOLE object under the owner-composed key
	return storagePutResult{Key: key, Provider: "store", Size: row.Size, Etag: row.Etag}
}

func (durableStorage) Get(owner, key string) (storageObject, bool) {
	row, found := storageObjects.Get(storageOKey(owner, key))
	if !found {
		return storageObject{}, false
	}
	return row.object(), true
}

func (durableStorage) Delete(owner, key string) bool {
	okey := storageOKey(owner, key)
	if _, found := storageObjects.Get(okey); !found {
		return false
	}
	storageObjects.Delete(okey)
	return true
}

func (durableStorage) Keys(owner string) []string {
	// owner-filtered (on the stamped owner field), returned as BARE keys
	// unbounded-safe: the storageList route paginates this owner key set via the paginate part — Keys() does the
	// raw .All() scan but bounding happens one layer up at the route (the provider signature stays stable ×adapters)
	keys := []string{}
	for _, row := range storageObjects.All() {
		if row.Owner == owner {
			keys = append(keys, row.Key)
		}
	}
	sort.Strings(keys)
	return keys
}

type s3Storage struct{}

func (s3Storage) fail() {
	panic("the s3 provider is a customization stub - wire a real client here (or set STORAGE_PROVIDER=store)")
}

// USER-SCOPED: each method receives the AUTHENTICATED owner first — namespace your bucket/prefix by it (e.g. an
// "<owner>/" key prefix), exactly as durableStorage composes "<owner>\x1f<key>", so one caller can never reach
// another's objects and Keys(owner) lists only that owner's.
func (s s3Storage) Put(owner, key, content string) storagePutResult { s.fail(); return storagePutResult{} }
func (s s3Storage) Get(owner, key string) (storageObject, bool)     { s.fail(); return storageObject{}, false }
func (s s3Storage) Delete(owner, key string) bool                   { s.fail(); return false }
func (s s3Storage) Keys(owner string) []string                      { s.fail(); return nil }

var storageInstance storageBackend

func storageProvider() storageBackend {
	if storageInstance == nil {
		if core.EnvOr("STORAGE_PROVIDER", "store") == "s3" {
			if core.EnvOr("S3_BUCKET", "") == "" || core.EnvOr("S3_ENDPOINT", "") == "" {
				panic("STORAGE_PROVIDER=s3 requires S3_BUCKET and S3_ENDPOINT") // fail loud, never store nothing
			}
			storageInstance = s3Storage{}
		} else {
			storageInstance = durableStorage{}
		}
	}
	return storageInstance
}
