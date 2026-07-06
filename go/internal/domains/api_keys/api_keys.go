// Package api_keys — issue/list/verify/rotate/revoke API keys with scopes; every key records created_at (seconds,
// the core clock seam, preserved across rotate). (1) NO PLAINTEXT AT REST: the secret is
// shown ONCE; only sha256(secret) (the digest part) is stored. (2) CONSTANT-TIME, NON-ENUMERABLE VERIFY: every
// verify hashes and runs ONE hmac.Equal against a record (a dummy when the id is unknown) — an unknown id and a
// wrong secret are the same {valid:false} after the same work; scopes only when valid. (3) ROTATION invalidates
// the old secret. (4) REVOCATION is monotonic. Key is `ak_<id>_<secret>`; the prefix is public, the secret is
// not. Store names and shapes match python/node; durable.
//
// OWNERSHIP — a key is USER-SCOPED: it belongs to the caller who created it. ApiKeysCreate/Get/List/Rotate/Revoke require
// core.RequireIdentity, the OWNER is stamped from the authenticated subject at create (never a body field), and a
// management op on another caller's key id is 404 — byte-identical to a missing id, so the enumerable sequential
// id leaks no existence (the tenancy not-yours==not-found pattern). ApiKeysList is the same owner-scoping over a
// COLLECTION (only the caller's keys, paginated, secret/owner-blind; a stranger gets an empty page, never 403). Precedence ×3: create is body-only so DecodeJSON
// runs FIRST (drain + 413), then RequireIdentity, then validation; the {key_id} routes run RequireIdentity FIRST so
// a no-token probe is 401 before the path-422. ApiKeysVerify stays PUBLIC (see its `mutation-auth: public`).
package api_keys

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

var apiKeysDummyHash = digest.DigestHex("api_keys_absent_record_filler")

type apiKeysRecord struct {
	Id         int      `json:"id"`
	Name       string   `json:"name"`
	Owner      string   `json:"owner"`
	Scopes     []string `json:"scopes"`
	Prefix     string   `json:"prefix"`
	SecretHash string   `json:"secret_hash"`
	Status     string   `json:"status"`
	CreatedAt  int      `json:"created_at"`
}

var apiKeysRecords = core.NewKV[string, apiKeysRecord]("api_keys_records")

func apiKeysPublic(rec apiKeysRecord) map[string]any {
	return map[string]any{"id": rec.Id, "name": rec.Name, "scopes": rec.Scopes, "prefix": rec.Prefix,
		"status": rec.Status, "created_at": rec.CreatedAt} // NEVER secret_hash OR owner (owner private); created_at public
}

func apiKeysIssue(rec apiKeysRecord) map[string]any {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		panic("api_keys: randomness unavailable") // a guessable secret is worse than a crash
	}
	secret := base64.RawURLEncoding.EncodeToString(buf)
	rec.SecretHash = digest.DigestHex(secret)
	apiKeysRecords.Set(strconv.Itoa(rec.Id), rec)
	out := apiKeysPublic(rec)
	out["key"] = "ak_" + strconv.Itoa(rec.Id) + "_" + secret
	return out
}

func ApiKeysCreate(w http.ResponseWriter, r *http.Request) {
	// body-only POST: DecodeJSON FIRST (drain the stream + enforce the 413 cap), THEN RequireIdentity, THEN validate
	// — so an ill-typed/oversize body is a 413/422 before auth, and a no-token caller is 401, identical ×3.
	in, ok := core.DecodeJSON[struct {
		Name   *string  `json:"name"`
		Scopes []string `json:"scopes"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if in.Name == nil || !well_formed.IsWellFormed(*in.Name) || len(in.Scopes) == 0 {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	for _, s := range in.Scopes {
		if !well_formed.IsWellFormed(s) {
			core.WriteProblem(w, 422, "invalid body")
			return
		}
	}
	kid := core.NextID("api_keys_key")
	// owner derived from the token, never client-set; created_at = the birth time via the core clock seam (preserved across rotate)
	rec := apiKeysRecord{Id: kid, Name: *in.Name, Owner: owner, Scopes: in.Scopes, Prefix: "ak_" + strconv.Itoa(kid),
		Status: "active", CreatedAt: int(core.TestNow(r))}
	core.WriteJSON(w, 201, apiKeysIssue(rec))
}

// apiKeysLoad expects RequireIdentity to have run already (so a no-token probe is 401 before the path-422); it does
// the path-int check, then loads, then enforces owner==caller, returning 404 for a missing OR cross-owner id.
func apiKeysLoad(w http.ResponseWriter, r *http.Request, owner string) (apiKeysRecord, bool) {
	kid, err := strconv.Atoi(r.PathValue("key_id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid key id")
		return apiKeysRecord{}, false
	}
	rec, exists := apiKeysRecords.Get(strconv.Itoa(kid))
	if !exists || rec.Owner != owner {
		core.WriteProblem(w, 404, "api key not found") // not-yours == not-found: existence never leaks cross-owner
		return apiKeysRecord{}, false
	}
	return rec, true
}

func ApiKeysGet(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // AUTH first: a no-token probe is 401 before the path-422
	if !ok {
		return
	}
	if rec, ok := apiKeysLoad(w, r, owner); ok {
		core.WriteJSON(w, 200, apiKeysPublic(rec))
	}
}

func ApiKeysList(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	// OWNER-SCOPED LIST: only the caller's keys leave the store — filtered INLINE on the authenticated owner, mapped
	// to the secret/owner-blind public view, then a BOUNDED page. Cross-owner isolation proven by I8; a stranger
	// gets an empty page, never 403.
	mine := make([]apiKeysRecord, 0)
	for _, rec := range apiKeysRecords.All() {
		if rec.Owner == owner {
			mine = append(mine, rec)
		}
	}
	// sorted by id (the stable order) — rotate/revoke re-write a row + bump its rowid, so an explicit id-sort is
	// required for a stable paged walk (the notifications/admin precedent; tenancy/audit_log never UPDATE a row).
	sort.Slice(mine, func(i, j int) bool { return mine[i].Id < mine[j].Id })
	views := make([]map[string]any, len(mine))
	for i, rec := range mine {
		views[i] = apiKeysPublic(rec)
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

func ApiKeysVerify(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: public — INTENTIONALLY unauthenticated. The `ak_<id>_<secret>` key IS the credential (like a
	// login): a caller verifies it BEFORE it has a session, so RequireIdentity would break the route's purpose. It
	// mutates no stored state on behalf of any user — it only recomputes the hash and runs one constant-time
	// compare. The owner-scoping guards the MANAGEMENT ops (create/get/rotate/revoke), not this credential check.
	in, ok := core.DecodeJSON[struct {
		Key *string `json:"key"`
	}](w, r)
	if !ok {
		return
	}
	if in.Key == nil || *in.Key == "" {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	// parse `ak_<id>_<secret>`; a malformed key still runs the dummy compare (uniform timing)
	keyID, secret := "", ""
	parts := strings.SplitN(*in.Key, "_", 3)
	if len(parts) == 3 && parts[0] == "ak" {
		keyID, secret = parts[1], parts[2]
	}
	rec, found := apiKeysRecords.Get(keyID)
	stored := apiKeysDummyHash
	if found {
		stored = rec.SecretHash
	}
	match := hmac.Equal([]byte(digest.DigestHex(secret)), []byte(stored)) // ALWAYS one constant-time compare
	valid := found && rec.Status == "active" && match
	scopes := []string{}
	if valid {
		scopes = rec.Scopes
	}
	core.WriteJSON(w, 200, map[string]any{"valid": valid, "scopes": scopes})
}

func ApiKeysRotate(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // AUTH first: a no-token probe is 401 before the path-422
	if !ok {
		return
	}
	rec, ok := apiKeysLoad(w, r, owner)
	if !ok {
		return
	}
	core.WriteJSON(w, 200, apiKeysIssue(rec)) // new secret + hash replaces the old; the old can never verify again
}

func ApiKeysRevoke(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // AUTH first: a no-token probe is 401 before the path-422
	if !ok {
		return
	}
	rec, ok := apiKeysLoad(w, r, owner)
	if !ok {
		return
	}
	rec.Status = "revoked" // monotonic + idempotent: revoked is TERMINAL
	apiKeysRecords.Set(strconv.Itoa(rec.Id), rec)
	core.WriteJSON(w, 200, apiKeysPublic(rec))
}
