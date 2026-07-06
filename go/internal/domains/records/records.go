// Package records — the App-Layer DATA SUBSTRATE: declare a typed record schema, then owner-scoped CRUD
// (create/list/get/update/delete) over the durable store. Dangerous properties, all proven (same ×3 as python/node):
// (1) OWNER-SCOPED: a record belongs to the caller who created it (core.RequireIdentity); the owner is stamped from
//
//	the authenticated subject, NEVER a body field. A by-id get/patch/delete of another caller's record is 404 —
//	byte-indistinguishable from missing (existence never leaks); the LIST returns only the caller's own rows.
//
// (2) NO MASS-ASSIGNMENT: a write reads ONLY the DECLARED field names out of the body `fields` map (allowlist-READ);
//
//	a smuggled owner/id/type (top-level, in fields, or a case-variant) is never consulted — structurally.
//
// (3) EXACTLY-ONCE CREATE: id = ScopedKey("/records", owner, key) — deterministic, owner-partitioned, idempotent —
//
//	written through ClaimOnce, so a repeat key returns the SAME record.
//
// (4) TYPED VALIDATION: each declared field validated per type with cross-language-identical accept/reject; PATCH is
//
//	a partial merge of validated declared fields through the atomic Do() RMW seam; owner/id/created_at never client-writable.
//
// The record TYPE is authored here (the ×3 source of truth; the manifest x-record_schema mirrors it). The by-id slot
// key is the composite "<owner>\x1f<id>" so a cross-owner id lands in a different slot.
package records

import (
	"net/http"
	"regexp"
	"sort"
	"strconv"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/idempotent_claim"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

// [0-9] not \d — go regexp \d is ASCII but python \d matches Unicode digits; [0-9] keeps the three identical.
var recordsDateRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
var recordsDatetimeRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})?$`)

type recordsField struct {
	name     string
	ftype    string
	required bool
	options  []string
}

// The record TYPE — same field set + types as records.py / records.js.
var recordsSchema = []recordsField{
	{"title", "text", true, nil},
	{"count", "number", false, nil},
	{"done", "boolean", false, nil},
	{"due", "datetime", false, nil},
	{"day", "date", false, nil},
	{"status", "select", false, []string{"open", "closed"}},
	{"meta", "json", false, nil},
}

type recordsRecord struct {
	Id        string         `json:"id"`
	Owner     string         `json:"owner"`
	CreatedAt int            `json:"created_at"`
	UpdatedAt int            `json:"updated_at"`
	Fields    map[string]any `json:"fields"`
}

var recordsKV = core.NewKV[string, recordsRecord]("records_rows")

// org records live in a DISTINCT partition (a subject and an org slug share an alphabet) — purely additive.
var recordsOrgKV = core.NewKV[string, recordsRecord]("records_org_rows")

func recordsPublic(rec recordsRecord) map[string]any {
	return map[string]any{"id": rec.Id, "owner": rec.Owner, "created_at": rec.CreatedAt,
		"updated_at": rec.UpdatedAt, "fields": rec.Fields}
}

// recordsOrgPublic = the user view PLUS scope:"org" (the org partition marker). USER records stay byte-identical.
func recordsOrgPublic(rec recordsRecord) map[string]any {
	v := recordsPublic(rec)
	v["scope"] = "org"
	return v
}

// recordsOrgCtx is the org-scope AUTHZ ladder (mirrors records.py _org_ctx): a forged/control-char ?org= slug -> 422,
// then a non-member/pending/missing org (the core OrgRole seam, never a client field) -> 404 (existence never leaks).
// Returns (slug, true), or writes the error response and returns (_, false).
func recordsOrgCtx(w http.ResponseWriter, org, caller string) (string, bool) {
	if !well_formed.IsWellFormed(org) {
		core.WriteProblem(w, 422, "the org slug must be non-empty with no control characters")
		return "", false
	}
	if _, ok := core.OrgRole(org, caller); !ok {
		core.WriteProblem(w, 404, "record not found")
		return "", false
	}
	return org, true
}

func recordsDateOK(s string) bool {
	// strict ISO format + field ranges, NOT calendar validity (calendar validity is NOT ×3-identical: go time.Date
	// normalizes, node Date rolls over, python raises) — owned v2 hardening. ASCII digits, so byte-indexing is safe.
	if !recordsDateRe.MatchString(s) {
		return false
	}
	mo, _ := strconv.Atoi(s[5:7])
	da, _ := strconv.Atoi(s[8:10])
	return mo >= 1 && mo <= 12 && da >= 1 && da <= 31
}

func recordsDatetimeOK(s string) bool {
	if !recordsDatetimeRe.MatchString(s) {
		return false
	}
	mo, _ := strconv.Atoi(s[5:7])
	da, _ := strconv.Atoi(s[8:10])
	hh, _ := strconv.Atoi(s[11:13])
	mi, _ := strconv.Atoi(s[14:16])
	se, _ := strconv.Atoi(s[17:19])
	return mo >= 1 && mo <= 12 && da >= 1 && da <= 31 && hh <= 23 && mi <= 59 && se <= 59
}

// recordsValidateOne returns (validated, "") or (nil, message); the message is byte-identical to python/node.
func recordsValidateOne(name, ftype string, options []string, value any) (any, string) {
	switch ftype {
	case "text":
		s, ok := value.(string)
		if !ok {
			return nil, "field '" + name + "' must be text"
		}
		return well_formed.MakeWellFormed(s), ""
	case "number":
		return well_formed.SafeNumber(name, value)
	case "boolean":
		b, ok := value.(bool)
		if !ok {
			return nil, "field '" + name + "' must be a boolean"
		}
		return b, ""
	case "date":
		s, ok := value.(string)
		if !ok || !recordsDateOK(s) {
			return nil, "field '" + name + "' must be a date (YYYY-MM-DD)"
		}
		return s, ""
	case "datetime":
		s, ok := value.(string)
		if !ok || !recordsDatetimeOK(s) {
			return nil, "field '" + name + "' must be an ISO-8601 datetime"
		}
		return s, ""
	case "select":
		if s, ok := value.(string); ok {
			for _, o := range options {
				if s == o {
					return s, ""
				}
			}
		}
		return nil, "field '" + name + "' is not an allowed option"
	}
	return well_formed.SanitizeJSON(name, value) // json: recursed — surrogate-safe strings + the ×3-safe number ceiling
}

func recordsValidate(fieldsIn map[string]any, creating bool) (map[string]any, string) {
	out := map[string]any{}
	for _, f := range recordsSchema {
		v, present := fieldsIn[f.name] // allowlist-READ: only DECLARED names are ever read
		if present {
			vv, msg := recordsValidateOne(f.name, f.ftype, f.options, v)
			if msg != "" {
				return nil, msg
			}
			out[f.name] = vv
		} else if creating && f.required {
			return nil, "field '" + f.name + "' is required"
		}
	}
	return out, ""
}

// recordsListPage writes the owner-scoped, id-sorted, BOUNDED page of `kv` for `owner` (a stranger/empty caller gets an
// empty page, never 403), each row rendered through `public`. The ONE list body the user + org read paths share.
func recordsListPage(w http.ResponseWriter, r *http.Request, kv *core.KV[string, recordsRecord], owner string, public func(recordsRecord) map[string]any) {
	mine := make([]recordsRecord, 0)
	for _, rec := range kv.All() {
		if rec.Owner == owner { // filtered on the authenticated owner FIELD as stored, never a client-supplied value
			mine = append(mine, rec)
		}
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].Id < mine[j].Id })
	views := make([]map[string]any, len(mine))
	for i, rec := range mine {
		views[i] = public(rec)
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

// recordsMergePatch applies a partial-merge PATCH through the atomic Do() RMW seam on `kv` at `slot`: only the DECLARED
// (pre-validated) fields merge, updated_at advances, owner/id/created_at come from cur (never the client). Returns
// (merged, true) or (zero, false) when the slot is absent (404, no resurrection). The ONE RMW the user + org paths share.
func recordsMergePatch(kv *core.KV[string, recordsRecord], slot string, validated map[string]any, now int) (recordsRecord, bool) {
	found := false
	var result recordsRecord
	kv.Do(slot, func(cur recordsRecord, exists bool) (recordsRecord, bool) {
		if !exists {
			return cur, false // 404 (no resurrection)
		}
		found = true
		merged := map[string]any{}
		for k, v := range cur.Fields {
			merged[k] = v
		}
		for k, v := range validated { // partial merge of DECLARED fields only
			merged[k] = v
		}
		cur.Fields = merged
		cur.UpdatedAt = now // owner/id/created_at untouched (I-PATCH-IMMUT)
		result = cur
		return cur, true
	})
	return result, found
}

// recordsWriteNew validates the create body (missing/forged key -> 422, then the typed fields), derives the exactly-once
// id via ScopedKey(route, owner, key) (owner from the token/verified org slug, NEVER a body field), and claims it once
// on `kv`, rendering the winner through `public`. The ONE create body the user + org write paths share.
func recordsWriteNew(w http.ResponseWriter, r *http.Request, kv *core.KV[string, recordsRecord], route, owner string, key *string, fields map[string]any, public func(recordsRecord) map[string]any) {
	if key == nil {
		core.WriteProblem(w, 422, "invalid body") // missing key (like the python required-field 422)
		return
	}
	if !well_formed.IsWellFormed(*key) {
		core.WriteProblem(w, 422, "the record key must be non-empty with no control characters")
		return
	}
	validated, msg := recordsValidate(fields, true)
	if msg != "" {
		core.WriteProblem(w, 422, msg)
		return
	}
	now := int(core.TestNow(r))
	rid := digest.ScopedKey(route, owner, *key) // deterministic + owner-partitioned + idempotent; owner never client-set
	rec := recordsRecord{Id: rid, Owner: owner, CreatedAt: now, UpdatedAt: now, Fields: validated}
	winner := idempotent_claim.ClaimOnce(kv, owner+"\x1f"+rid, rec) // exactly-once: a repeat key returns the SAME record
	core.WriteJSON(w, 201, public(winner))
}

func RecordsCreate(w http.ResponseWriter, r *http.Request) {
	// body-only POST: DecodeJSON FIRST (drain + 413 cap), THEN RequireIdentity, THEN validate — identical ×3.
	in, ok := core.DecodeJSON[struct {
		Key    *string        `json:"key"`
		Fields map[string]any `json:"fields"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if org := r.URL.Query().Get("org"); org != "" {
		slug, ok := recordsOrgCtx(w, org, owner) // membership FIRST: 422 (bad slug) then 404 (non-member) BEFORE body validation
		if !ok {
			return
		}
		recordsWriteNew(w, r, recordsOrgKV, "/records@org", slug, in.Key, in.Fields, recordsOrgPublic) // a DISTINCT route -> a disjoint id space; owner = the verified slug
		return
	}
	recordsWriteNew(w, r, recordsKV, "/records", owner, in.Key, in.Fields, recordsPublic)
}

func RecordsList(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if org := r.URL.Query().Get("org"); org != "" {
		slug, ok := recordsOrgCtx(w, org, owner) // non-member (incl. missing org) -> 404, never a leaked empty page
		if !ok {
			return
		}
		recordsListPage(w, r, recordsOrgKV, slug, recordsOrgPublic)
		return
	}
	// SCOPED read: only the caller's own rows leave the store, id-sorted, then a BOUNDED page; a stranger gets an
	// empty page, never 403.
	recordsListPage(w, r, recordsKV, owner, recordsPublic)
}

func RecordsGet(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // AUTH first: a no-token probe is 401
	if !ok {
		return
	}
	if org := r.URL.Query().Get("org"); org != "" {
		slug, ok := recordsOrgCtx(w, org, owner) // non-member -> 404 (same 404 as a missing org record)
		if !ok {
			return
		}
		rec, exists := recordsOrgKV.Get(slug + "\x1f" + r.PathValue("record_id"))
		if !exists {
			core.WriteProblem(w, 404, "record not found")
			return
		}
		core.WriteJSON(w, 200, recordsOrgPublic(rec))
		return
	}
	rec, exists := recordsKV.Get(owner + "\x1f" + r.PathValue("record_id")) // cross-owner id -> different slot -> 404
	if !exists {
		core.WriteProblem(w, 404, "record not found")
		return
	}
	core.WriteJSON(w, 200, recordsPublic(rec))
}

func RecordsUpdate(w http.ResponseWriter, r *http.Request) {
	in, ok := core.DecodeJSON[struct {
		Fields map[string]any `json:"fields"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if org := r.URL.Query().Get("org"); org != "" {
		slug, ok := recordsOrgCtx(w, org, owner) // membership FIRST (404) before body validation (422)
		if !ok {
			return
		}
		validated, msg := recordsValidate(in.Fields, false)
		if msg != "" {
			core.WriteProblem(w, 422, msg)
			return
		}
		result, found := recordsMergePatch(recordsOrgKV, slug+"\x1f"+r.PathValue("record_id"), validated, int(core.TestNow(r)))
		if !found {
			core.WriteProblem(w, 404, "record not found")
			return
		}
		core.WriteJSON(w, 200, recordsOrgPublic(result))
		return
	}
	validated, msg := recordsValidate(in.Fields, false) // validate BEFORE the transaction (Do's fn must be pure)
	if msg != "" {
		core.WriteProblem(w, 422, msg)
		return
	}
	result, found := recordsMergePatch(recordsKV, owner+"\x1f"+r.PathValue("record_id"), validated, int(core.TestNow(r)))
	if !found {
		core.WriteProblem(w, 404, "record not found")
		return
	}
	core.WriteJSON(w, 200, recordsPublic(result))
}

func RecordsDelete(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if org := r.URL.Query().Get("org"); org != "" {
		slug, ok := recordsOrgCtx(w, org, owner) // non-member -> 404 (existence never leaks)
		if !ok {
			return
		}
		composite := slug + "\x1f" + r.PathValue("record_id")
		if _, exists := recordsOrgKV.Get(composite); !exists {
			core.WriteProblem(w, 404, "record not found")
			return
		}
		recordsOrgKV.Delete(composite)
		w.WriteHeader(204)
		return
	}
	composite := owner + "\x1f" + r.PathValue("record_id")
	if _, exists := recordsKV.Get(composite); !exists {
		core.WriteProblem(w, 404, "record not found") // idempotent re-delete -> 404; cross-owner -> 404
		return
	}
	recordsKV.Delete(composite)
	w.WriteHeader(204)
}
