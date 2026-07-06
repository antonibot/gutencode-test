// Package tenancy — tenant isolation, the application-level row-scoping shape (models Postgres row-level
// security). Every row carries its tenant; EVERY read is scoped to the caller's tenant; a cross-tenant read is
// 404, byte-indistinguishable from a missing row (existence is never revealed across tenants). The tenant is the
// AUTHENTICATED identity (core.RequireIdentity) — derived from the bearer token, NEVER a client-supplied
// X-Tenant-Id header — so a caller cannot read another tenant's rows by setting a header. Deny-by-default (no
// token -> 401). The demo resource is a note; the isolation pattern is the product. Store namespaces and the row
// shape match the python/node impls. (Minimal scope: tenant = authenticated principal; multi-user tenants via org
// membership are a follow-on.)
package tenancy

import (
	"net/http"
	"strconv"

	"app/internal/core"
	"app/internal/parts/paginate"
)

type tenancyNote struct {
	Id     int    `json:"id"`
	Tenant string `json:"tenant"`
	Body   string `json:"body"`
}

var tenancyNotes = core.NewKV[string, tenancyNote]("tenancy_notes")

func TenancyCreate(w http.ResponseWriter, r *http.Request) {
	// decode FIRST: DecodeJSON enforces the body cap (413) and drains the stream — replying (incl. a 401) before
	// the body is read aborts the connection mid-upload. Identity is checked next, before any write.
	in, ok := core.DecodeJSON[struct {
		Body *string `json:"body"`
	}](w, r)
	if !ok {
		return
	}
	tenant, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if in.Body == nil || *in.Body == "" {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	nid := core.NextID("tenancy_note") // atomic, durable; a crash before the write loses the id (a harmless gap)
	row := tenancyNote{Id: nid, Tenant: tenant, Body: *in.Body} // tenant derived from the token, never client-set
	tenancyNotes.Set(strconv.Itoa(nid), row)
	core.WriteJSON(w, 201, row)
}

func TenancyList(w http.ResponseWriter, r *http.Request) {
	tenant, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	// SCOPED read: only the caller's tenant's rows ever leave the store (filtered on the authenticated tenant),
	// then a bounded page over that owner-scoped list (store insertion order is stable + identical ×3).
	rows := make([]tenancyNote, 0)
	for _, row := range tenancyNotes.All() {
		if row.Tenant == tenant {
			rows = append(rows, row)
		}
	}
	q := r.URL.Query()
	page, next, valid := paginate.Paginate(rows, q.Get("cursor"), q.Get("limit"))
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

func TenancyGet(w http.ResponseWriter, r *http.Request) {
	tenant, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	nid, err := strconv.Atoi(r.PathValue("note_id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid note id") // a non-numeric id is a 422, never a silent miss
		return
	}
	row, exists := tenancyNotes.Get(strconv.Itoa(nid))
	if !exists || row.Tenant != tenant {
		core.WriteProblem(w, 404, "note not found") // not-yours == not-found: existence never leaks across tenants
		return
	}
	core.WriteJSON(w, 200, row)
}
