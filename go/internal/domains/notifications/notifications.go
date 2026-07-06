// Package notifications — in-app notifications with three dangerous properties, all proven:
// (1) SENDER IS THE AUTHENTICATED CALLER: sending requires a valid bearer token (no token -> 401) and the
// notification's `from` is STAMPED from the authenticated subject (core.RequireIdentity) — NEVER a caller-supplied
// body field, so a caller cannot forge the sender. (2) RECIPIENT SCOPING: a notification belongs to its recipient;
// listing or acting as anyone else returns 404, byte-indistinguishable from missing (existence never leaks), keyed
// by the AUTHENTICATED identity from the core RequireIdentity seam — NOT a caller-supplied param, so a client
// cannot read another's by setting a header. Deny-by-default. (3) MONOTONIC READ-STATE: unread -> read only;
// marking read is idempotent (a TERMINAL-value write — concurrent marks converge, the billing-cancel class) and a
// read notification never returns to unread. Store names and shapes match the python/node impls (the `from` field
// included); the read-state survives a restart.
package notifications

import (
	"net/http"
	"sort"
	"strconv"

	"app/internal/core"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

type notificationsItem struct {
	Id      int    `json:"id"`
	From    string `json:"from"` // the AUTHENTICATED sender (RequireIdentity), never a body field
	To      string `json:"to"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

var notificationsItems = core.NewKV[string, notificationsItem]("notifications_items")

func NotificationsSend(w http.ResponseWriter, r *http.Request) {
	// body-only POST: decode FIRST (DecodeJSON enforces the body cap (413) and drains the stream — replying, incl.
	// a 401, before the body is read aborts the connection mid-upload), THEN auth, THEN field validation. ×3 parity.
	// The body carries only {to, message}: a `from` in the body is IGNORED — the sender comes from the token.
	in, ok := core.DecodeJSON[struct {
		To      *string `json:"to"`
		Message *string `json:"message"`
	}](w, r)
	if !ok {
		return
	}
	sender, ok := core.RequireIdentity(w, r) // authenticated mutation (no/invalid token -> 401), before any write
	if !ok {
		return
	}
	if in.To == nil || !well_formed.IsWellFormed(*in.To) || in.Message == nil || *in.Message == "" {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	nid := core.NextID("notifications_item") // atomic, durable; a crash before the write loses the id (a gap)
	// `from` STAMPED from the authenticated subject, never client-set — the sender cannot be forged.
	notif := notificationsItem{Id: nid, From: sender, To: *in.To, Message: *in.Message, Status: "unread"} // created UNREAD
	notificationsItems.Set(strconv.Itoa(nid), notif)
	core.WriteJSON(w, 201, notif)
}

func NotificationsList(w http.ResponseWriter, r *http.Request) {
	who, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	// SCOPED read: only the recipient's rows ever leave the store, in id order (deterministic ×3)
	rows := []notificationsItem{}
	for _, n := range notificationsItems.All() {
		if n.To == who {
			rows = append(rows, n)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Id < rows[j].Id })
	// BOUNDED: the owner-scoped list rides the shared paginate seam (clamps to PageMax) so a busy inbox can never
	// become a soft-DoS/OOM ceiling — owner-scope applied FIRST, then the page is sliced.
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

func NotificationsRead(w http.ResponseWriter, r *http.Request) {
	who, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	nid, err := strconv.Atoi(r.PathValue("note_id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid notification id") // non-numeric id -> 422, never a silent miss
		return
	}
	notif, exists := notificationsItems.Get(strconv.Itoa(nid))
	if !exists || notif.To != who {
		core.WriteProblem(w, 404, "notification not found") // not-yours == not-found: no existence leak
		return
	}
	// monotonic + idempotent: "read" is TERMINAL — concurrent marks converge; nothing writes "unread" back
	notif.Status = "read"
	notificationsItems.Set(strconv.Itoa(nid), notif)
	core.WriteJSON(w, 200, notif)
}
