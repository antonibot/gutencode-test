// Package audit_log — an append-only, tamper-evident evidence log (the hash-chain shape). Every event's hash is
// sha256 over the COMPLETE record (prev · id · at · actor · action — the two well_formed fields pre-hashed so the
// join stays injective), rooted at GENESIS, so editing ANY past field breaks every later link. The dangerous
// property is CHAIN INTEGRITY: the append is ONE atomic read-modify-write on the chain head
// through (*KV).Do — two processes appending concurrently get sequential ids on one chain, never a fork.
// Immutability is by construction (no update or delete route). /verify re-derives the whole chain and reports
// ANY damage loudly — including self-damage (a crash between head advance and event write leaves a visible
// hole; an evidence log must show its own wounds). Store names and shapes match the python/node impls.
//
// WRITES ARE SERVICE-ONLY, THE DISCLOSING READ ADMIN-ONLY: an anonymous append is log-poisoning (the chain
// stays "valid" over forged rows) and the event LIST discloses every subject's events. Append is gated by the
// trusted SERVICE seam (core.RequireService) — events are ingested by app services on a user's behalf, not posted
// by end users; List requires the 'admin' role (core.RequireAdmin). Append is body-only, so the precedence is
// PARSE -> AUTH -> SEMANTIC: decode the body as raw JSON FIRST (drains it + handles 413/malformed JSON), THEN
// RequireService, THEN unmarshal+validate the action — so an unauthenticated ill-typed body is 401, identical ×3.
// List (no body) calls RequireAdmin first. Verify stays OPEN: the integrity probe returns only {valid, count,
// detail} — no event contents.
package audit_log

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

type auditLogHead struct {
	Id   int    `json:"id"`
	Hash string `json:"hash"`
}

type auditLogEvent struct {
	Id     int    `json:"id"`
	At     int    `json:"at"`     // WHEN — seconds since epoch (UTC), from the core clock seam; covered by the hash
	Actor  string `json:"actor"`  // WHO — the subject the trusted service logs on behalf of
	Action string `json:"action"` // WHAT
	Prev   string `json:"prev"`
	Hash   string `json:"hash"`
}

var (
	auditLogChain  = core.NewKV[string, auditLogHead]("audit_log_chain")
	auditLogEvents = core.NewKV[string, auditLogEvent]("audit_log_events")
)

func auditLogLink(prev string, id, at int, actor, action string) string {
	// the chain link over the COMPLETE record, INJECTIVE: prev (64-hex/GENESIS), id+at (digits) are colon-free, and
	// the two ADVERSARIAL well_formed fields (actor, action — can contain ':') are PRE-HASHED to colon-free 64-hex
	// FIRST, so DigestHex's ':'-join stays unambiguous (the delimiter lesson).
	return digest.DigestHex(prev, id, at, digest.DigestHex(actor), digest.DigestHex(action))
}

func AuditLogAppend(w http.ResponseWriter, r *http.Request) {
	// mutation-auth: service — audit events are ingested by the trusted backend (a SERVICE) on a user's behalf,
	// never posted by end users, so the append is gated by core.RequireService, NOT RequireAdmin.
	// PARSE: decode the body as RAW JSON FIRST (only malformed JSON / a 413 fails here, and the body must be
	// drained before any reply) — the action's type/value check is SEMANTIC and runs AFTER auth, so an
	// unauthenticated ill-typed body (e.g. {"action": 7}) is 401 not 422, exactly like python's Depends, ×3.
	in, ok := core.DecodeJSON[struct {
		Actor  *json.RawMessage `json:"actor"`
		Action *json.RawMessage `json:"action"`
	}](w, r)
	if !ok {
		return
	}
	if _, ok := core.RequireService(w, r); !ok { // AUTH: trusted service caller, BEFORE the semantic field check
		return
	}
	var actor, action string
	if in.Actor == nil || json.Unmarshal(*in.Actor, &actor) != nil || !well_formed.IsWellFormed(actor) ||
		in.Action == nil || json.Unmarshal(*in.Action, &action) != nil || !well_formed.IsWellFormed(action) {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	// WHEN: the timestamp comes from the core CLOCK seam — deterministic under APP_TEST_CLOCK (?now=), the real
	// wall clock in prod (a client can't forge prod time). COVERED BY THE HASH below, so a backdate is tamper-evident.
	at := int(core.TestNow(r))
	// THE APPEND: one atomic claim on the head — the id is chain-derived (head.id + 1) and computed INSIDE the
	// exclusive transaction, so two processes can never build on the same predecessor. The fn stays PURE; the
	// event row is written right after the head advances.
	var event auditLogEvent
	auditLogChain.Do("head", func(head auditLogHead, exists bool) (auditLogHead, bool) {
		prevID, prevHash := 0, "GENESIS"
		if exists {
			prevID, prevHash = head.Id, head.Hash
		}
		event = auditLogEvent{Id: prevID + 1, At: at, Actor: actor, Action: action, Prev: prevHash,
			Hash: auditLogLink(prevHash, prevID+1, at, actor, action)}
		return auditLogHead{Id: event.Id, Hash: event.Hash}, true
	})
	auditLogEvents.Set(strconv.Itoa(event.Id), event)
	core.WriteJSON(w, 201, event)
}

func AuditLogList(w http.ResponseWriter, r *http.Request) {
	// ADMIN-ONLY read (no body): the full event list discloses every subject's events — a read the mutation gate
	// won't catch, so it is hand-gated. RequireAdmin FIRST, before pagination; no token 401, non-admin 403 (auth
	// precedence PRESERVED). Verify stays OPEN. BOUNDED via the shared paginate part — never an unbounded full
	// dump. Events are the hash-chain rows in stable id order (All() is rowid-stable == monotonic id order).
	if _, ok := core.RequireAdmin(w, r); !ok {
		return
	}
	// unscoped-read: admin — the event log is GLOBAL by design (every subject's events); RequireAdmin above is the
	// explicit privileged gate. The whole hash-chain IS the trail — there is no per-caller owner field.
	q := r.URL.Query()
	page, next, valid := paginate.Paginate(auditLogEvents.All(), q.Get("cursor"), q.Get("limit"))
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

func AuditLogVerify(w http.ResponseWriter, r *http.Request) {
	// read-scope: public — integrity probe, returns only {valid, count, detail}, never event contents (already documented as intentionally open).
	// re-derive the WHOLE chain from GENESIS: every id 1..head present, every link correct. Any deviation —
	// a tampered action, a missing event (crash damage), a forged head — is reported loudly, never smoothed.
	head, hasHead := auditLogChain.Get("head")
	count := 0
	if hasHead {
		count = head.Id
	}
	prev := "GENESIS"
	for id := 1; id <= count; id++ {
		event, exists := auditLogEvents.Get(strconv.Itoa(id))
		if !exists {
			core.WriteJSON(w, 200, map[string]any{"valid": false, "count": count,
				"detail": fmt.Sprintf("event %d missing (hole in the chain)", id)})
			return
		}
		if event.Prev != prev || event.Hash != auditLogLink(prev, id, event.At, event.Actor, event.Action) {
			core.WriteJSON(w, 200, map[string]any{"valid": false, "count": count,
				"detail": fmt.Sprintf("chain broken at event %d", id)})
			return
		}
		prev = event.Hash
	}
	if hasHead && head.Hash != prev {
		core.WriteJSON(w, 200, map[string]any{"valid": false, "count": count, "detail": "head does not match the derived chain"})
		return
	}
	core.WriteJSON(w, 200, map[string]any{"valid": true, "count": count, "detail": "chain intact"})
}
