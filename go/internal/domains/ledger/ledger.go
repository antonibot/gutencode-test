// Package ledger — double-entry: every tx balances (sum == 0, >= 2 entries) else 422; append-only (no
// update/delete route); balances DERIVED never stored. ADMIN-ONLY: both routes require the 'admin' role (the
// core RequireAdmin seam) — financial infra with no per-account owner model. The precedence is PARSE -> AUTH ->
// SEMANTIC, identical ×3: the body is decoded as raw JSON FIRST (only malformed JSON / a 413 fails here), THEN auth
// runs, THEN the strict per-field validation (json.Number + RequireInt rejects "100"/100.5/true) — so an
// unauthenticated caller with an ill-typed body gets 401, never a 422 that leaks the body shape. Validation runs
// BEFORE the id mint, so a rejected tx consumes no tx id. Store namespaces match the python/node impls.
package ledger

import (
	"encoding/json"
	"net/http"
	"strconv"

	"app/internal/core"
)

type ledgerEntry struct {
	AccountId int `json:"account_id"`
	Amount    int `json:"amount"`
}

type ledgerTx struct {
	Id      int           `json:"id"`
	Entries []ledgerEntry `json:"entries"`
}

// the WHOLE balanced transaction is ONE atomic row (a crash can't leave a half-written, unbalanced tx).
var ledgerTxns = core.NewKV[string, ledgerTx]("ledger_tx")

func LedgerPost(w http.ResponseWriter, r *http.Request) {
	// PARSE: accept ANY well-formed JSON; only malformed JSON / a 413 fails here. Per-field type checks are SEMANTIC
	// and run AFTER auth (below), exactly like python's pydantic — so an unauthenticated ill-typed body is 401, ×3.
	raw, ok := core.DecodeJSON[json.RawMessage](w, r)
	if !ok {
		return
	}
	if _, ok := core.RequireAdmin(w, r); !ok { // AUTH: admin-only, BEFORE any semantic validation
		return
	}
	// SEMANTIC: ints are decoded as json.Number then RequireInt'd, so "100"/100.5/true are rejected HERE (after auth).
	var in struct {
		Entries []struct {
			AccountId json.RawMessage `json:"account_id"`
			Amount    json.RawMessage `json:"amount"`
		} `json:"entries"`
	}
	if json.Unmarshal(raw, &in) != nil { // a shape mismatch (entries:"nope", an entry that isn't an object) is 422 here
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	if len(in.Entries) < 2 {
		core.WriteProblem(w, 422, "double-entry requires >= 2 entries")
		return
	}
	sum := 0
	entries := make([]ledgerEntry, 0, len(in.Entries))
	for _, e := range in.Entries {
		// RequireIntRaw on the RAW bytes rejects a QUOTED "100" as well as 100.5/true/null/missing — json.Number
		// would have accepted "100" as 100 (diverging from python StrictInt + node isStrictInt). Strict ×3.
		aid, aok := core.RequireIntRaw(e.AccountId)
		amt, mok := core.RequireIntRaw(e.Amount)
		if !aok || !mok {
			core.WriteProblem(w, 422, "invalid body")
			return
		}
		sum += amt
		entries = append(entries, ledgerEntry{AccountId: aid, Amount: amt})
	}
	if sum != 0 {
		core.WriteProblem(w, 422, "transaction does not balance")
		return
	}
	tid := core.NextID("ledger_tx") // atomic, durable; a crash before the write below loses the id (a harmless gap)
	ledgerTxns.Set(strconv.Itoa(tid), ledgerTx{Id: tid, Entries: entries}) // the WHOLE balanced tx in ONE atomic row
	core.WriteJSON(w, 201, map[string]any{"id": tid, "entries": entries})
}

func LedgerBalance(w http.ResponseWriter, r *http.Request) {
	if _, ok := core.RequireAdmin(w, r); !ok { // ADMIN-ONLY: a balance reveals financial position (AUTH before path-422)
		return
	}
	id, err := strconv.Atoi(r.PathValue("account_id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid account id") // a non-numeric id is a 422, never a silent account 0
		return
	}
	derived := 0
	// unbounded-safe: scalar aggregate — sums the account's entries into a single balance, returns no collection; the O(n) scan is the documented store-swap-at-scale limit (a running-balance row is the Postgres upgrade).
	for _, tx := range ledgerTxns.All() {
		for _, e := range tx.Entries {
			if e.AccountId == id {
				derived += e.Amount // DERIVED from the stored transactions, never stored
			}
		}
	}
	core.WriteJSON(w, 200, map[string]any{"account_id": id, "balance": derived})
}
