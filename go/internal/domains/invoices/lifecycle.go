// The invoices lifecycle TRANSITIONS — edit-draft (PATCH), finalize (the 2-step monotonic legal number + the
// immutability trap door), and the terminal pay/void/uncollectible state machine. The package doc + the shared types
// and helpers (invoiceRecord, invoicesKV, parseInvoiceFields, recomputeInvoice, invoicesDigest, invoiceOut) live in
// invoices.go. Each transition is ONE atomic (*KV).Do — the state read, the check, and the write happen INSIDE the
// callback against `cur` (NEVER a value read before Do), so two processes racing serialize on the slot.
package invoices

import (
	"encoding/json"
	"fmt"
	"net/http"

	"app/internal/core"
	"app/internal/parts/well_formed"
)

func InvoicesUpdate(w http.ResponseWriter, r *http.Request) {
	// DRAFT-ONLY edit (the IMMUTABILITY trap door: a finalized bill is FROZEN, 409). Re-validate + RECOMPUTE BEFORE the
	// do(), then atomically check status=="draft" and replace the editable fields. No Idempotency-Key (the bill is
	// addressed by its path id; a PATCH is idempotent by nature). Order: parse -> recompute -> id -> do (matches python).
	raw, ok := core.DecodeJSON[json.RawMessage](w, r)
	if !ok {
		return
	}
	subject, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	customer, currencyCode, tax, parsed, ok := parseInvoiceFields(w, raw)
	if !ok {
		return
	}
	safeCustomer, lines, subtotal, total, ok := recomputeInvoice(w, customer, parsed, tax)
	if !ok {
		return
	}
	id := r.PathValue("invoice_id")
	if !well_formed.IsWellFormed(id) {
		core.WriteProblem(w, 422, "the invoice id must be non-empty with no control characters")
		return
	}
	bodyHash := invoicesDigest(safeCustomer, currencyCode, tax, lines)
	code := 0
	var rec invoiceRecord
	invoicesKV.Do(subject+"\x1f"+id, func(cur invoiceRecord, exists bool) (invoiceRecord, bool) {
		if !exists {
			code = 404
			return cur, false
		}
		if cur.Status != "draft" { // IMMUTABILITY: only a draft is editable
			code = 409
			return cur, false
		}
		cur.Customer = safeCustomer
		cur.Currency = currencyCode
		cur.LineItems = lines
		cur.Subtotal = subtotal
		cur.Tax = tax
		cur.Total = total
		cur.BodyHash = bodyHash
		rec = cur
		return cur, true
	})
	if code == 404 {
		core.WriteProblem(w, 404, "invoice not found")
		return
	}
	if code == 409 {
		core.WriteProblem(w, 409, "only a draft invoice can be edited")
		return
	}
	core.WriteJSON(w, 200, invoiceOut(rec))
}

func InvoicesFinalize(w http.ResponseWriter, r *http.Request) {
	// FINALIZE = the one-way trap door draft -> open + assign the legal NUMBER. Minting INSIDE the transition do() would
	// RE-ENTER the store (the reentry guard fails ×3); minting BEFORE a possible 409 would burn a number -> a gap. So a
	// TWO-STEP: (1) an atomic do() flips draft->open WITHOUT minting; (2) only after it commits, mint NextID OUTSIDE the
	// callback and attach via a 2nd do(). A crash between leaves an open bill with number=null, which a re-finalize
	// COMPLETES (idempotent). Two processes racing -> exactly ONE number attached (the other's mint is a rare owned gap).
	subject, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	id := r.PathValue("invoice_id")
	if !well_formed.IsWellFormed(id) {
		core.WriteProblem(w, 422, "the invoice id must be non-empty with no control characters")
		return
	}
	slot := subject + "\x1f" + id
	now := core.TestNow(r)
	code := 0
	var rec invoiceRecord
	invoicesKV.Do(slot, func(cur invoiceRecord, exists bool) (invoiceRecord, bool) {
		if !exists {
			code = 404
			return cur, false
		}
		if cur.Status == "draft" { // the transition: freeze the content, stamp finalized_at, NO mint
			cur.Status = "open"
			cur.FinalizedAt = &now
			rec = cur
			return cur, true
		}
		if cur.Status == "open" { // already finalized (number set) OR half-finalized (number null)
			rec = cur
			return cur, false
		}
		code = 409 // paid / void / uncollectible -> past finalize, not re-finalizable
		return cur, false
	})
	if code == 404 {
		core.WriteProblem(w, 404, "invoice not found")
		return
	}
	if code == 409 {
		core.WriteProblem(w, 409, "only a draft invoice can be finalized")
		return
	}
	if rec.Number == nil { // mint OUTSIDE the do() (reentrancy-safe), then attach atomically
		minted := fmt.Sprintf("INV-%06d", core.NextID("invoices_number_"+subject))
		invoicesKV.Do(slot, func(cur invoiceRecord, exists bool) (invoiceRecord, bool) {
			if !exists || cur.Status != "open" || cur.Number != nil {
				if exists {
					rec = cur // another process attached first -> use the stored number (the minted one is a gap)
				}
				return cur, false
			}
			cur.Number = &minted
			rec = cur
			return cur, true
		})
	}
	core.WriteJSON(w, 200, invoiceOut(rec))
}

// ── the TERMINAL transitions — a finalized (open) bill moves ONCE to paid / void / uncollectible. Each is ONE
// atomic Do; idempotent on its own target, 409 from any other. amount_paid == total IFF paid (conservation: a bill is
// fully paid or written off, never partial). The three share ONE helper. ────────────────────────────────────────────

func invoicesTerminal(w http.ResponseWriter, r *http.Request, target string, pay bool) {
	subject, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	id := r.PathValue("invoice_id")
	if !well_formed.IsWellFormed(id) {
		core.WriteProblem(w, 422, "the invoice id must be non-empty with no control characters")
		return
	}
	code := 0
	var rec invoiceRecord
	invoicesKV.Do(subject+"\x1f"+id, func(cur invoiceRecord, exists bool) (invoiceRecord, bool) {
		if !exists {
			code = 404
			return cur, false
		}
		if cur.Status == target { // idempotent re-application of the SAME transition (no double-pay)
			rec = cur
			return cur, false
		}
		if cur.Status != "open" || cur.Number == nil { // only a FULLY-finalized (NUMBERED) bill transitions — a torn
			code = 409 // finalize (open, number=nil, the crash/race window) 409s until a re-finalize completes its number
			return cur, false
		}
		cur.Status = target
		if pay {
			cur.AmountPaid = cur.Total // CONSERVATION: a paid bill records its FULL total (never partial)
		}
		rec = cur
		return cur, true
	})
	if code == 404 {
		core.WriteProblem(w, 404, "invoice not found")
		return
	}
	if code == 409 {
		core.WriteProblem(w, 409, "invoice cannot transition to "+target+" from its current state")
		return
	}
	core.WriteJSON(w, 200, invoiceOut(rec))
}

// InvoicesPay — mark-paid: the bill is fully paid (amount_paid = total) WITHOUT importing the payments
// domain. open -> paid; idempotent; a draft/void/uncollectible bill -> 409.
func InvoicesPay(w http.ResponseWriter, r *http.Request) { invoicesTerminal(w, r, "paid", true) }

// InvoicesVoid — void a finalized bill that will NOT be collected. open -> void; idempotent; else 409.
func InvoicesVoid(w http.ResponseWriter, r *http.Request) { invoicesTerminal(w, r, "void", false) }

// InvoicesMarkUncollectible — mark a finalized bill as bad debt. open -> uncollectible; idempotent; else 409.
func InvoicesMarkUncollectible(w http.ResponseWriter, r *http.Request) {
	invoicesTerminal(w, r, "uncollectible", false)
}
