// Package invoices — a CONSERVED multi-line bill (package shape): create-draft + retrieve (this file) and the
// edit/finalize/pay/void/uncollectible lifecycle (lifecycle.go). The dangerous properties proven across the package:
// (1) CONSERVATION: the server RECOMPUTES every total — line amount = unit_amount × quantity, subtotal = Σ line
// amounts, total = subtotal + tax — and DISCARDS any client total, so a stored bill ALWAYS reconciles to its lines +
// tax. Every amount is capped at 2^53-1 and the per-line PRODUCT is bounded BEFORE the multiply (int64 would WRAP
// silently past 2^63 — so go pre-checks by DIVISION), as is the running subtotal/total: the sums cannot diverge ×3.
// (2) OWNER ISOLATION: a bill belongs to its creating caller (core.RequireIdentity). The store slot is the composite
// "<caller>\x1f<id>", so a by-id get for another caller's bill lands in a DIFFERENT slot -> 404, byte-indistinguishable
// from missing; the list is owner-FIELD-filtered.
// (3) FINALIZE-IMMUTABILITY: a draft is editable (PATCH); finalize is a ONE-WAY trap door draft -> open that assigns a
// monotonic, no-duplicate NUMBER and FREEZES the bill (PATCH on a non-draft -> 409). The number is minted OUTSIDE the
// transition do() (a next_id INSIDE it would re-enter the store), so it is monotonic + unique but not gapless.
// Every route requires the AUTHENTICATED caller — an anonymous create is bill fabrication; no token -> 401.
// The id is DERIVED — id = digest.ScopedKey("POST /invoices", caller, Idempotency-Key). Store names + the bill shape
// match the python/node impls.
package invoices

import (
	"encoding/json"
	"net/http"
	"strconv"

	"app/internal/core"
	"app/internal/parts/currency"
	"app/internal/parts/digest"
	"app/internal/parts/idempotent_claim"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

const invoicesRoute = "POST /invoices" // the route discriminator (per-route caller-private derived id/slot)
const maxAmount = (1 << 53) - 1        // the cross-language-safe amount ceiling (Node exact-int + no int64 sum-wrap)
const maxLines = 1000                  // a single bill's line list is COUNT-bounded (no unbounded record growth)

var invoicesKV = core.NewKV[string, invoiceRecord]("invoices_records")

type invoiceLine struct {
	Description string `json:"description"`
	Quantity    int    `json:"quantity"`
	UnitAmount  int    `json:"unit_amount"`
	Amount      int    `json:"amount"`
}

type invoiceRecord struct {
	Id          string        `json:"id"`
	Caller      string        `json:"caller"` // the OWNING caller — the composite slot is private to it
	Customer    string        `json:"customer"`
	Status      string        `json:"status"`
	Currency    string        `json:"currency"`
	LineItems   []invoiceLine `json:"line_items"`
	Subtotal    int           `json:"subtotal"`
	Tax         int           `json:"tax"`
	Total       int           `json:"total"`
	AmountPaid  int           `json:"amount_paid"`
	Number      *string       `json:"number"`       // nil until finalize -> JSON null
	FinalizedAt *int64        `json:"finalized_at"` // internal; never projected
	BodyHash    string        `json:"body_hash"`
}

type parsedLine struct {
	desc string
	q    int
	u    int
}

func invoicesDigest(customer, currencyCode string, tax int, lines []invoiceLine) string {
	// the central canonical body fingerprint (over the recomputed, U+FFFD-safe shape) — lines field-by-field, in order
	parts := []any{"customer", customer, "currency", currencyCode, "tax", tax, "lines", len(lines)}
	for i, li := range lines {
		parts = append(parts, "d"+strconv.Itoa(i), li.Description, "q"+strconv.Itoa(i), li.Quantity,
			"u"+strconv.Itoa(i), li.UnitAmount)
	}
	return digest.DigestHex(parts...)
}

// invoiceOut is the PUBLIC projection — the internal caller/body_hash/finalized_at bookkeeping never leaves the store.
func invoiceOut(v invoiceRecord) map[string]any {
	lines := []map[string]any{}
	for _, li := range v.LineItems {
		lines = append(lines, map[string]any{"description": li.Description, "quantity": li.Quantity,
			"unit_amount": li.UnitAmount, "amount": li.Amount})
	}
	return map[string]any{"id": v.Id, "number": v.Number, "customer": v.Customer, "status": v.Status,
		"currency": v.Currency, "line_items": lines, "subtotal": v.Subtotal, "tax": v.Tax, "total": v.Total,
		"amount_paid": v.AmountPaid}
}

// parseInvoiceFields — decode + PASS 1 (every field strict + range, mirrors python pydantic) + is_currency. SHARED by
// create + update (the body shape + validation are identical — the centralization rule). Writes the 422 + returns
// ok=false on failure. Returns the RAW customer (the caller sanitizes via recomputeInvoice) + the parsed lines.
func parseInvoiceFields(w http.ResponseWriter, raw json.RawMessage) (string, string, int, []parsedLine, bool) {
	var in struct {
		Customer  *string         `json:"customer"`
		Currency  *string         `json:"currency"`
		Tax       json.RawMessage `json:"tax"`
		LineItems []struct {
			Description *string         `json:"description"`
			Quantity    json.RawMessage `json:"quantity"`
			UnitAmount  json.RawMessage `json:"unit_amount"`
		} `json:"line_items"`
	}
	if json.Unmarshal(raw, &in) != nil {
		core.WriteProblem(w, 422, "invalid body")
		return "", "", 0, nil, false
	}
	if in.Customer == nil || !well_formed.IsWellFormed(*in.Customer) || in.Currency == nil ||
		!well_formed.IsWellFormed(*in.Currency) {
		core.WriteProblem(w, 422, "invalid body")
		return "", "", 0, nil, false
	}
	tax, taxok := core.RequireIntRaw(in.Tax) // RequireIntRaw on the RAW bytes: a quoted "0"/0.5/true/null all reject
	if !taxok || tax < 0 || tax > maxAmount {
		core.WriteProblem(w, 422, "invalid body")
		return "", "", 0, nil, false
	}
	if len(in.LineItems) < 1 || len(in.LineItems) > maxLines { // >=1 line, COUNT-bounded
		core.WriteProblem(w, 422, "invalid body")
		return "", "", 0, nil, false
	}
	parsed := []parsedLine{}
	for _, li := range in.LineItems {
		if li.Description == nil || !well_formed.IsWellFormed(*li.Description) {
			core.WriteProblem(w, 422, "invalid body")
			return "", "", 0, nil, false
		}
		q, qok := core.RequireIntRaw(li.Quantity)
		if !qok || q < 1 || q > maxAmount {
			core.WriteProblem(w, 422, "invalid body")
			return "", "", 0, nil, false
		}
		u, uok := core.RequireIntRaw(li.UnitAmount)
		if !uok || u < 1 || u > maxAmount {
			core.WriteProblem(w, 422, "invalid body")
			return "", "", 0, nil, false
		}
		parsed = append(parsed, parsedLine{desc: *li.Description, q: q, u: u})
	}
	if !currency.IsCurrency(*in.Currency) { // SEMANTIC: a CLOSED ISO-4217 set, not just well-formed
		core.WriteProblem(w, 422, "invalid body")
		return "", "", 0, nil, false
	}
	return *in.Customer, *in.Currency, tax, parsed, true
}

// recomputeInvoice — PASS 2: the CONSERVATION arithmetic. Derives every money field; bounds the per-line PRODUCT (by
// division — the int64 product would WRAP past 2^63) and the running subtotal/total. Echoed text is U+FFFD-sanitized.
func recomputeInvoice(w http.ResponseWriter, customer string, parsed []parsedLine, tax int) (string, []invoiceLine, int, int, bool) {
	lines := []invoiceLine{}
	subtotal := 0
	for _, p := range parsed {
		if p.u > maxAmount/p.q { // q>=1 (validated), so the division is safe; rejects unit_amount*quantity > maxAmount
			core.WriteProblem(w, 422, "a line amount exceeds the maximum")
			return "", nil, 0, 0, false
		}
		amount := p.u * p.q
		lines = append(lines, invoiceLine{Description: well_formed.MakeWellFormed(p.desc), Quantity: p.q,
			UnitAmount: p.u, Amount: amount})
		subtotal += amount
		if subtotal > maxAmount {
			core.WriteProblem(w, 422, "the subtotal exceeds the maximum")
			return "", nil, 0, 0, false
		}
	}
	total := subtotal + tax
	if total > maxAmount {
		core.WriteProblem(w, 422, "the total exceeds the maximum")
		return "", nil, 0, 0, false
	}
	return well_formed.MakeWellFormed(customer), lines, subtotal, total, true
}

func InvoicesCreate(w http.ResponseWriter, r *http.Request) {
	// PARSE -> AUTH -> VALIDATE (PASS1 + is_currency) -> SEMANTIC (idem-key) -> RECOMPUTE (PASS2) -> CLAIM. Identical ×3:
	// a malformed body is 422 (the JSON FRAME is decoded before auth in python (pydantic) + node (runtime) too), an
	// unauthenticated caller with a VALID body is 401, an authenticated caller's bad field is 422.
	raw, ok := core.DecodeJSON[json.RawMessage](w, r)
	if !ok {
		return
	}
	subject, ok := core.RequireIdentity(w, r) // AUTH: creating a bill needs an authenticated caller
	if !ok {
		return
	}
	customer, currencyCode, tax, parsed, ok := parseInvoiceFields(w, raw)
	if !ok {
		return
	}
	key, hasKey := r.Header["Idempotency-Key"]
	if !hasKey { // REQUIRED: the bill id is DERIVED from the key (no key, no id)
		core.WriteProblem(w, 422, "Idempotency-Key header is required")
		return
	}
	if len(key) > 1 { // a SINGLE opaque token; duplicate headers are ambiguous -> reject (×3 parity)
		core.WriteProblem(w, 422, "Idempotency-Key must be a single value")
		return
	}
	k := key[0]
	if !well_formed.IsWellFormed(k) {
		core.WriteProblem(w, 422, "Idempotency-Key must be non-empty with no control characters")
		return
	}
	safeCustomer, lines, subtotal, total, ok := recomputeInvoice(w, customer, parsed, tax)
	if !ok {
		return
	}
	bodyHash := invoicesDigest(safeCustomer, currencyCode, tax, lines)
	invID := digest.ScopedKey(invoicesRoute, subject, k) // the deterministic, caller-private bill id
	slot := subject + "\x1f" + invID                     // the owner-composite store slot (cross-caller -> 404)
	prior, settled := invoicesKV.Get(slot)               // fast path: a settled key never re-creates
	if !settled {
		rec := invoiceRecord{Id: invID, Caller: subject, Customer: safeCustomer, Status: "draft",
			Currency: currencyCode, LineItems: lines, Subtotal: subtotal, Tax: tax, Total: total,
			AmountPaid: 0, Number: nil, FinalizedAt: nil, BodyHash: bodyHash}
		prior = idempotent_claim.ClaimOnce(invoicesKV, slot, rec) // ONE atomic claim per slot (no double-create)
	}
	if prior.Caller != subject {
		// DEFENSE-IN-DEPTH: the composite slot isolates callers; a mismatch is structurally impossible, so REFUSE.
		core.WriteProblem(w, 409, "idempotency key is not owned by this caller")
		return
	}
	if prior.BodyHash != bodyHash {
		core.WriteProblem(w, 409, "idempotency key reused with a different body")
		return
	}
	core.WriteJSON(w, 201, invoiceOut(prior))
}

func InvoicesList(w http.ResponseWriter, r *http.Request) {
	subject, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	// SCOPED read: only the caller's OWN bills (owner-FIELD-filtered — the comparison runs on the STORED owner
	// field, never a client value), then a BOUNDED page over that stable-ordered set via the shared paginate part.
	mine := []invoiceRecord{}
	for _, v := range invoicesKV.All() {
		if v.Caller == subject {
			mine = append(mine, v)
		}
	}
	q := r.URL.Query()
	page, next, valid := paginate.Paginate(mine, q.Get("cursor"), q.Get("limit"))
	if !valid {
		core.WriteProblem(w, 422, "invalid cursor or limit")
		return
	}
	results := []map[string]any{}
	for _, v := range page {
		results = append(results, invoiceOut(v))
	}
	var nc any
	if next != "" {
		nc = next
	}
	core.WriteJSON(w, 200, map[string]any{"results": results, "next_cursor": nc})
}

func InvoicesGet(w http.ResponseWriter, r *http.Request) {
	subject, ok := core.RequireIdentity(w, r) // AUTH before path-422: a no-token control-char probe is 401, ×3
	if !ok {
		return
	}
	id := r.PathValue("invoice_id")
	if !well_formed.IsWellFormed(id) {
		core.WriteProblem(w, 422, "the invoice id must be non-empty with no control characters")
		return
	}
	rec, found := invoicesKV.Get(subject + "\x1f" + id)
	if !found {
		core.WriteProblem(w, 404, "invoice not found") // not-yours == not-found: another caller's bill is elsewhere
		return
	}
	core.WriteJSON(w, 200, invoiceOut(rec))
}
