// Package email — outbound email behind a provider PORT, two dangerous properties proven, matching python/node:
// (1) EXACTLY-ONCE DISPATCH: sending is idempotent on the Idempotency-Key — the claim is ONE atomic
// read-modify-write through (*KV).Do (ClaimOnce), so two processes racing one key produce ONE recorded message and
// the loser is served the winner. The slot is SCOPED to the authenticated caller (ScopedKey) — a key is PRIVATE.
// A same-key retry with ANY different message (recipient/subject/body/template) is 409 — never a silent re-send,
// never a dropped Bcc. (2) HEADER SAFETY: every header-bound field rejects CR/LF + control/NEL/line-separator
// (addresses via validEmail, the rendered subject via validHeaderText, AFTER template rendering) so a subject (or a
// template value rendered into it) can never open a second header line; we REJECT (422), stricter than silent
// sanitizers. OWNER-scoped (owner = RequireIdentity, never a body field): another caller's message is 404.
// Append-only; durable (a keyed send dedups after restart). Offline: the default backend RECORDS to the store (the
// record IS the outbox); a real provider is the emailDispatch swap-point (INTEROP.md). Every route auth'd.
package email_outbox

import (
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/idempotent_claim"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

const (
	emailRoute            = "POST /email_outbox/messages" // the dedup-slot discriminator (per-operation, owner-scoped slot)
	emailMaxSubjectBytes  = 998                    // RFC 5322 §2.1.1 line length — a hard protocol limit
	emailLocalCharset     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.!#$%&'*+/=?^_`{|}~-"
)

// an operator LIMIT: a positive int within the 2^53-safe range (so go/node/python AGREE ×3 — the env-knob overflow
// class); anything else falls back to the default. ×3-identical with python/node.
func emailEnvLimit(name string, def int) int {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 || int64(v) > (1<<53)-1 {
		return def
	}
	return v
}

var (
	emailMaxRecipients = emailEnvLimit("EMAIL_MAX_RECIPIENTS", 50)
	emailMaxBodyBytes  = emailEnvLimit("EMAIL_MAX_BODY_BYTES", 262144)
	emailMessages      = core.NewKV[string, emailMessage]("email_outbox_messages")
	emailLabel         = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	emailPlaceholder   = regexp.MustCompile(`\{\{([A-Za-z0-9_]+)\}\}`) // ASCII-explicit -> ×3 parity with py/node
)

// THE TEMPLATE REGISTRY (policy, code-reviewed) — id -> {subject, html, text}; same data + same render ×3. NEVER empty.
var emailTemplates = map[string]map[string]string{
	"verify_email":   {"subject": "Verify your email address", "html": "<p>Hi {{name}},</p><p>Confirm your address: {{link}}</p>", "text": "Hi {{name}},\nConfirm your address: {{link}}"},
	"reset_password": {"subject": "Reset your password", "html": "<p>Hi {{name}},</p><p>Reset your password: {{link}}</p>", "text": "Hi {{name}},\nReset your password: {{link}}"},
	"notify":         {"subject": "New message: {{title}}", "html": "<p>{{body}}</p>", "text": "{{body}}"},
}

type emailMessage struct {
	Id        int      `json:"id"`
	Owner     string   `json:"owner"`
	From      string   `json:"from"`
	To        []string `json:"to"`
	Cc        []string `json:"cc"`
	Bcc       []string `json:"bcc"`
	ReplyTo   []string `json:"reply_to"`
	Subject   string   `json:"subject"`
	Html      string   `json:"html"`
	Text      string   `json:"text"`
	CreatedAt int64    `json:"created_at"`
	BodyHash  string   `json:"body_hash"`
}

// validEmail — a strict boundary validator: a SUPERSET of the connector email_domain extractor + RFC 5321 length
// caps + the WHATWG dot-atom charset. Surrounding whitespace is REJECTED (not trimmed — trimming differs ×3). All
// valid addresses are ASCII, so len (bytes) == code points for any address that could pass — the decision is ×3.
func validEmail(s string) bool {
	if s == "" || len(s) > 254 || strings.Count(s, "@") != 1 {
		return false
	}
	at := strings.IndexByte(s, '@')
	local, domain := s[:at], s[at+1:]
	if local == "" || domain == "" || len(local) > 64 || len(domain) > 255 {
		return false
	}
	for _, c := range local {
		if !strings.ContainsRune(emailLocalCharset, c) {
			return false
		}
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, lbl := range labels {
		if !emailLabel.MatchString(lbl) {
			return false
		}
	}
	return true
}

// validHeaderText — the header-injection wall: reject CR/LF + the rest of C0, DEL, C1 (incl. NEL) and U+2028/U+2029.
func validHeaderText(s string) bool {
	for _, c := range s { // range iterates runes (code points) -> matches python's per-codepoint check
		if c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F) || c == 0x2028 || c == 0x2029 {
			return false
		}
	}
	return true
}

// emailRender — scan the TEMPLATE for {{key}} (never iterate data -> deterministic ×3); a placeholder with no data
// value -> ok=false (a 422). Single-pass (a substituted value is not re-scanned).
func emailRender(tpl string, data map[string]string) (string, bool) {
	complete := true
	out := emailPlaceholder.ReplaceAllStringFunc(tpl, func(m string) string {
		key := m[2 : len(m)-2] // strip {{ }}
		v, ok := data[key]
		if !ok {
			complete = false
			return ""
		}
		return v
	})
	return out, complete
}

func emailH(s string) string { return digest.DigestHex(s) } // pre-hash one field to fixed colon-free hex

func emailHL(xs []string) string { // pre-hash each list element -> injective (the scoped_key idiom)
	parts := make([]any, len(xs))
	for i, x := range xs {
		parts[i] = emailH(x)
	}
	return digest.DigestHex(parts...)
}

// emailBodyHash — the fingerprint over EVERY message-determining REQUEST field (digest_hex joins with ':' and is NOT
// injective for free text, so each variable-length field is PRE-HASHED first). An added bcc / a changed data value
// all drift the hash -> a same-key reuse with any different message is 409.
func emailBodyHash(frm string, to, cc, bcc, reply []string, subject, html, text, tid string, data map[string]string) string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	dparts := make([]any, 0, len(keys)*2)
	for _, k := range keys {
		dparts = append(dparts, emailH(k), emailH(data[k]))
	}
	return digest.DigestHex("from", emailH(frm), "to", emailHL(to), "cc", emailHL(cc), "bcc", emailHL(bcc),
		"reply", emailHL(reply), "subj", emailH(subject), "html", emailH(html), "text", emailH(text),
		"tid", emailH(tid), "data", digest.DigestHex(dparts...))
}

// emailDispatch — the offline fake backend: the stored record IS the sent message (record-to-store). A real backend
// transmits here; the INTEROP swap-point. Called ONLY on a fresh claim, so a retried/raced send never sends twice.
func emailDispatch(m emailMessage) {}

func emailPublic(m emailMessage) map[string]any {
	return map[string]any{"id": m.Id, "from": m.From, "to": m.To, "cc": m.Cc, "bcc": m.Bcc,
		"reply_to": m.ReplyTo, "subject": m.Subject, "created_at": m.CreatedAt}
}

func emailNonEmpty(xs []string) []string { // JSON omits an absent list as nil; normalize to [] so the stored shape matches py/node
	if xs == nil {
		return []string{}
	}
	return xs
}

func EmailOutboxSend(w http.ResponseWriter, r *http.Request) {
	// PARSE -> AUTH -> SEMANTIC (×3 with python's body-parse-before-Depends): a typed decode rejects a numeric
	// recipient / a non-string subject / a non-string template value as 422; a no-token caller is 401.
	in, ok := core.DecodeJSON[struct {
		From     *string  `json:"from"`
		To       []string `json:"to"`
		Cc       []string `json:"cc"`
		Bcc      []string `json:"bcc"`
		ReplyTo  []string `json:"reply_to"`
		Subject  *string  `json:"subject"`
		Html     *string  `json:"html"`
		Text     *string  `json:"text"`
		Template *struct {
			Id   string            `json:"id"`
			Data map[string]string `json:"data"`
		} `json:"template"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if in.From == nil || !validEmail(*in.From) {
		core.WriteProblem(w, 422, "from is not a valid email address")
		return
	}
	for _, group := range [][]string{in.To, in.Cc, in.Bcc, in.ReplyTo} {
		for _, addr := range group {
			if !validEmail(addr) {
				core.WriteProblem(w, 422, "a recipient address is not valid")
				return
			}
		}
	}
	recipients := len(in.To) + len(in.Cc) + len(in.Bcc)
	if len(in.To) == 0 {
		core.WriteProblem(w, 422, "to must contain at least one recipient")
		return
	}
	if recipients > emailMaxRecipients {
		core.WriteProblem(w, 422, "too many recipients")
		return
	}
	seen := map[string]bool{}
	for _, group := range [][]string{in.To, in.Cc, in.Bcc} {
		for _, a := range group {
			if seen[a] {
				core.WriteProblem(w, 422, "a recipient address is duplicated across to, cc and bcc")
				return
			}
			seen[a] = true
		}
	}
	hasTpl := in.Template != nil
	hasRaw := in.Subject != nil || in.Html != nil || in.Text != nil
	if hasTpl && hasRaw {
		core.WriteProblem(w, 422, "provide either a template or subject and body, not both")
		return
	}
	var subject, html, text, bodyHash string
	data := map[string]string{}
	if hasTpl {
		tpl, known := emailTemplates[in.Template.Id]
		if !known {
			core.WriteProblem(w, 422, "unknown template")
			return
		}
		// CONTAIN the data values BEFORE render + fingerprint (identity in go — json already substitutes U+FFFD —
		// but kept parallel with py/node where a lone surrogate would otherwise break the UTF-8 hash).
		if in.Template.Data != nil {
			for k, v := range in.Template.Data {
				data[k] = well_formed.MakeWellFormed(v)
			}
		}
		var s1, s2, s3 bool
		subject, s1 = emailRender(tpl["subject"], data)
		html, s2 = emailRender(tpl["html"], data)
		text, s3 = emailRender(tpl["text"], data)
		if !s1 || !s2 || !s3 {
			core.WriteProblem(w, 422, "template variable not provided")
			return
		}
		subject, html, text = well_formed.MakeWellFormed(subject), well_formed.MakeWellFormed(html), well_formed.MakeWellFormed(text)
		bodyHash = emailBodyHash(*in.From, in.To, in.Cc, in.Bcc, in.ReplyTo, "", "", "", in.Template.Id, data)
	} else {
		if in.Subject == nil || (in.Html == nil && in.Text == nil) {
			core.WriteProblem(w, 422, "a raw send needs a subject and at least one of html or text")
			return
		}
		subject = well_formed.MakeWellFormed(*in.Subject)
		if in.Html != nil {
			html = well_formed.MakeWellFormed(*in.Html)
		}
		if in.Text != nil {
			text = well_formed.MakeWellFormed(*in.Text)
		}
		bodyHash = emailBodyHash(*in.From, in.To, in.Cc, in.Bcc, in.ReplyTo, subject, html, text, "", data)
	}
	// RENDER-THEN-VALIDATE: header-safety + bounds on the CONTAINED, rendered output.
	if !validHeaderText(subject) {
		core.WriteProblem(w, 422, "subject must not contain control characters or line breaks")
		return
	}
	if len(subject) > emailMaxSubjectBytes {
		core.WriteProblem(w, 422, "subject is too long")
		return
	}
	if len(html)+len(text) > emailMaxBodyBytes { // go strings are UTF-8 bytes -> octet count, matches py/node encode-len
		core.WriteProblem(w, 422, "message body is too large")
		return
	}
	createdAt := core.TestNow(r)
	build := func(eid int) emailMessage {
		return emailMessage{Id: eid, Owner: owner, From: *in.From, To: emailNonEmpty(in.To), Cc: emailNonEmpty(in.Cc),
			Bcc: emailNonEmpty(in.Bcc), ReplyTo: emailNonEmpty(in.ReplyTo), Subject: subject, Html: html, Text: text,
			CreatedAt: createdAt, BodyHash: bodyHash}
	}
	key, hasKey := r.Header["Idempotency-Key"]
	if !hasKey { // no key -> no dedupe (opt-in)
		eid := core.NextID("email_outbox_message")
		rec := build(eid)
		emailMessages.Set(strconv.Itoa(eid), rec)
		emailDispatch(rec)
		core.WriteJSON(w, 201, emailPublic(rec))
		return
	}
	if len(key) > 1 {
		core.WriteProblem(w, 422, "Idempotency-Key must be a single value")
		return
	}
	if !well_formed.IsWellFormed(key[0]) {
		core.WriteProblem(w, 422, "Idempotency-Key must be non-empty with no control characters")
		return
	}
	scoped := digest.ScopedKey(emailRoute, owner, key[0])
	prior, settled := emailMessages.Get(scoped)
	if !settled {
		eid := core.NextID("email_outbox_message") // mint BEFORE the claim (a race loser's id is a harmless gap)
		rec := build(eid)
		prior = idempotent_claim.ClaimOnce(emailMessages, scoped, rec)
		if prior.Id == eid { // I won the claim -> send ONCE
			emailDispatch(prior)
		}
	}
	if prior.Owner != owner {
		core.WriteProblem(w, 409, "Idempotency-Key is not owned by this caller")
		return
	}
	if prior.BodyHash != bodyHash {
		core.WriteProblem(w, 409, "Idempotency-Key reused with a different message")
		return
	}
	core.WriteJSON(w, 201, emailPublic(prior))
}

func EmailOutboxList(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	rows := []emailMessage{}
	for _, m := range emailMessages.All() {
		if m.Owner == owner { // OWNER-scoped: only the caller's own sends ever leave the store
			rows = append(rows, m)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Id < rows[j].Id })
	views := make([]map[string]any, len(rows))
	for i, m := range rows {
		views[i] = emailPublic(m)
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

func EmailOutboxGet(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	id, err := strconv.Atoi(r.PathValue("message_id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid message id")
		return
	}
	// unbounded-safe: a single-record lookup by id (returns at most one row); OWNER-scoped — not-yours == 404
	for _, m := range emailMessages.All() {
		if m.Id == id && m.Owner == owner {
			core.WriteJSON(w, 200, emailPublic(m))
			return
		}
	}
	core.WriteProblem(w, 404, "message not found")
}
