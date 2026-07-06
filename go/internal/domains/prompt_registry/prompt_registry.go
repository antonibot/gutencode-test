// Package prompt_registry — a versioned, IMMUTABLE prompt-template store with movable deployment LABELS (rollback)
// and a deterministic {{variable}} render. Matches python/node; durable. See prompt_registry.py for the full
// contract. PIN-HONESTY: (1) IMMUTABILITY — each POST mints a NEW monotonic version per (owner,name) through (*KV).Do;
// a published version's (template, content_hash) is frozen; append-only (no update/delete). (2) LABEL NO-DRIFT — a
// label is a movable pointer to ONE version; creating versions never moves an existing label (no virtual `latest`, no
// silent default); rollback resolves the old version's EXACT content. (3) CONTENT PIN — content_hash = DigestHex over
// the ONE contained template (injective by construction); server-derived (a smuggled content_hash is discarded).
// (4) RENDER — {{var}} from a string->string data map, ASCII [A-Za-z0-9_] placeholder (NOT \w), scan the template not
// the data (x3), single-pass (a value can't inject a 2nd var; a self-ref terminates), missing var -> 422, data values
// CONTAINED before substitution, rendered output bounded (the amplification cap). (5) OWNER-SCOPED — owner =
// RequireIdentity; the composite key <owner>\x1f<name> stops cross-owner clobber; not-yours == 404. Names/labels are
// IsWellFormed (control-char-free) THEN MakeWellFormed (UTF-8-safe key + echo). Same names + DECISIONS in all 3 langs.
package prompt_registry

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/env_int"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

type promptRecord struct {
	Owner         string         `json:"owner"`
	Name          string         `json:"name"`
	LatestVersion int            `json:"latest_version"`
	Labels        map[string]int `json:"labels"` // label -> version (a movable one-to-one pointer)
	CreatedAt     int64          `json:"created_at"`
}

type versionRow struct {
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	Version     int    `json:"version"`
	Template    string `json:"template"`
	ContentHash string `json:"content_hash"`
	CreatedAt   int64  `json:"created_at"`
}

var (
	prPrompts     = core.NewKV[string, promptRecord]("prompt_registry_prompts")
	prVersions    = core.NewKV[string, versionRow]("prompt_registry_versions")
	prPlaceholder = regexp.MustCompile(`\{\{([A-Za-z0-9_]+)\}\}`) // ASCII-explicit -> x3 parity with py/node
)

func prMaxVersions() int      { return env_int.EnvInt(os.Getenv("PROMPT_REGISTRY_MAX_VERSIONS"), 1000, 1) } // reject past cap (preserve pins)
func prMaxLabels() int        { return env_int.EnvInt(os.Getenv("PROMPT_REGISTRY_MAX_LABELS"), 50, 1) }
func prMaxTemplateBytes() int { return env_int.EnvInt(os.Getenv("PROMPT_REGISTRY_MAX_TEMPLATE_BYTES"), 65536, 1) }
func prMaxRenderedBytes() int { return env_int.EnvInt(os.Getenv("PROMPT_REGISTRY_MAX_RENDERED_BYTES"), 262144, 1) } // amplification cap

func prPKey(owner, name string) string { return owner + "\x1f" + name } // owner-partitioned: B can't clobber A's name
func prVKey(owner, name string, version int) string {
	return owner + "\x1f" + name + "\x1f" + strconv.Itoa(version)
}

// prRender — scan the TEMPLATE for {{key}} (never iterate data -> deterministic x3); a placeholder with no data value
// -> ok=false (a 422). Single-pass (a substituted value is not re-scanned -> a self-ref terminates). Go strings are
// always valid UTF-8 so MakeWellFormed on the data values (by the caller) is identity here, kept parallel with py/node.
func prRender(template string, data map[string]string) (string, bool) {
	complete := true
	out := prPlaceholder.ReplaceAllStringFunc(template, func(m string) string {
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

func prPublicVersion(rec versionRow) map[string]any {
	return map[string]any{"name": rec.Name, "version": rec.Version, "template": rec.Template,
		"content_hash": rec.ContentHash, "created_at": rec.CreatedAt}
}

// prCleanName — IsWellFormed (reject a control char < 0x20 so the \x1f key separator can't be forged) -> 422; then
// MakeWellFormed (contain a lone surrogate so the key + echo are UTF-8-safe — identity in go). Returns ("", false) on reject.
func prCleanName(w http.ResponseWriter, raw, what string) (string, bool) {
	if !well_formed.IsWellFormed(raw) {
		core.WriteProblem(w, 422, "the "+what+" must be non-empty with no control characters")
		return "", false
	}
	return well_formed.MakeWellFormed(raw), true
}

func PromptRegistryCreateVersion(w http.ResponseWriter, r *http.Request) {
	in, ok := core.DecodeJSON[struct {
		Template *string `json:"template"` // the ONLY body field read -> a smuggled owner/version/content_hash is ignored
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	name, ok := prCleanName(w, r.PathValue("name"), "prompt name")
	if !ok {
		return
	}
	if in.Template == nil || *in.Template == "" {
		core.WriteProblem(w, 422, "template is required")
		return
	}
	template := well_formed.MakeWellFormed(*in.Template) // CONTAIN before hash/store (a lone surrogate would break the UTF-8 hash)
	if len(template) > prMaxTemplateBytes() {            // go strings are UTF-8 bytes -> octet count, matches py/node encode-len
		core.WriteProblem(w, 422, "template is too large")
		return
	}
	contentHash := digest.DigestHex(template) // server-DERIVED pin over the ONE contained string (injective)
	createdAt := core.TestNow(r)
	mx := prMaxVersions()
	version := 0
	over := false
	prPrompts.Do(prPKey(owner, name), func(p promptRecord, exists bool) (promptRecord, bool) {
		if !exists {
			version = 1
			return promptRecord{Owner: owner, Name: name, LatestVersion: 1, Labels: map[string]int{}, CreatedAt: createdAt}, true
		}
		if p.LatestVersion >= mx { // reject past the cap (preserve every pin; never prune)
			over = true
			return p, false
		}
		version = p.LatestVersion + 1
		p.LatestVersion = version
		return p, true
	})
	if over {
		core.WriteProblem(w, 422, "too many versions")
		return
	}
	// the immutable version row, written AFTER Do (the callback is pure). A crash here leaves a benign gap the read-side
	// None-check turns into a 404.
	prVersions.Set(prVKey(owner, name, version), versionRow{Owner: owner, Name: name, Version: version,
		Template: template, ContentHash: contentHash, CreatedAt: createdAt})
	core.WriteJSON(w, 201, map[string]any{"name": name, "version": version, "content_hash": contentHash, "created_at": createdAt})
}

func PromptRegistryGetVersion(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	name, ok := prCleanName(w, r.PathValue("name"), "prompt name")
	if !ok {
		return
	}
	version, err := strconv.Atoi(r.PathValue("version")) // STRICT path int: rejects "1.0"/"abc" (matches IntPath)
	if err != nil {
		core.WriteProblem(w, 422, "invalid version")
		return
	}
	// unbounded-safe: a single immutable version by key; OWNER-scoped (the key includes owner -> not-yours == 404,
	// byte-indistinguishable from a missing/torn-window row).
	rec, exists := prVersions.Get(prVKey(owner, name, version))
	if !exists {
		core.WriteProblem(w, 404, "prompt version not found")
		return
	}
	core.WriteJSON(w, 200, prPublicVersion(rec))
}

func PromptRegistryListPrompts(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	// read-scope: owner — ONLY the caller's own prompts (owner FIELD == caller); sorted by name (stable x3); BOUNDED
	// through paginate (a stranger gets an empty page, never 403).
	rows := []promptRecord{}
	for _, p := range prPrompts.All() {
		if p.Owner == owner {
			rows = append(rows, p)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	views := make([]map[string]any, len(rows))
	for i, p := range rows {
		views[i] = map[string]any{"name": p.Name, "latest_version": p.LatestVersion}
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

func PromptRegistryGetPrompt(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	name, ok := prCleanName(w, r.PathValue("name"), "prompt name")
	if !ok {
		return
	}
	p, exists := prPrompts.Get(prPKey(owner, name))
	if !exists {
		core.WriteProblem(w, 404, "prompt not found")
		return
	}
	labels := p.Labels
	if labels == nil {
		labels = map[string]int{}
	}
	// version_count == latest_version (append-only); latest_version is read-only metadata, NOT a render target.
	core.WriteJSON(w, 200, map[string]any{"name": p.Name, "latest_version": p.LatestVersion,
		"version_count": p.LatestVersion, "labels": labels, "created_at": p.CreatedAt})
}

func PromptRegistrySetLabel(w http.ResponseWriter, r *http.Request) {
	in, ok := core.DecodeJSON[struct {
		Version *json.RawMessage `json:"version"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	name, ok := prCleanName(w, r.PathValue("name"), "prompt name")
	if !ok {
		return
	}
	label, ok := prCleanName(w, r.PathValue("label"), "label")
	if !ok {
		return
	}
	if in.Version == nil {
		core.WriteProblem(w, 422, "version is required")
		return
	}
	version, valid := core.RequireIntRaw(*in.Version) // STRICT: rejects "1"/float/bool AND a magnitude past 2^53, x3
	if !valid || version < 1 {
		core.WriteProblem(w, 422, "version must be a positive integer")
		return
	}
	if _, exists := prPrompts.Get(prPKey(owner, name)); !exists {
		core.WriteProblem(w, 404, "prompt not found") // not-yours / missing -> 404 (existence never leaks)
		return
	}
	if _, exists := prVersions.Get(prVKey(owner, name, version)); !exists { // the immutable version ROW must exist (not the counter)
		core.WriteProblem(w, 422, "version does not exist")
		return
	}
	mx := prMaxLabels()
	outcome := "ok"
	prPrompts.Do(prPKey(owner, name), func(p promptRecord, exists bool) (promptRecord, bool) {
		if !exists {
			outcome = "no-prompt"
			return p, false
		}
		labels := map[string]int{}
		for k, v := range p.Labels {
			labels[k] = v
		}
		if _, has := labels[label]; !has && len(labels) >= mx { // a NEW label past cap is rejected; MOVING an existing one is fine
			outcome = "too-many"
			return p, false
		}
		labels[label] = version // one-to-one: setting MOVES the label
		p.Labels = labels
		return p, true
	})
	if outcome == "no-prompt" {
		core.WriteProblem(w, 404, "prompt not found")
		return
	}
	if outcome == "too-many" {
		core.WriteProblem(w, 422, "too many labels")
		return
	}
	core.WriteJSON(w, 200, map[string]any{"name": name, "label": label, "version": version})
}

func PromptRegistryRender(w http.ResponseWriter, r *http.Request) {
	in, ok := core.DecodeJSON[struct {
		Version *json.RawMessage  `json:"version"`
		Label   *string           `json:"label"`
		Data    map[string]string `json:"data"` // string->string: a numeric/bool value fails the decode -> 422 (x3)
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	name, ok := prCleanName(w, r.PathValue("name"), "prompt name")
	if !ok {
		return
	}
	if (in.Version == nil) == (in.Label == nil) { // EXACTLY one of version|label (no silent default)
		core.WriteProblem(w, 422, "provide exactly one of version or label")
		return
	}
	version := 0
	if in.Label != nil {
		label, lok := prCleanName(w, *in.Label, "label")
		if !lok {
			return
		}
		p, exists := prPrompts.Get(prPKey(owner, name))
		if !exists {
			core.WriteProblem(w, 404, "prompt not found")
			return
		}
		v, has := p.Labels[label]
		if !has {
			core.WriteProblem(w, 404, "label not found") // an unset label -> 404 (no silent fallback to newest)
			return
		}
		version = v
	} else {
		v, valid := core.RequireIntRaw(*in.Version)
		if !valid || v < 1 {
			core.WriteProblem(w, 422, "version must be a positive integer")
			return
		}
		version = v
	}
	rec, exists := prVersions.Get(prVKey(owner, name, version))
	if !exists {
		core.WriteProblem(w, 404, "prompt version not found")
		return
	}
	// CONTAIN the data values BEFORE substitution (identity in go; kept parallel with py/node where a lone surrogate
	// would otherwise break serialization).
	data := map[string]string{}
	for k, v := range in.Data {
		data[k] = well_formed.MakeWellFormed(v)
	}
	rendered, complete := prRender(rec.Template, data)
	if !complete {
		core.WriteProblem(w, 422, "template variable not provided")
		return
	}
	if len(rendered) > prMaxRenderedBytes() { // RENDER-THEN-VALIDATE: bound the rendered output (amplification)
		core.WriteProblem(w, 422, "rendered output is too large")
		return
	}
	core.WriteJSON(w, 200, map[string]any{"name": name, "version": version, "content_hash": rec.ContentHash, "rendered": rendered})
}
