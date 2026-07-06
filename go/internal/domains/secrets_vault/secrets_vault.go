// Package secrets_vault (package shape) — a versioned secret store with a version LIFECYCLE, a domain-local ACCESS
// AUDIT, and an opt-in at-rest AES-256-GCM SEAL. Matches python/node; durable; see python/router.py for the full
// contract; the at-rest seal (svSeal/svUnseal) lives in seal.go. IMMUTABILITY: reveal(N) returns the bytes at N unless
// PRUNED (max_versions)/DESTROYED/DISABLED (each a byte-indistinguishable 404). ADMIN-ONLY — 401/403 before validation.
// AUDIT (domain-local): reveal/put/destroy/disable/enable, success AND 403/404 -> secrets_vault_access (NEVER a value).
package secrets_vault

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"app/internal/core"
	"app/internal/parts/env_int"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

type secretsVaultMeta struct {
	Name           string            `json:"name"`
	CurrentVersion int               `json:"current_version"`
	MinVersion     int               `json:"min_version"`
	States         map[string]string `json:"states"` // "<version>" -> "disabled" | "destroyed"; active versions absent
}

type svAccessRec struct { // one audit row; Name/Version `any` so a no-name/version route logs null (x3); NEVER a value
	Id      int    `json:"id"`
	Actor   string `json:"actor"`
	Action  string `json:"action"`
	Name    any    `json:"name"`
	Version any    `json:"version"`
	Outcome string `json:"outcome"`
	At      int64  `json:"at"`
	Source  string `json:"source"`
}

var (
	secretsVaultMetas    = core.NewKV[string, secretsVaultMeta]("secrets_vault_meta")
	secretsVaultVersions = core.NewKV[string, string]("secrets_vault_versions")
	secretsVaultAccess   = core.NewKV[string, svAccessRec]("secrets_vault_access")
)

func secretsVaultVKey(name string, version int) string {
	return name + "\x1f" + strconv.Itoa(version) // name well-formed (no separator) -> key can't be forged
}

// svMaxVersions bounds a name's retained versions (oldest PRUNED past the cap); a non-numeric/<1 value -> default 100.
func svMaxVersions() int { return env_int.EnvInt(os.Getenv("SECRETS_VAULT_MAX_VERSIONS"), 100, 1) }

func svMinVersion(m secretsVaultMeta) int {
	if m.MinVersion < 1 {
		return 1
	}
	return m.MinVersion
}
// svStateOf: active | pruned | destroyed | disabled | unknown. ONLY `active` reveals; the rest are a 404.
func svStateOf(m secretsVaultMeta, version int) string {
	if version < 1 || version > m.CurrentVersion {
		return "unknown"
	}
	if version < svMinVersion(m) {
		return "pruned"
	}
	if s, ok := m.States[strconv.Itoa(version)]; ok && (s == "destroyed" || s == "disabled") {
		return s
	}
	return "active"
}
func svCopyStates(s map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range s {
		out[k] = v
	}
	return out
}

// svAudit — the domain-local AU-3 access audit. APP_SECRETS_VAULT_AUDIT: off | deny (default — denials/failures) | all.
func svAudit(r *http.Request, actor, action string, name any, version any, outcome string) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("APP_SECRETS_VAULT_AUDIT")))
	if mode != "off" && mode != "all" {
		mode = "deny" // unknown/empty/typo -> fail SAFE to the default
	}
	if mode == "off" || (mode == "deny" && outcome == "allowed") {
		return
	}
	id := core.NextID("secrets_vault_access")
	secretsVaultAccess.Set(strconv.Itoa(id), svAccessRec{Id: id, Actor: actor, Action: action, Name: name,
		Version: version, Outcome: outcome, At: core.TestNow(r), Source: core.RequestID(r)})
}

// svRequireAdmin — admin-gate a route AND audit the 403 denial (the subject is known). A 401 is sent by RequireIdentity
// before this -> it is in the core access-log, not the domain audit (x3).
func svRequireAdmin(w http.ResponseWriter, r *http.Request, action string) (string, bool) {
	subject, ok := core.RequireIdentity(w, r)
	if !ok {
		return "", false
	}
	if !core.IsAdmin(subject) {
		var nm any
		if pn := r.PathValue("name"); pn != "" {
			nm = pn
		}
		svAudit(r, subject, action, nm, nil, "denied")
		core.WriteProblem(w, 403, "this operation requires the admin role")
		return "", false
	}
	return subject, true
}

// svRequireVersion decodes a REQUIRED positive-integer body `version` (STRICT: rejects "1"/float/bool), identical x3.
func svRequireVersion(w http.ResponseWriter, r *http.Request) (int, bool) {
	in, ok := core.DecodeJSON[struct {
		Version *json.RawMessage `json:"version"`
	}](w, r)
	if !ok {
		return 0, false
	}
	if in.Version == nil {
		core.WriteProblem(w, 422, "version is required")
		return 0, false
	}
	v, valid := core.RequireIntRaw(*in.Version)
	if !valid || v < 1 {
		core.WriteProblem(w, 422, "version must be a positive integer")
		return 0, false
	}
	return v, true
}

func SecretsVaultList(w http.ResponseWriter, r *http.Request) {
	if _, ok := svRequireAdmin(w, r, "list"); !ok {
		return
	}
	// unscoped-read: admin — lists names only (NEVER values) across all secrets; no per-caller owner field.
	names := []string{}
	for _, m := range secretsVaultMetas.All() {
		names = append(names, m.Name)
	}
	sort.Strings(names)
	q := r.URL.Query()
	page, next, valid := paginate.Paginate(names, q.Get("cursor"), q.Get("limit"))
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

func SecretsVaultAccessLog(w http.ResponseWriter, r *http.Request) {
	if _, ok := svRequireAdmin(w, r, "audit-read"); !ok {
		return
	}
	// unscoped-read: admin — a GLOBAL admin resource (svRequireAdmin gates it); no per-caller owner field. NEWEST-first; NEVER a value.
	rows := secretsVaultAccess.All()
	sort.Slice(rows, func(i, j int) bool { return rows[i].Id > rows[j].Id })
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

func SecretsVaultPut(w http.ResponseWriter, r *http.Request) {
	subject, ok := svRequireAdmin(w, r, "put") // authn -> authz BEFORE decode (401/403 before 422), x3
	if !ok {
		return
	}
	in, ok := core.DecodeJSON[struct {
		Value *string `json:"value"`
	}](w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if !well_formed.IsWellFormed(name) {
		core.WriteProblem(w, 422, "the secret name must be non-empty with no control characters")
		return
	}
	if name == "access" {
		core.WriteProblem(w, 422, "'access' is a reserved name")
		return
	}
	if in.Value == nil || *in.Value == "" {
		core.WriteProblem(w, 422, "value is required")
		return
	}
	mx := svMaxVersions()
	version := 0
	var pruned []int
	secretsVaultMetas.Do(name, func(meta secretsVaultMeta, exists bool) (secretsVaultMeta, bool) {
		version = meta.CurrentVersion + 1
		minV := 1
		states := map[string]string{}
		if exists {
			minV = svMinVersion(meta)
			states = svCopyStates(meta.States)
		}
		newMin := version - mx + 1 // keep only the newest mx versions
		if newMin < minV {
			newMin = minV
		}
		pruned = nil
		for v := minV; v < newMin; v++ {
			pruned = append(pruned, v)
			delete(states, strconv.Itoa(v))
		}
		return secretsVaultMeta{Name: name, CurrentVersion: version, MinVersion: newMin, States: states}, true
	})
	sealed, err := svSeal(*in.Value, name, version) // AES-256-GCM under SECRETS_VAULT_KEK, else passthrough
	if err != nil {
		core.WriteProblem(w, 500, "secret could not be sealed") // loud — never store plaintext when a seal was requested
		return
	}
	secretsVaultVersions.Set(secretsVaultVKey(name, version), sealed) // immutable, SEALED version row
	for _, v := range pruned {
		secretsVaultVersions.Delete(secretsVaultVKey(name, v)) // secure_delete=ON scrubs the evicted bytes
	}
	svAudit(r, subject, "put", name, version, "allowed")
	core.WriteJSON(w, 201, map[string]any{"name": name, "version": version}) // value NEVER echoed
}

func SecretsVaultGet(w http.ResponseWriter, r *http.Request) {
	subject, ok := svRequireAdmin(w, r, "get")
	if !ok {
		return
	}
	name := r.PathValue("name")
	if !well_formed.IsWellFormed(name) {
		core.WriteProblem(w, 422, "the secret name must be non-empty with no control characters")
		return
	}
	meta, exists := secretsVaultMetas.Get(name)
	if !exists {
		svAudit(r, subject, "get", name, nil, "not_found")
		core.WriteProblem(w, 404, "secret not found")
		return
	}
	// metadata only — NO value. Expose non-active states (disabled/destroyed) >= min_version; active implied, pruned gone.
	out := map[string]any{"name": meta.Name, "current_version": meta.CurrentVersion}
	states := map[string]string{}
	for k, v := range meta.States {
		if n, err := strconv.Atoi(k); err == nil && n >= svMinVersion(meta) {
			states[k] = v
		}
	}
	if len(states) > 0 {
		out["states"] = states
	}
	svAudit(r, subject, "get", name, nil, "allowed")
	core.WriteJSON(w, 200, out)
}

func SecretsVaultReveal(w http.ResponseWriter, r *http.Request) {
	subject, ok := svRequireAdmin(w, r, "reveal") // authn -> authz BEFORE decode (RequireInt after auth, x3)
	if !ok {
		return
	}
	in, ok := core.DecodeJSON[struct {
		Version *json.RawMessage `json:"version"`
	}](w, r)
	if !ok {
		return
	}
	version := 0
	if in.Version != nil {
		v, valid := core.RequireIntRaw(*in.Version) // STRICT: rejects a quoted "1"/float/bool, x3
		if !valid || v < 1 {
			core.WriteProblem(w, 422, "version must be a positive integer")
			return
		}
		version = v
	}
	name := r.PathValue("name")
	if !well_formed.IsWellFormed(name) {
		core.WriteProblem(w, 422, "the secret name must be non-empty with no control characters")
		return
	}
	meta, exists := secretsVaultMetas.Get(name)
	if !exists {
		svAudit(r, subject, "reveal", name, nil, "not_found") // no secret -> the version is moot
		core.WriteProblem(w, 404, "secret not found")
		return
	}
	if version == 0 {
		version = meta.CurrentVersion
	}
	if svStateOf(meta, version) != "active" { // pruned / destroyed / disabled / unknown -> 404 (byte-indistinguishable)
		svAudit(r, subject, "reveal", name, version, "not_found")
		core.WriteProblem(w, 404, "secret version not found")
		return
	}
	value, has := secretsVaultVersions.Get(secretsVaultVKey(meta.Name, version))
	if !has { // defensive: state says active but the row is gone
		svAudit(r, subject, "reveal", name, version, "not_found")
		core.WriteProblem(w, 404, "secret version not found")
		return
	}
	plain, err := svUnseal(value, meta.Name, version) // AES-256-GCM open under SECRETS_VAULT_KEK, else passthrough
	if err != nil {
		core.WriteProblem(w, 500, "secret could not be unsealed") // loud — never return plaintext/garbage
		return
	}
	svAudit(r, subject, "reveal", name, version, "allowed")
	core.WriteJSON(w, 200, map[string]any{"name": meta.Name, "version": version, "value": plain}) // the ONE value path
}
