// Package settings — settings over a fixed, typed schema, scoped to the AUTHENTICATED identity. The dangerous
// property is TYPE SAFETY + COMPLETENESS: only known keys are writable (unknown -> 422, deny-by-default), each
// value is STRICTLY type-checked against its key's declared type before any write (a string "20", a float 1.5, or
// a boolean true is NOT an int), and a read always returns EVERY known key with the declared default filling any
// gap. The owner is the bearer token's subject (core.RequireIdentity) — NOT a path param — so a caller only ever
// reads/writes THEIR OWN settings. Deny-by-default (no token -> 401). Store names and shapes match python/node.
package settings

import (
	"encoding/json"
	"net/http"
	"strings"

	"app/internal/core"
)

type settingsSpec struct {
	kind  string
	deflt any
}

// the schema is POLICY (fixed): key -> (type, default). The ONLY writable keys + their types.
var settingsSchema = map[string]settingsSpec{
	"notifications_enabled": {"bool", true},
	"items_per_page":        {"int", 20},
	"theme":                 {"string", "light"},
}

var settingsOverrides = core.NewKV[string, any]("settings_overrides")

func settingsKeyID(owner, key string) string {
	return owner + "\x1f" + key // both well-formed -> the separator can't be forged
}

// STRICT type check off the RAW JSON token (so 20 and 20.0 are distinguishable, ×3 with python StrictInt): an
// int is a bare integer literal, a bool is true/false, a string is a JSON string. Returns the materialized Go
// value to store on success.
func settingsTyped(kind string, raw json.RawMessage) (any, bool) {
	s := strings.TrimSpace(string(raw))
	switch kind {
	case "bool":
		if s == "true" {
			return true, true
		}
		if s == "false" {
			return false, true
		}
	case "int":
		if v, ok := core.RequireIntRaw(raw); ok { // strict integer literal, bounded to the ×3-safe range
			return v, true
		}
	case "string":
		if len(s) > 0 && s[0] == '"' {
			var x string
			if json.Unmarshal(raw, &x) == nil {
				return x, true
			}
		}
	}
	return nil, false
}

func SettingsList(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	out := map[string]any{}
	for k, spec := range settingsSchema {
		out[k] = spec.deflt // COMPLETENESS: every known key present, default first
		if v, found := settingsOverrides.Get(settingsKeyID(owner, k)); found {
			out[k] = v
		}
	}
	core.WriteJSON(w, 200, out)
}

func SettingsGet(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	key := r.PathValue("key")
	spec, known := settingsSchema[key]
	if !known {
		core.WriteProblem(w, 404, "setting not found")
		return
	}
	value := spec.deflt
	if v, found := settingsOverrides.Get(settingsKeyID(owner, key)); found {
		value = v
	}
	core.WriteJSON(w, 200, map[string]any{"key": key, "value": value})
}

func SettingsPut(w http.ResponseWriter, r *http.Request) {
	// decode FIRST: DecodeJSON enforces the body cap (413) and drains the stream before any reply (incl. a 401).
	body, ok := core.DecodeJSON[map[string]json.RawMessage](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	key := r.PathValue("key")
	spec, known := settingsSchema[key]
	if !known {
		core.WriteProblem(w, 422, "unknown setting key") // deny-by-default: no arbitrary keys
		return
	}
	raw, present := body["value"]
	if !present {
		core.WriteProblem(w, 422, "value is required")
		return
	}
	value, okType := settingsTyped(spec.kind, raw)
	if !okType {
		core.WriteProblem(w, 422, "setting '"+key+"' must be of type "+spec.kind) // strict, BEFORE any write
		return
	}
	settingsOverrides.Set(settingsKeyID(owner, key), value)
	core.WriteJSON(w, 200, map[string]any{"key": key, "value": value})
}
