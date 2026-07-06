// Package ai_tools — the typed tool belt: a registry of tools any caller invokes over HTTP. Each tool declares a
// TYPED CONTRACT — a description + an input_schema (JSON Schema: per-arg type + which are required) — and the args
// are VALIDATED against it. The dangerous property is SAFE EXECUTION: an invoke whose args violate the contract (a
// missing required arg, OR an arg of the wrong type) is CONTAINED (ok:false + the error, HTTP 200 — a tool failure
// is a RESULT, never a crash or a 5xx), an unknown tool is an honest 404, and every tool is deterministic and
// BOUNDED (repeat is capped — output can never explode). String ops work by CODEPOINTS (runes), the ×3-identical
// semantic; go's json decoder already substitutes U+FFFD for a lone surrogate, so text is well-formed (parity with
// python's normalize + node's toWellFormed). Integer args are STRICT and ×3-identical within the safe-integer range
// (5.0 / "5" / true / null AND any magnitude beyond ±(2^53-1) rejected via core.RequireIntRaw + the safe-int bound).
// The registry is static policy (no store). Matches the python/node impls.
package ai_tools

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"app/internal/core"
	"app/internal/parts/well_formed"
)

const aiToolsRepeatCap = 100

// 2^53-1 = Number.MAX_SAFE_INTEGER: the integer range all three languages represent EXACTLY. Beyond it the runtimes
// diverge (python is arbitrary-precision, go's strconv.Atoi caps at int64, node loses float precision), so a
// magnitude past it is rejected uniformly ×3.
const aiToolsMaxSafeInt = 9007199254740991

// an arg spec: name, type ("string"|"integer"), required, description.
type aiToolsArg struct {
	name     string
	typ      string
	required bool
	desc     string
}

type aiToolsEntry struct {
	desc string
	args []aiToolsArg
	fn   func(args map[string]any) string
}

// the ONE registry: name -> {description, [arg specs], fn}. Static policy, identical ×3. The input_schema (listing),
// the required[] and the per-arg validation are all DERIVED from the specs — one source per tool.
var aiToolsRegistry = map[string]aiToolsEntry{
	"upper": {"Uppercase the text by Unicode codepoint.",
		[]aiToolsArg{{"text", "string", true, "the text to uppercase"}},
		func(a map[string]any) string { return strings.ToUpper(aiToolsText(a)) }},
	"reverse": {"Reverse the text by Unicode codepoint (non-BMP characters stay whole).",
		[]aiToolsArg{{"text", "string", true, "the text to reverse"}},
		func(a map[string]any) string {
			runes := []rune(aiToolsText(a)) // codepoint reverse — parity with python/node
			for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
				runes[i], runes[j] = runes[j], runes[i]
			}
			return string(runes)
		}},
	"wordcount": {"Count the whitespace-separated words in the text.",
		[]aiToolsArg{{"text", "string", true, "the text to count words in"}},
		func(a map[string]any) string { return strconv.Itoa(len(strings.Fields(aiToolsText(a)))) }},
	"repeat": {"Repeat the text n times; n is clamped to 0..100 so the output can never explode.",
		[]aiToolsArg{{"text", "string", true, "the text to repeat"},
			{"n", "integer", false, "how many times to repeat (clamped to 0..100; default 1)"}},
		func(a map[string]any) string {
			n := 1
			if v, ok := a["n"].(int); ok { // validated: present -> a strict int, absent -> the default (1)
				n = v
			}
			if n < 0 {
				n = 0
			}
			if n > aiToolsRepeatCap {
				n = aiToolsRepeatCap // BOUNDED: output can never explode
			}
			return strings.Repeat(aiToolsText(a), n)
		}},
}

var aiToolsOrder = []string{"repeat", "reverse", "upper", "wordcount"} // sorted, deterministic ×3

func aiToolsText(a map[string]any) string {
	if s, isStr := a["text"].(string); isStr {
		return s
	}
	return ""
}

// aiToolsInputSchema DERIVES the JSON-Schema input_schema from the arg specs (one source per tool).
func aiToolsInputSchema(args []aiToolsArg) map[string]any {
	props := map[string]any{}
	required := []string{}
	for _, ar := range args {
		props[ar.name] = map[string]any{"type": ar.typ, "description": ar.desc}
		if ar.required {
			required = append(required, ar.name)
		}
	}
	return map[string]any{"type": "object", "properties": props, "required": required}
}

// aiToolsValidate checks args against the typed contract and returns the CLEAN typed values (text->string, n->int)
// so the fn runs on validated data. Returns ("", clean) when valid, or (errMsg, nil). Unknown (undeclared) args are
// ignored — lenient. STRICT integer via core.RequireIntRaw (the raw-token seam: 5.0 / "5" / true / null rejected),
// and a *string decode distinguishes a JSON null from a string — identical ×3 with python + node isStrictInt.
func aiToolsValidate(raw map[string]json.RawMessage, args []aiToolsArg) (string, map[string]any) {
	clean := map[string]any{}
	for _, ar := range args {
		rv, present := raw[ar.name]
		if !present {
			if ar.required {
				return "missing required arg '" + ar.name + "'", nil
			}
			continue
		}
		switch ar.typ {
		case "string":
			var s *string
			if err := json.Unmarshal(rv, &s); err != nil || s == nil { // null / number / bool / object -> not a string
				return "arg '" + ar.name + "' must be a string", nil
			}
			clean[ar.name] = *s
		case "integer":
			i, ok := core.RequireIntRaw(rv)
			if !ok || i > aiToolsMaxSafeInt || i < -aiToolsMaxSafeInt { // strict int AND within the ×3-safe range
				return "arg '" + ar.name + "' must be an integer", nil
			}
			clean[ar.name] = i
		}
	}
	return "", clean
}

func AiToolsList(w http.ResponseWriter, r *http.Request) {
	// read-scope: public — the global static tool catalog (each tool's name + typed contract), identical for every caller.
	out := []map[string]any{}
	for _, name := range aiToolsOrder {
		e := aiToolsRegistry[name]
		out = append(out, map[string]any{"name": name, "description": e.desc, "input_schema": aiToolsInputSchema(e.args)})
	}
	core.WriteJSON(w, 200, out)
}

func AiToolsInvoke(w http.ResponseWriter, r *http.Request) {
	// PRECEDENCE (proven ×3 against python's FastAPI): PARSE (413 oversize / 422 malformed JSON) -> AUTH (401) ->
	// PATH (422) -> SEMANTIC. `args` is captured RAW so a non-object value is NOT a decode error here — its type is
	// validated AFTER auth, matching python's dependency-before-type-validation order (a no-token bad-args body is
	// 401, not 422). Each arg value is kept as a RawMessage so the strict-int seam can read its raw token.
	in, ok := core.DecodeJSON[struct {
		Args json.RawMessage `json:"args"`
	}](w, r)
	if !ok {
		return
	}
	if _, ok := core.RequireIdentity(w, r); !ok { // any authenticated caller may invoke (no/invalid token -> 401)
		return
	}
	name := r.PathValue("tool_name")
	if !well_formed.IsWellFormed(name) {
		core.WriteProblem(w, 422, "tool name must be non-empty with no control characters")
		return
	}
	args := map[string]json.RawMessage{}
	if len(in.Args) > 0 {
		if err := json.Unmarshal(in.Args, &args); err != nil { // args present but not a JSON object -> 422
			core.WriteProblem(w, 422, "invalid body")
			return
		}
	}
	entry, known := aiToolsRegistry[name]
	if !known {
		core.WriteProblem(w, 404, "tool not found")
		return
	}
	errMsg, clean := aiToolsValidate(args, entry.args)
	if errMsg != "" {
		// CONTAINED: a contract violation is a RESULT the caller can read — never a crash, never a 5xx
		core.WriteJSON(w, 200, map[string]any{"tool": name, "ok": false, "output": "", "error": errMsg})
		return
	}
	core.WriteJSON(w, 200, map[string]any{"tool": name, "ok": true, "output": entry.fn(clean), "error": nil})
}
