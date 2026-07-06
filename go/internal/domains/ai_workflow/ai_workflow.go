// Package ai_workflow — multi-step pipelines over a running value: each step's output threads into the next.
// The dangerous property is TERMINATION + CONTAINMENT: a run ALWAYS terminates (MAX_STEPS bounds every run) and
// a failing or unknown step is CONTAINED (the run stops gracefully with ok:false and the trace so far — never a
// crash, never a 5xx). String ops slice and measure by CODEPOINTS (runes) — the ×3-identical semantic.
// Definitions are durable. Store names and shapes match the python/node impls.
package ai_workflow

import (
	"net/http"
	"strconv"

	"app/internal/core"
)

const aiWorkflowMaxSteps = 50

type aiWorkflowStep = map[string]any

type aiWorkflowDef struct {
	Id    int              `json:"id"`
	Steps []aiWorkflowStep `json:"steps"`
}

var aiWorkflowDefs = core.NewKV[string, aiWorkflowDef]("ai_workflow_defs")

// one step. Returns (newValue, ok) — unknown/invalid ops report ok=false, they never panic.
func aiWorkflowApply(op, value string, step aiWorkflowStep) (string, bool) {
	text, _ := step["text"].(string)
	switch op {
	case "append":
		return value + text, true
	case "prepend":
		return text + value, true
	case "truncate":
		n := 0
		if f, isNum := step["n"].(float64); isNum && f >= 0 {
			n = int(f)
		}
		runes := []rune(value) // CODEPOINT slicing — parity with python/node
		if n > len(runes) {
			n = len(runes)
		}
		return string(runes[:n]), true
	case "length":
		return strconv.Itoa(len([]rune(value))), true // CODEPOINT count
	}
	return value, false
}

func AiWorkflowCreate(w http.ResponseWriter, r *http.Request) {
	// decode FIRST: DecodeJSON enforces the body cap (413) and drains the stream — replying (incl. a 401) before
	// the body is read aborts the connection mid-upload. Identity is checked next, before any write. (×3 parity)
	in, ok := core.DecodeJSON[struct {
		Steps []aiWorkflowStep `json:"steps"`
	}](w, r)
	if !ok {
		return
	}
	if _, ok := core.RequireIdentity(w, r); !ok { // authenticated mutation (no/invalid token -> 401)
		return
	}
	if len(in.Steps) == 0 {
		core.WriteProblem(w, 422, "a workflow needs at least one step")
		return
	}
	for _, step := range in.Steps {
		op, isStr := step["op"].(string)
		if step == nil || !isStr || op == "" {
			core.WriteProblem(w, 422, "every step must be an object with a string 'op'")
			return
		}
	}
	wid := core.NextID("ai_workflow_def")
	aiWorkflowDefs.Set(strconv.Itoa(wid), aiWorkflowDef{Id: wid, Steps: in.Steps})
	core.WriteJSON(w, 201, map[string]any{"id": wid, "steps": len(in.Steps)})
}

func AiWorkflowRun(w http.ResponseWriter, r *http.Request) {
	if _, ok := core.RequireIdentity(w, r); !ok { // identity before the path id (×3: a no-token float-path -> 401)
		return
	}
	wid, err := strconv.Atoi(r.PathValue("workflow_id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid workflow id")
		return
	}
	in, ok := core.DecodeJSON[struct {
		Input *string `json:"input"`
	}](w, r)
	if !ok {
		return
	}
	if in.Input == nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	wf, exists := aiWorkflowDefs.Get(strconv.Itoa(wid))
	if !exists {
		core.WriteProblem(w, 404, "workflow not found")
		return
	}
	value, runOk := *in.Input, true
	trace := []map[string]string{}
	limit := len(wf.Steps)
	if limit > aiWorkflowMaxSteps {
		limit = aiWorkflowMaxSteps // TERMINATION: never more than MAX_STEPS, whatever was defined
	}
	for _, step := range wf.Steps[:limit] {
		op := step["op"].(string)
		next, stepOk := aiWorkflowApply(op, value, step)
		value = next
		if !stepOk {
			runOk = false // CONTAINMENT: stop gracefully, keep the trace so far
			break
		}
		trace = append(trace, map[string]string{"op": op, "output": value})
	}
	if runOk && len(wf.Steps) > aiWorkflowMaxSteps {
		runOk = false // the budget itself was exceeded — report it, loudly
	}
	core.WriteJSON(w, 200, map[string]any{"output": value, "steps_run": len(trace), "ok": runOk, "trace": trace})
}
