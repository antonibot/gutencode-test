// Package crew — multi-agent orchestration: named roles that each process the running value and hand off to
// the next. The load-bearing invariant is TERMINATION UNDER CYCLES: the handoff graph MAY cycle (A->B->A is a
// legal definition), so MAX_HANDOFFS bounds every run — infinite ping-pong is impossible, and hitting the bound
// is reported (terminated:false), never disguised as success. A handoff to an UNKNOWN role is CONTAINED (the
// run stops gracefully with the trace so far). Handoffs THREAD. Store names and shapes match python/node.
package crew

import (
	"net/http"
	"strconv"

	"app/internal/core"
	"app/internal/parts/well_formed"
)

const crewMaxHandoffs = 25

type crewRole = map[string]any

type crewDef struct {
	Id    int        `json:"id"`
	Roles []crewRole `json:"roles"`
}

var crewDefs = core.NewKV[string, crewDef]("crew_defs")

func CrewCreate(w http.ResponseWriter, r *http.Request) {
	// decode FIRST: DecodeJSON enforces the body cap (413) and drains the stream — replying before the body is read
	// aborts the connection mid-upload. Identity is checked next, before any write. (×3 parity)
	in, ok := core.DecodeJSON[struct {
		Roles []crewRole `json:"roles"`
	}](w, r)
	if !ok {
		return
	}
	if _, ok := core.RequireIdentity(w, r); !ok { // authenticated mutation (no/invalid token -> 401)
		return
	}
	if len(in.Roles) == 0 {
		core.WriteProblem(w, 422, "a crew needs at least one role")
		return
	}
	seen := map[string]bool{}
	for _, role := range in.Roles {
		name, isStr := role["name"].(string)
		if role == nil || !isStr || !well_formed.IsWellFormed(name) {
			core.WriteProblem(w, 422, "every role must be an object with a well-formed string 'name'")
			return
		}
		if nxt, present := role["next"]; present {
			if _, nextIsStr := nxt.(string); !nextIsStr {
				core.WriteProblem(w, 422, "'next' must be a string role name")
				return
			}
		}
		if seen[name] {
			core.WriteProblem(w, 422, "role names must be unique")
			return
		}
		seen[name] = true
	}
	cid := core.NextID("crew_def")
	crewDefs.Set(strconv.Itoa(cid), crewDef{Id: cid, Roles: in.Roles})
	core.WriteJSON(w, 201, map[string]any{"id": cid, "roles": len(in.Roles)})
}

func CrewRun(w http.ResponseWriter, r *http.Request) {
	if _, ok := core.RequireIdentity(w, r); !ok { // identity before the path id (×3: a no-token float-path -> 401)
		return
	}
	cid, err := strconv.Atoi(r.PathValue("crew_id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid crew id")
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
	crew, exists := crewDefs.Get(strconv.Itoa(cid))
	if !exists {
		core.WriteProblem(w, 404, "crew not found")
		return
	}
	byName := map[string]crewRole{}
	for _, role := range crew.Roles {
		byName[role["name"].(string)] = role
	}
	current, value := crew.Roles[0], *in.Input
	trace := []map[string]string{}
	terminated := false
	for len(trace) < crewMaxHandoffs { // TERMINATION: the bound holds whatever the graph shape
		name := current["name"].(string)
		value = value + " [" + name + "]" // the role's tagged contribution — THREADING by construction
		trace = append(trace, map[string]string{"role": name, "output": value})
		nxt, present := current["next"]
		if !present {
			terminated = true // a clean finish: the chain ended by design
			break
		}
		next, known := byName[nxt.(string)]
		if !known {
			break // CONTAINED: an unknown handoff stops gracefully, trace kept
		}
		current = next
	}
	core.WriteJSON(w, 200, map[string]any{"output": value, "handoffs": len(trace),
		"terminated": terminated, "trace": trace})
}
