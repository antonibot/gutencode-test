// Package agent — a multi-file AI agent runtime: swappable provider port (AI_PROVIDER, fake = deterministic
// offline default) · tool registry (safe calc, never eval) · durable agents/sessions/memory · a bounded run
// loop that ALWAYS terminates. Store namespaces and counters match the python/node impls.
package agent

import (
	"net/http"
	"strconv"

	"app/internal/core"
)

type agAgent struct {
	Id           int    `json:"id"`
	Name         string `json:"name"`
	SystemPrompt string `json:"system_prompt"`
	Owner        string `json:"owner"` // the authenticated subject; stored, NEVER returned (see agAgentPublic)
}

var (
	agAgents   = core.NewKV[string, agAgent]("agent_agents")
	agSessions = core.NewKV[string, int]("agent_sessions")
)

// agAgentPublic is the wire view — it NEVER includes the owner (internal, like api_keys' secret_hash).
func agAgentPublic(a agAgent) map[string]any {
	return map[string]any{"id": a.Id, "name": a.Name, "system_prompt": a.SystemPrompt}
}

// loadAgent expects RequireIdentity to have run already; it does the path-int check, loads, then enforces
// owner==caller, returning 404 for a missing OR cross-owner id (not-yours == not-found: existence never leaks
// cross-owner). Mirrors api_keys' apiKeysLoad.
func loadAgent(w http.ResponseWriter, r *http.Request, owner string) (agAgent, bool) {
	agentID, err := strconv.Atoi(r.PathValue("agent_id"))
	if err != nil {
		core.WriteProblem(w, 422, "invalid agent id")
		return agAgent{}, false
	}
	a, found := agAgents.Get(strconv.Itoa(agentID))
	if !found || a.Owner != owner {
		core.WriteProblem(w, 404, "agent not found") // not-yours == not-found
		return agAgent{}, false
	}
	return a, true
}

func AgentCreate(w http.ResponseWriter, r *http.Request) {
	// body-only POST: decode FIRST (DecodeJSON enforces the 413 cap and drains the stream — replying before the body
	// is read aborts the connection), THEN identity, THEN semantic validation. PARSE -> AUTH -> SEMANTIC, ×3.
	in, ok := core.DecodeJSON[struct {
		Name         *string `json:"name"`
		SystemPrompt *string `json:"system_prompt"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r) // authenticated mutation (no/invalid token -> 401)
	if !ok {
		return
	}
	if in.Name == nil || in.SystemPrompt == nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	// owner derived from the token, never client-set; stored on the record but kept OUT of the response.
	out := agAgent{Id: core.NextID("agent_agent"), Name: *in.Name, SystemPrompt: *in.SystemPrompt, Owner: owner}
	agAgents.Set(strconv.Itoa(out.Id), out)
	core.WriteJSON(w, 201, agAgentPublic(out))
}

func AgentCreateSession(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // path mutation -> identity before the path id (no-token -> 401)
	if !ok {
		return
	}
	a, ok := loadAgent(w, r, owner) // owner-or-404 before creating a session under the agent
	if !ok {
		return
	}
	sid := core.NextID("agent_session")
	agSessions.Set(strconv.Itoa(sid), a.Id)
	core.WriteJSON(w, 201, map[string]int{"id": sid, "agent_id": a.Id})
}

func sessionOf(w http.ResponseWriter, r *http.Request) (agentID, sessionID int, ok bool) {
	agentID, errA := strconv.Atoi(r.PathValue("agent_id"))
	sessionID, errS := strconv.Atoi(r.PathValue("session_id"))
	if errA != nil || errS != nil {
		core.WriteProblem(w, 422, "invalid id")
		return 0, 0, false
	}
	owner, found := agSessions.Get(strconv.Itoa(sessionID))
	if !found || owner != agentID {
		core.WriteProblem(w, 404, "session for this agent not found")
		return 0, 0, false
	}
	return agentID, sessionID, true
}

func AgentRun(w http.ResponseWriter, r *http.Request) {
	// path+body POST: identity FIRST (a no-token float-path probe must be 401, before the path-422), THEN
	// owner-or-404, THEN the session<->agent binding, THEN DecodeJSON — python's Depends(require_identity) fires
	// before path/body validation. PARSE -> AUTH -> SEMANTIC ×3.
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	agent, ok := loadAgent(w, r, owner) // owner-or-404 FIRST
	if !ok {
		return
	}
	_, sessionID, ok := sessionOf(w, r) // then the session<->agent binding
	if !ok {
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
	provider, notWired := getProvider()
	if notWired != "" {
		core.WriteProblem(w, 501, notWired) // fail LOUD per call — never silent fake output (see providers.go)
		return
	}
	// owner = the run's authenticated subject (owner-self-metering, executed server-side — the spend lands in THIS
	// user's llm_usage summary); now = the request clock (keeps the test-clock seam coherent).
	output, iterations, terminated, err := runLoop(provider, sessionID, agent.SystemPrompt, *in.Input, owner, core.TestNow(r))
	if err != nil {
		// a wired adapter's upstream failure — mapped 502/504, rendered as the ONE problem+json envelope
		// BEFORE any SSE byte (streaming only begins after every guard AND the run have completed).
		status, detail := 502, "provider upstream failure"
		if pf, ok := err.(*providerFailure); ok {
			status, detail = pf.status, pf.detail
		}
		core.WriteProblem(w, status, detail)
		return
	}
	body := map[string]any{
		"session_id": sessionID, "output": output, "iterations": iterations, "terminated": terminated,
	}
	if core.WantsStream(r) {
		// SSE mode (?stream=1, or Accept: text/event-stream) — the SAME run result, chunked at the transport:
		// the delta frames concatenate to exactly `output`, and `event: done` carries this exact sync body.
		core.Stream(w, chunkOutput(output), body)
		return
	}
	core.WriteJSON(w, 200, body)
}

func AgentMessages(w http.ResponseWriter, r *http.Request) {
	// USER-SCOPED read: identity FIRST, then owner-or-404, THEN the session<->agent binding.
	// A non-owner reading another's messages -> 404; no token -> 401.
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if _, ok := loadAgent(w, r, owner); !ok {
		return
	}
	_, sessionID, ok := sessionOf(w, r)
	if !ok {
		return
	}
	core.WriteJSON(w, 200, history(sessionID))
}
