package agent

// The run loop + durable per-session memory. THE INVARIANT: the loop ALWAYS terminates — bounded by
// AGENT_MAX_ITERATIONS (default 6), proven black-box by the 'use forever' contract case.

import (
	"log"
	"os"
	"strconv"
	"unicode/utf8"

	"app/internal/core"
	"app/internal/parts/env_int"
)

var meterWarnedUnmetered bool // the lazy warn-once flag (a real provider running unmetered warns ONCE per process)

// meterCall meters ONE provider call's usage into the core usage sink (which forwards to llm_usage when present).
// NEVER panics — a meter failure must not break the run. Real providers always meter; the fake meters only when
// ARMED (AI_USAGE_METER_FAKE=1), so the default fake stays free + the bar stays inert.
func meterCall(owner string, sessionID int, now int64, u *usageInfo) {
	if u == nil {
		return
	}
	provider := core.EnvOr("AI_PROVIDER", "fake")
	if provider == "fake" && os.Getenv("AI_USAGE_METER_FAKE") != "1" {
		return // fake is free + unmetered by default (arm to see the wire)
	}
	// the identifier (exactly-once): the provider's response id when present; else agent's OWN atomic-minted fallback
	identifier := u.Identifier
	if identifier == "" {
		identifier = "agent:" + strconv.Itoa(sessionID) + ":" + strconv.Itoa(core.NextID("agent_usage_seq"))
	}
	call := core.UsageCall{Identifier: identifier, Provider: provider, Model: u.Model,
		InputTokens: u.InputTokens, OutputTokens: u.OutputTokens, CacheReadInputTokens: u.CacheReadInputTokens,
		CacheCreationInputTokens: u.CacheCreationInputTokens, ReasoningTokens: u.ReasoningTokens}
	status := core.UsageRecord(owner, call, now) // never panics; the run's success is independent of the meter's
	if status == "no-meter" && provider != "fake" && !meterWarnedUnmetered {
		meterWarnedUnmetered = true // lazy, first-real-use only (no boot-time check — the import-order trap)
		log.Printf("AI_PROVIDER=%s but no usage meter is registered in this build — LLM spend is NOT being recorded "+
			"(add the llm_usage domain, or meter externally via POST /llm_usage/events)", provider)
	}
}

const msgTruncMarker = "…[truncated]…" // advisory only — a tool may emit it; never key a decision on it

// the agent loop/buffer bounds (max iterations · history ring-buffer · per-message cap) come from env via the
// central env_int part — the ×3-safe parse (trim · reject non-integer/hex/exponent · |value| > 2**53-1 -> default).

// msgMax is the per-message codepoint cap (middle-truncate). Floor 64, default 4000. Same env as python/node.
func msgMax() int {
	if n := env_int.EnvInt(core.EnvOr("AGENT_MAX_MSG_CHARS", ""), 4000); n >= 64 {
		return n
	}
	return 64
}

// truncateMiddle bounds s to cap CODE POINTS, keeping the HEAD and TAIL with a marker between (the tool answer/error
// is often at the end) — matches smolagents. Rune-based, so identical ×3 with python (len) / node ([...s].length).
func truncateMiddle(s string, cap int) string {
	if utf8.RuneCountInString(s) <= cap {
		return s
	}
	r := []rune(s)
	keep := cap - utf8.RuneCountInString(msgTruncMarker)
	if keep <= 0 {
		return string(r[:cap])
	}
	head := keep / 2
	return string(r[:head]) + msgTruncMarker + string(r[len(r)-(keep-head):])
}

// sseChunkSize is the SSE delta window in CODE POINTS (env SSE_CHUNK_CODEPOINTS via the env_int part; sub-1 ->
// the default 12) — a streamed run response chops the FINAL output at the transport; the run loop is untouched.
func sseChunkSize() int {
	if n := env_int.EnvInt(core.EnvOr("SSE_CHUNK_CODEPOINTS", ""), 12); n >= 1 {
		return n
	}
	return 12
}

// chunkOutput splits the final output into fixed CODE-POINT windows for the streamed response — the same rune
// discipline as truncateMiddle (python len/slice · go []rune · node [...s]), so the delta frames are identical
// ×3 and always concatenate back to exactly the sync output.
func chunkOutput(s string) []string {
	r := []rune(s)
	k := sseChunkSize()
	chunks := make([]string, 0, (len(r)+k-1)/k)
	for i := 0; i < len(r); i += k {
		chunks = append(chunks, string(r[i:min(i+k, len(r))]))
	}
	return chunks
}

type agMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

var agMemory = core.NewKV[string, []agMessage]("agent_memory")

func maxIterations() int {
	if n := env_int.EnvInt(core.EnvOr("AGENT_MAX_ITERATIONS", ""), 6); n >= 1 {
		return n
	}
	return 6
}

// historyMax is the per-session ring-buffer cap (drop-oldest) — keeps the stored blob, the per-turn feed, and GET
// /messages BOUNDED (the unbounded-history O(n^2)/OOM/cost soft-DoS). MUST be >= maxIterations+2 so a run never evicts
// its own user turn mid-loop. Same env + floor as python config.HISTORY_MAX / node maxHistory().
func historyMax() int {
	n := env_int.EnvInt(core.EnvOr("AGENT_HISTORY_MAX", ""), 200)
	if floor := maxIterations() + 2; n < floor {
		n = floor
	}
	return n
}

func remember(sessionID int, role, content string) {
	// content is ALREADY well-formed UTF-8 here when it arrives via the JSON body (the json decoder substitutes
	// U+FFFD at the boundary), so well_formed.MakeWellFormed would be identity — python/node call it explicitly (a
	// decoded `\ud800` escape CAN exist there), Go gets it free. (Edge: a %ED%A0%80 in a non-JSON path COULD give Go
	// a raw WTF-8 string — then Go STORES the raw bytes where python/node store U+FFFD, a minor stored-content drift;
	// the OBSERVATION still converges because encoding/json.Marshal substitutes U+FFFD at encode and NEVER raises, so
	// the response can't 5xx — the safety property holds ×3, the stored bytes are a cosmetic divergence only.)
	// atomic append via the Do seam: a Get-then-Set RACES — concurrent appends to one session lose a message
	// (the rbac F1 class). Do holds the write lock across read+write.
	content = truncateMiddle(content, msgMax()) // bound each stored message (a giant obs/input would flood the buffer + next prompt)
	// RING-BUFFER: keep only the last historyMax messages (drop-oldest) — the BOUNDED conversation buffer.
	agMemory.Do(strconv.Itoa(sessionID), func(cur []agMessage, exists bool) ([]agMessage, bool) {
		next := append(cur, agMessage{Role: role, Content: content})
		if max := historyMax(); len(next) > max {
			next = next[len(next)-max:]
		}
		return next, true
	})
}

func history(sessionID int) []agMessage {
	hist, _ := agMemory.Get(strconv.Itoa(sessionID))
	if hist == nil {
		return []agMessage{}
	}
	return hist
}

func runLoop(provider llmProvider, sessionID int, system, userInput string, owner string, now int64) (string, int, bool, error) {
	remember(sessionID, "user", userInput)
	budget := maxIterations()
	done := func(output string, iterations int, terminated bool) (string, int, bool, error) {
		output = truncateMiddle(output, msgMax()) // the RESPONSE matches the stored copy (bounded)
		remember(sessionID, "assistant", output)
		return output, iterations, terminated, nil
	}
	for i := 0; i < budget; i++ {
		resp, err := provider.complete(system, history(sessionID))
		if err != nil {
			// an upstream-mapped adapter failure (502/504) — surfaced to the route, which renders it as the
			// ONE problem+json envelope. The user turn stays in history (it was received); no fabricated
			// assistant turn is ever appended. Identical in python (raise) and node (throw).
			return "", 0, false, err
		}
		meterCall(owner, sessionID, now, resp.usage) // meter this call's spend (never breaks the run)
		if resp.final != nil {                       // the agent answered -> done
			return done(*resp.final, i+1, false)
		}
		result, ok := runTool(resp.tool, resp.args)
		observation := result
		if !ok {
			observation = "error: " + result // graceful, fed back, never a crash
		}
		remember(sessionID, "tool", observation)
	}
	return done("stopped: max iterations reached", budget, true) // the terminate guard
}
