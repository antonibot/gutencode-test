// Package ai_provider — the unified LLM gateway: the ONE seam every caller uses for completions. The dangerous
// property is BILLING HONESTY: the meter is CONSERVED (usage always equals the sum of every billed completion —
// the update is one atomic read-modify-write through (*KV).Do) and a cache replay is NEVER re-billed. Model
// fallback degrades an unknown model to the default — never a 5xx. The offline fake is deterministic (tokens are
// utf-8 BYTE lengths — go's len(string) — the ×3-identical semantic); SHIPPED stdlib adapters for Anthropic +
// OpenAI swap in behind the same shape (INTEROP.md): AI_PROVIDER=anthropic|openai with the matching key env set
// round-trips the REAL API per call — net/http only, env read at call time, one configured model per deployment
// (AI_MODEL or the provider default), upstream non-2xx mapped to a LOUD 502 problem+json with a SANITIZED
// snippet (the key is never echoed), timeout/network failure to 504, and a failed call is never billed and
// never cached. HONESTY CONTRACT (identical ×3): AI_PROVIDER naming a real provider WITHOUT its key env — or
// any unknown value — makes POST /ai/complete REFUSE per call with a 501 that says exactly what to set, NEVER
// silent fake output under a real provider's name (GET /ai/usage keeps working: the failure stays local to
// completions, and a refusal is never billed or cached). The cache key comes from the digest part. Durable:
// meter and cache survive a restart.
package ai_provider

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/env_int"
)

const aiProviderDefault = "fake"

var aiProviderModels = map[string]bool{"fake": true, "fast": true, "smart": true}

// the SHIPPED real providers (INTEROP.md): key env · default model · base-URL env + real endpoint. The base-URL
// override is both a proxy/gateway feature and the offline test seam (the invariant drives a loopback stub).
var (
	aiProviderKeyEnv      = map[string]string{"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}
	aiProviderRealModel   = map[string]string{"anthropic": "claude-sonnet-4-6", "openai": "gpt-4o"}
	aiProviderBaseEnv     = map[string]string{"anthropic": "ANTHROPIC_BASE_URL", "openai": "OPENAI_BASE_URL"}
	aiProviderBaseDefault = map[string]string{"anthropic": "https://api.anthropic.com", "openai": "https://api.openai.com"}
)

const (
	aiProviderAnthropicVersion = "2023-06-01"      // the Messages API version pin — a wire constant the API requires
	aiProviderUpstreamCap      = 1048576           // bytes read of a provider response (a text completion is KBs)
	aiProviderMaxSafeTokens    = 9007199254740991  // 2**53-1 — a reported token count past this bills 0, never overflows
)

// aiProviderSelect — the HONESTY GATE (identical in python/node): returns which provider runs this call —
// "fake" (the offline default) or a SHIPPED real adapter whose key env is set — or "" plus the 501 refusal
// detail (byte-identical ×3) for a keyless real name / unknown value. Checked per CALL (not at boot) and
// BEFORE the cache/meter, so the app stays usable and a refusal is never billed or cached. 501 Not
// Implemented — deliberate: not 503 (the missing key is not transient; retrying cannot succeed until an
// operator sets one) and not a 4xx (the request is valid; the DEPLOYMENT lacks the capability).
func aiProviderSelect() (string, string) {
	which := core.EnvOr("AI_PROVIDER", "fake")
	if which == "fake" {
		return which, ""
	}
	if keyEnv, ok := aiProviderKeyEnv[which]; ok {
		if os.Getenv(keyEnv) == "" { // empty counts as unset, like EnvOr
			return "", "provider '" + which + "' needs " + keyEnv + " — see INTEROP.md"
		}
		return which, ""
	}
	return "", "unknown provider '" + which + "' — see INTEROP.md"
}

// aiProviderUsageInt contains a provider-reported token count: an integral number in [0, 2**53-1] bills as-is;
// anything else (absent, non-numeric, negative, fractional, absurd magnitude) bills 0 — the CONSERVED meter can
// never be poisoned or overflowed by an upstream payload. Identical decision in python/node.
func aiProviderUsageInt(v any) int {
	f, ok := v.(float64)
	if !ok || f < 0 || f > aiProviderMaxSafeTokens || f != math.Trunc(f) {
		return 0
	}
	return int(f)
}

// aiProviderCallReal — the SHIPPED adapter (net/http only, no SDK): POST the provider's completion API, extract
// the text + real token usage into the gateway's response shape. Env is read per CALL (key, base URL, timeout,
// ceiling). Failure map (identical ×3): upstream non-2xx -> (502, status + a <=200-char body snippet with the
// key value REDACTED — never echo credentials, never dump headers); timeout / network / bad endpoint -> 504; a
// 2xx whose body isn't the documented shape -> 502. Returns (result, 0, "") on success, else (zero, status,
// detail) — the caller refuses BEFORE the cache write and the meter add, so a failure is never billed or cached.
func aiProviderCallReal(which, model, prompt string) (aiProviderResult, int, string) {
	keyVal := os.Getenv(aiProviderKeyEnv[which]) // non-empty — aiProviderSelect checked
	timeout := env_int.EnvInt(core.EnvOr("AI_TIMEOUT_SECONDS", ""), 60, 1, 600)
	base := strings.TrimRight(core.EnvOr(aiProviderBaseEnv[which], aiProviderBaseDefault[which]), "/")
	var url string
	var payload map[string]any
	if which == "anthropic" {
		url = base + "/v1/messages"
		payload = map[string]any{"model": model,
			"max_tokens": env_int.EnvInt(core.EnvOr("AI_MAX_TOKENS", ""), 1024, 1),
			"messages":   []map[string]string{{"role": "user", "content": prompt}}}
	} else {
		url = base + "/v1/chat/completions"
		payload = map[string]any{"model": model,
			"messages": []map[string]string{{"role": "user", "content": prompt}}}
	}
	netFail := "provider '" + which + "' upstream timeout or network failure"
	shapeFail := "provider '" + which + "' upstream error: unexpected response shape"
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil { // a malformed base URL is an unreachable endpoint, not a caller error
		return aiProviderResult{}, 504, netFail
	}
	req.Header.Set("content-type", "application/json")
	if which == "anthropic" { // OUTBOUND credentials on the upstream request (inbound identity stays core's)
		req.Header.Set("x-api-key", keyVal)
		req.Header.Set("anthropic-version", aiProviderAnthropicVersion)
	} else {
		req.Header.Set("Authorization", "Bearer "+keyVal)
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return aiProviderResult{}, 504, netFail
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, aiProviderUpstreamCap+1))
	if err != nil {
		return aiProviderResult{}, 504, netFail
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 { // non-2xx: loud + sanitized, never invented text
		snippet := string(raw)
		if keyVal != "" {
			snippet = strings.ReplaceAll(snippet, keyVal, "[redacted]")
		}
		if r := []rune(snippet); len(r) > 200 {
			snippet = string(r[:200])
		}
		return aiProviderResult{}, 502,
			"provider '" + which + "' upstream error (HTTP " + strconv.Itoa(resp.StatusCode) + "): " + snippet
	}
	if len(raw) > aiProviderUpstreamCap {
		return aiProviderResult{}, 502, shapeFail
	}
	// extract text + usage. Go's json decoder substitutes U+FFFD for any invalid escape/byte at decode, so the
	// extracted text is always UTF-8-serializable (python/node apply the same containment explicitly).
	out := aiProviderResult{Model: model}
	if which == "anthropic" {
		var parsed struct {
			Content []struct {
				Type string  `json:"type"`
				Text *string `json:"text"`
			} `json:"content"`
			Usage map[string]any `json:"usage"`
		}
		if json.Unmarshal(raw, &parsed) != nil || parsed.Content == nil {
			return aiProviderResult{}, 502, shapeFail
		}
		text := "" // concatenate the text blocks (usually exactly one)
		for _, b := range parsed.Content {
			if b.Type == "text" {
				if b.Text == nil {
					return aiProviderResult{}, 502, shapeFail
				}
				text += *b.Text
			}
		}
		out.Output = text
		out.Usage.PromptTokens = aiProviderUsageInt(parsed.Usage["input_tokens"])
		out.Usage.CompletionTokens = aiProviderUsageInt(parsed.Usage["output_tokens"])
	} else {
		var parsed struct {
			Choices []struct {
				Message struct {
					Content *string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
			Usage map[string]any `json:"usage"`
		}
		if json.Unmarshal(raw, &parsed) != nil || len(parsed.Choices) == 0 || parsed.Choices[0].Message.Content == nil {
			return aiProviderResult{}, 502, shapeFail
		}
		out.Output = *parsed.Choices[0].Message.Content
		out.Usage.PromptTokens = aiProviderUsageInt(parsed.Usage["prompt_tokens"])
		out.Usage.CompletionTokens = aiProviderUsageInt(parsed.Usage["completion_tokens"])
	}
	// cost stays 0: token counts are the provider's real numbers, but no price table is baked in (prices move) —
	// wire your own pricing into the billed usage if you want money units in the meter.
	out.Usage.Cost = 0
	return out, 0, ""
}

type aiProviderUsageT struct {
	Requests         int `json:"requests"`
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	Cost             int `json:"cost"`
}

type aiProviderResult struct {
	Model  string `json:"model"`
	Output string `json:"output"`
	Usage  struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		Cost             int `json:"cost"`
	} `json:"usage"`
}

var (
	aiProviderMeter = core.NewKV[string, aiProviderUsageT]("ai_provider_meter")
	aiProviderCache = core.NewKV[string, aiProviderResult]("ai_provider_cache")
)

func aiProviderFake(model, prompt string) aiProviderResult {
	// deterministic offline completion: token counts are BYTE lengths so all three languages agree
	r := aiProviderResult{Model: model, Output: "[" + model + "] " + strings.ToUpper(prompt)}
	r.Usage.PromptTokens = len(prompt)
	r.Usage.CompletionTokens = len(prompt) + len(model) + 3
	r.Usage.Cost = 0
	return r
}

func AiProviderComplete(w http.ResponseWriter, r *http.Request) {
	// PARSE: decode the body as raw JSON FIRST — DecodeJSON enforces the body cap (413) and drains the stream;
	// only malformed JSON fails here. Per-field type checks are SEMANTIC and run AFTER auth (below), so an
	// unauthenticated ill-typed body is 401, not a 422 that leaks the body shape. (×3 parity, body-only POST.)
	raw, ok := core.DecodeJSON[json.RawMessage](w, r)
	if !ok {
		return
	}
	// AUTH: authenticated mutation, ANY authenticated caller (no/invalid token -> 401), BEFORE any semantics.
	if _, ok := core.RequireIdentity(w, r); !ok {
		return
	}
	// FOLLOW-ON: the meter stays a single global "total" key for now; the PER-SUBJECT meter + per-caller cache
	// key (bill/quota the caller, scope the cache by subject) is a documented data-model change — see INTEROP.md.
	// SEMANTIC: now the strict string checks (prompt:7 / model:7 -> 422), exactly like python's pydantic after the dep.
	var in struct {
		Prompt *string `json:"prompt"`
		Model  *string `json:"model"`
	}
	if json.Unmarshal(raw, &in) != nil || in.Prompt == nil || *in.Prompt == "" {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	which, refusal := aiProviderSelect()
	if refusal != "" {
		core.WriteProblem(w, 501, refusal) // fail LOUD on a keyless/unknown AI_PROVIDER — never silent fake output
		return
	}
	model := aiProviderDefault // FALLBACK: unknown -> default, never a 5xx
	if which == "fake" {
		if in.Model != nil && aiProviderModels[*in.Model] {
			model = *in.Model
		}
	} else {
		// a wired gateway serves ONE configured model per deployment (AI_MODEL, else the provider default), so
		// spend stays operator-controlled: the request `model` field is not a caller escalation channel — any
		// value falls back to the configured model (the same unknown->default doctrine as the offline tiers).
		model = core.EnvOr("AI_MODEL", aiProviderRealModel[which])
	}
	key := digest.DigestHex(model, *in.Prompt)
	if prior, hit := aiProviderCache.Get(key); hit {
		core.WriteJSON(w, 200, map[string]any{"model": prior.Model, "output": prior.Output,
			"usage": prior.Usage, "cached": true}) // a replay is served stored and NEVER re-billed
		return
	}
	var result aiProviderResult
	if which == "fake" {
		result = aiProviderFake(model, *in.Prompt)
	} else {
		res, status, detail := aiProviderCallReal(which, model, *in.Prompt)
		if status != 0 {
			core.WriteProblem(w, status, detail) // upstream failure: refused BEFORE the cache/meter — never billed or cached
			return
		}
		result = res
	}
	// rmw-safe: convergent-or-benign — the cache key is digest(model, prompt); the offline completion is
	// deterministic (identical concurrent writes), and a sampling real provider makes two concurrent misses a
	// benign last-write-wins cache fill (each real call WAS made and IS billed, so conservation still holds)
	aiProviderCache.Set(key, result)
	// CONSERVED: one atomic add per billed completion
	aiProviderMeter.Do("total", func(m aiProviderUsageT, exists bool) (aiProviderUsageT, bool) {
		m.Requests++
		m.PromptTokens += result.Usage.PromptTokens
		m.CompletionTokens += result.Usage.CompletionTokens
		m.Cost += result.Usage.Cost
		return m, true
	})
	core.WriteJSON(w, 200, map[string]any{"model": result.Model, "output": result.Output,
		"usage": result.Usage, "cached": false})
}

func AiProviderUsage(w http.ResponseWriter, r *http.Request) {
	// ADMIN-ONLY: this is the GLOBAL usage meter (total requests/tokens/cost across ALL completions) — it exposes
	// the app's total AI spend. authn -> authz BEFORE the read (no token -> 401, a valid non-admin -> 403), ×3.
	if _, ok := core.RequireAdmin(w, r); !ok {
		return
	}
	m, _ := aiProviderMeter.Get("total")
	core.WriteJSON(w, 200, m)
}
