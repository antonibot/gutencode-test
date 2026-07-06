package agent

// The provider PORT + the deterministic fake (the default and the test oracle — the whole stack runs offline)
// + the SHIPPED real adapters (Anthropic Messages · OpenAI Chat Completions, net/http only, no SDK) + the ONE
// selection site (AI_PROVIDER env). HONESTY CONTRACT (identical in python/node): the offline fake is the
// default, and a recognized real provider — anthropic, openai — runs the moment its key env is set; a real
// name WITHOUT its key, or any unknown value, is REFUSED per call (a 501 at the run route), NEVER a silent
// fake completion under a real provider's name. Adapters read env per CALL (AI_MODEL · AI_TIMEOUT_SECONDS ·
// AI_MAX_TOKENS · the base-URL overrides — the base URL is both a proxy/gateway feature and the offline test
// seam), return ONE final text (native tool-use/token streaming deliberately not mapped — the SSE mode chunks
// the final output at the transport), and map upstream failure instead of inventing text: non-2xx -> 502 with
// a sanitized <=200-char snippet (the key value is REDACTED, headers never dumped), timeout/network -> 504.
// Protocol of the fake (identical to the python/node fakes): 'use <tool> <args>' -> a structured tool call ·
// a tool observation -> 'answer: <obs>' · 'use forever …' -> NEVER finalizes (so the iteration guard is
// provable black-box) · else '[fake] <input>'.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"app/internal/core"
	"app/internal/parts/env_int"
)

type llmResponse struct {
	final *string
	tool  string
	args  map[string]string
	usage *usageInfo // the provider call's token usage (metered into llm_usage when present); nil = no usage reported
}

// usageInfo — the provider call's reported spend, carried back so the run loop can METER it. Identifier is the
// provider's response id (the natural exactly-once key; "" -> the run loop mints a fallback); Model is the model the
// adapter actually sent (so the meter's price table can price it).
type usageInfo struct {
	Identifier               string
	Model                    string
	InputTokens              int64
	OutputTokens             int64
	CacheReadInputTokens     int64
	CacheCreationInputTokens int64
	ReasoningTokens          int64
}

type llmProvider interface {
	complete(system string, messages []agMessage) (llmResponse, error)
}

// fakeUsage — deterministic NONZERO counts so the metering wire is provable offline (armed via AI_USAGE_METER_FAKE);
// model "fake" is priced at zero in the meter's table (an explicit priced-at-zero row, not a silent $0). Same ×3.
func fakeUsage() *usageInfo { return &usageInfo{Model: "fake", InputTokens: 3, OutputTokens: 5} }

// providerFailure carries an upstream-mapped refusal (502 upstream error / 504 timeout) from an adapter out
// of the run loop to the route, which renders it as the ONE problem+json envelope — before any SSE byte.
type providerFailure struct {
	status int
	detail string
}

func (e *providerFailure) Error() string { return e.detail }

type fakeLLM struct{}

func (fakeLLM) complete(system string, messages []agMessage) (llmResponse, error) {
	last := messages[len(messages)-1]
	runInput := ""
	for _, m := range messages {
		if m.Role == "user" {
			runInput = m.Content
		}
	}
	if strings.HasPrefix(runInput, "use forever") {
		return llmResponse{tool: "echo", args: map[string]string{"text": "again"}, usage: fakeUsage()}, nil
	}
	if last.Role == "tool" {
		out := "answer: " + last.Content
		return llmResponse{final: &out, usage: fakeUsage()}, nil
	}
	if strings.HasPrefix(last.Content, "use ") {
		rest := strings.SplitN(last.Content[4:], " ", 2)
		tool := rest[0]
		value := ""
		if len(rest) > 1 {
			value = rest[1]
		}
		args := map[string]string{"text": value}
		if tool == "calc" {
			args = map[string]string{"expr": value}
		}
		return llmResponse{tool: tool, args: args, usage: fakeUsage()}, nil
	}
	out := "[fake] " + last.Content
	return llmResponse{final: &out, usage: fakeUsage()}, nil
}

const (
	anthropicVersion = "2023-06-01" // the Messages API version pin — a wire constant the API requires
	upstreamBodyCap  = 1048576      // bytes read of a provider response (a text completion is KBs)
)

// mergedTurns maps the port's roles onto provider wire roles: tool observations become user turns (the
// minimal-adapter doctrine — the model sees the observation as conversation), then consecutive same-role
// turns merge (newline-joined) so the wire alternates user/assistant cleanly. Identical in python/node.
func mergedTurns(messages []agMessage) []map[string]string {
	turns := []map[string]string{}
	for _, m := range messages {
		role := "user"
		if m.Role == "assistant" {
			role = "assistant"
		}
		if n := len(turns); n > 0 && turns[n-1]["role"] == role {
			turns[n-1]["content"] += "\n" + m.Content
		} else {
			turns = append(turns, map[string]string{"role": role, "content": m.Content})
		}
	}
	return turns
}

func shapeFailure(which string) *providerFailure {
	return &providerFailure{502, "provider '" + which + "' upstream error: unexpected response shape"}
}

// providerPost POSTs a JSON body and returns the raw 2xx response — or the mapped failure: non-2xx -> 502
// with the status + a <=200-char snippet with the key value REDACTED (credentials never echo, headers never
// dump); timeout / network / bad endpoint -> 504. The adapter never fabricates a completion.
func providerPost(which, url string, headers map[string]string, payload map[string]any, key string) ([]byte, error) {
	timeout := env_int.EnvInt(core.EnvOr("AI_TIMEOUT_SECONDS", ""), 60, 1, 600)
	netFail := &providerFailure{504, "provider '" + which + "' upstream timeout or network failure"}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil { // a malformed base URL is an unreachable endpoint, not a caller error
		return nil, netFail
	}
	req.Header.Set("content-type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, netFail
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, upstreamBodyCap+1))
	if err != nil {
		return nil, netFail
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet := string(raw)
		if key != "" {
			snippet = strings.ReplaceAll(snippet, key, "[redacted]")
		}
		if r := []rune(snippet); len(r) > 200 {
			snippet = string(r[:200])
		}
		return nil, &providerFailure{502,
			"provider '" + which + "' upstream error (HTTP " + strconv.Itoa(resp.StatusCode) + "): " + snippet}
	}
	if len(raw) > upstreamBodyCap {
		return nil, shapeFailure(which)
	}
	return raw, nil
}

// anthropicLLM — POST {ANTHROPIC_BASE_URL}/v1/messages: x-api-key auth, the system prompt as the top-level
// `system` field; the concatenated text blocks come back as the final answer (go's json decoder substitutes
// U+FFFD for any invalid escape, so the text is always valid UTF-8).
type anthropicLLM struct{}

func (anthropicLLM) complete(system string, messages []agMessage) (llmResponse, error) {
	key := os.Getenv("ANTHROPIC_API_KEY") // non-empty — the selection site checked
	base := strings.TrimRight(core.EnvOr("ANTHROPIC_BASE_URL", "https://api.anthropic.com"), "/")
	model := core.EnvOr("AI_MODEL", "claude-sonnet-4-6")
	payload := map[string]any{
		"model":      model,
		"max_tokens": env_int.EnvInt(core.EnvOr("AI_MAX_TOKENS", ""), 1024, 1),
		"messages":   mergedTurns(messages),
	}
	if system != "" {
		payload["system"] = system
	}
	raw, err := providerPost("anthropic", base+"/v1/messages",
		map[string]string{"x-api-key": key, "anthropic-version": anthropicVersion}, payload, key)
	if err != nil {
		return llmResponse{}, err
	}
	var parsed struct {
		Id      string `json:"id"`
		Content []struct {
			Type string  `json:"type"`
			Text *string `json:"text"`
		} `json:"content"`
		Usage *struct {
			InputTokens              int64 `json:"input_tokens"`
			OutputTokens             int64 `json:"output_tokens"`
			CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
			CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(raw, &parsed) != nil || parsed.Content == nil {
		return llmResponse{}, shapeFailure("anthropic")
	}
	text := "" // concatenate the text blocks (usually exactly one)
	for _, b := range parsed.Content {
		if b.Type == "text" {
			if b.Text == nil {
				return llmResponse{}, shapeFailure("anthropic")
			}
			text += *b.Text
		}
	}
	resp := llmResponse{final: &text}
	if parsed.Usage != nil { // the provider's reported spend (metered into llm_usage)
		resp.usage = &usageInfo{Identifier: parsed.Id, Model: model,
			InputTokens: parsed.Usage.InputTokens, OutputTokens: parsed.Usage.OutputTokens,
			CacheReadInputTokens: parsed.Usage.CacheReadInputTokens, CacheCreationInputTokens: parsed.Usage.CacheCreationInputTokens}
	}
	return resp, nil
}

// openaiLLM — POST {OPENAI_BASE_URL}/v1/chat/completions: Bearer auth, the system prompt riding as the first
// message; choices[0].message.content comes back as the final answer.
type openaiLLM struct{}

func (openaiLLM) complete(system string, messages []agMessage) (llmResponse, error) {
	key := os.Getenv("OPENAI_API_KEY") // non-empty — the selection site checked
	base := strings.TrimRight(core.EnvOr("OPENAI_BASE_URL", "https://api.openai.com"), "/")
	model := core.EnvOr("AI_MODEL", "gpt-4o")
	turns := mergedTurns(messages)
	if system != "" {
		turns = append([]map[string]string{{"role": "system", "content": system}}, turns...)
	}
	payload := map[string]any{"model": model, "messages": turns}
	raw, err := providerPost("openai", base+"/v1/chat/completions",
		map[string]string{"Authorization": "Bearer " + key}, payload, key)
	if err != nil {
		return llmResponse{}, err
	}
	var parsed struct {
		Id      string `json:"id"`
		Choices []struct {
			Message struct {
				Content *string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(raw, &parsed) != nil || len(parsed.Choices) == 0 || parsed.Choices[0].Message.Content == nil {
		return llmResponse{}, shapeFailure("openai")
	}
	resp := llmResponse{final: parsed.Choices[0].Message.Content}
	if parsed.Usage != nil { // openai reports prompt/completion tokens (metered into llm_usage)
		resp.usage = &usageInfo{Identifier: parsed.Id, Model: model,
			InputTokens: parsed.Usage.PromptTokens, OutputTokens: parsed.Usage.CompletionTokens}
	}
	return resp, nil
}

// realProviders — the SHIPPED real providers: name -> key env + constructor. Adding a provider = one row +
// one adapter type.
var realProviders = map[string]struct {
	keyEnv string
	build  func() llmProvider
}{
	"anthropic": {"ANTHROPIC_API_KEY", func() llmProvider { return anthropicLLM{} }},
	"openai":    {"OPENAI_API_KEY", func() llmProvider { return openaiLLM{} }},
}

// getProvider — the ONE selection site; change AI_PROVIDER env, never a call site. Returns the provider and
// "" when this build can run it (the fake, or a shipped adapter whose key env is set), else nil and the 501
// refusal detail (byte-identical ×3) naming exactly what to set. 501 is deliberate: not 503 (the missing key
// is not transient; retrying cannot succeed until an operator sets one) and not a 4xx (the request is valid;
// the DEPLOYMENT lacks the capability).
func getProvider() (llmProvider, string) {
	which := core.EnvOr("AI_PROVIDER", "fake")
	if which == "fake" {
		return fakeLLM{}, ""
	}
	if p, ok := realProviders[which]; ok {
		if os.Getenv(p.keyEnv) == "" { // empty counts as unset, like EnvOr
			return nil, "provider '" + which + "' needs " + p.keyEnv + " — see INTEROP.md"
		}
		return p.build(), ""
	}
	return nil, "unknown provider '" + which + "' — see INTEROP.md"
}
