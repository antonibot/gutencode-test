# INTEROP.md — where the offline defaults end and your real providers plug in

Everything in this backend runs offline and deterministic out of the box — fake LLM, local store, in-process queue. Each section below is one module's seam map: the exact functions and environment knobs to wire a real provider behind, what stays fixed across the swap, and what each swap costs.

Modules with a provider seam: [agent](#agent) · [ai_memory](#ai_memory) · [ai_provider](#ai_provider) · [chat_threads](#chat_threads) · [evals](#evals) · [job_queue](#job_queue) · [llm_usage](#llm_usage) · [prompt_registry](#prompt_registry) · [rag](#rag) · [reporting](#reporting) · [secrets_vault](#secrets_vault)

## agent

The agent runtime ships **offline and deterministic** by default: with `AI_PROVIDER` unset (or `fake`) a
deterministic fake LLM makes the whole stack — run loop, tools, memory, tests — work with zero configuration
and zero cost. Nothing pretends to be a real model.

**Real adapters SHIP in this build.** Set `AI_PROVIDER=anthropic` or `AI_PROVIDER=openai` plus the matching
key env and every run round-trips the real API — standard-library HTTP only (no SDK dependency):

```
AI_PROVIDER=anthropic  ANTHROPIC_API_KEY=sk-ant-...   → POST {ANTHROPIC_BASE_URL}/v1/messages
AI_PROVIDER=openai     OPENAI_API_KEY=sk-...          → POST {OPENAI_BASE_URL}/v1/chat/completions
```

**The honesty contract:** nothing ever fakes silently. If `AI_PROVIDER` names a real provider whose key env
is not set, the run route **fails loud instead of faking**:

```
POST /agents/{id}/sessions/{sid}/run   with AI_PROVIDER=anthropic and no ANTHROPIC_API_KEY
-> 501 application/problem+json
   {"type":"about:blank","title":"provider 'anthropic' needs ANTHROPIC_API_KEY — see INTEROP.md",
    "status":501,"detail":"provider 'anthropic' needs ANTHROPIC_API_KEY — see INTEROP.md"}
```

- `AI_PROVIDER` unset / `fake` → the offline deterministic provider (unchanged, always works, no network).
- `AI_PROVIDER=anthropic|openai` **with** the key env set → the shipped adapter calls the real API per run.
- `AI_PROVIDER=anthropic|openai` **without** its key env → the `501` above, naming the exact variable to set.
- Any other value (a typo, an unsupported name) → `501` with `unknown provider '<value>' — see INTEROP.md`.
- The check runs per call, before the loop touches memory — a refused run leaves no trace, and only the run
  route is affected: creating agents/sessions and reading messages never touch the provider. Identical in
  Python, Go, and Node.

### How the wired adapters behave

- **The conversation you already have is what the model sees.** The bounded, ring-buffered session history is
  mapped onto the provider's wire: `tool` observations ride as user turns (the minimal-adapter doctrine) and
  consecutive same-role turns are merged, so the wire alternates cleanly; the agent's `system_prompt` goes out
  as Anthropic's top-level `system` field / OpenAI's leading `system` message.
- **Final answers only.** The shipped adapters return one complete text per call; they do not map the
  provider's native tool-use onto the runtime's `{tool, args}` — the built-in tools are still exercised by the
  offline fake (which is also the test oracle), and mapping native tool calls is the natural first
  customization (return `{tool, args}` from the adapter instead of `final`; the loop already handles it).
- **Failure is mapped, never invented.** Upstream non-2xx → `502` problem+json carrying the upstream status
  plus a ≤200-character body snippet with your key value redacted (credentials are never echoed; headers are
  never dumped). Timeout (`AI_TIMEOUT_SECONDS`, default 60s per provider call) or any network failure → `504`.
  A 2xx that isn't the documented response shape → `502`. The user turn stays in history (it was received);
  no fabricated assistant turn is ever appended.
- **One configured model per deployment** — `AI_MODEL`, else the provider default (anthropic
  `claude-sonnet-4-6`, openai `gpt-4o`). Model choice is operator configuration, never caller input.
- **Spend is metered automatically.** When the `llm_usage` domain is in your build, each provider call that
  reports token usage is metered into the per-owner cost ledger (`POST /llm_usage/events`) **for the run's
  authenticated caller** — one event per call, the provider's response id as the exactly-once key. Real providers
  always meter; the offline fake meters only when `AI_USAGE_METER_FAKE=1` (so the default fake stays free and the
  test bar stays inert). The wire is **availability-first**: a meter write can never break a run — a failure is
  logged with the event id + payload for a safe, exactly-once operator replay via `POST /llm_usage/events`, and the
  run still returns its answer. A build **without** `llm_usage` runs unmetered (a real provider warns once, loudly,
  at first use); the `/ai` gateway keeps its own separate global ops meter. The mechanism is a core seam
  (`core.usage_record`) that `llm_usage` registers its own recorder into, so the spend ledger stays owned by
  `llm_usage` (its price table is the one cost authority). See the `llm_usage` INTEROP for the metered→billed recipe.

### Streaming (SSE)

The run route can stream its answer as **Server-Sent Events** — the same wire convention OpenAI, Anthropic and
the Vercel AI SDK converged on. Opt in per request with the canonical **`?stream=1`** query flag (or the
equivalent `Accept: text/event-stream` header); without it the route answers plain JSON exactly as before. A
`stream` field in the JSON body is **not** a trigger — the request body stays byte-identical in both modes.

```
POST /agents/{id}/sessions/{sid}/run?stream=1      body: {"input": "use calc 2+2"}

event: delta
data: {"delta":"answer: 4.0"}

event: done
data: {"session_id":1,"output":"answer: 4.0","iterations":2,"terminated":false}
```

- Each `event: delta` carries a JSON-wrapped text chunk; concatenating the `delta` values reconstructs exactly
  the sync response's `output`. The terminal `event: done` carries the **full sync JSON body** — a streaming
  client needs no second request for the envelope. Identical in Python, Go, and Node.
- Errors **before the first byte** (401 / 404 / 422 / the 501 above / a wired adapter's 502/504 / 413) keep
  the normal `application/problem+json` envelope — streaming only begins after every guard has passed and the
  run has completed. A failure **after** the stream has started cannot change the already-sent 200; it is
  delivered as a terminal `event: error` frame (the same problem shape as frame data) and the stream closes.
- Chunking happens at the transport on the final output (`SSE_CHUNK_CODEPOINTS` codepoint windows): the whole
  answer — fake or wired — is computed first, so streaming demonstrates the wire contract, not token latency.
  The shipped adapters deliberately do not request provider-native token streams; feeding native deltas
  through the same frame path is a customization.
- **Reverse proxies:** buffering proxies are the #1 real-world SSE failure. The response sets
  `Cache-Control: no-cache` and `X-Accel-Buffering: no`, but you must also disable proxy buffering for this
  route (nginx: `proxy_buffering off;`). The Go server's `WriteTimeout` (30s) bounds a response's total write
  time — generous for the offline provider; raise it in `cmd/server/main.go` if a wired run (up to
  `AGENT_MAX_ITERATIONS` provider calls) can exceed it.

### The port

A provider is one function: given the system prompt and the conversation so far, return **either** a final
answer **or** a structured tool call — never free text the runtime has to parse.

| language | seam file (the ONE selection site) | the shipped adapters |
|---|---|---|
| Python | `python/app_pkg/domains/agent/providers/factory.py` | `providers/real.py` — `AnthropicLLM` / `OpenAILLM`, each `complete(system, messages) -> LLMResponse` |
| Go | `go/internal/domains/agent/providers.go` | `anthropicLLM` / `openaiLLM` implementing `llmProvider` |
| Node | `node/src/domains/agent/providers.js` | `anthropicLLM` / `openaiLLM`, each `complete(system, messages)` |

`messages` carry `role` (`user` | `assistant` | `tool`) and `content`. Return exactly one of:
- a **final answer** (`final` set) — ends the run;
- a **tool call** (`tool` + `args`) — the runtime executes the tool and feeds the observation back as a
  `tool` message on the next iteration (bounded by `AGENT_MAX_ITERATIONS`).

**Adding another provider** is one table row + one adapter in the language you deploy: mirror the shipped
adapter (build the request, extract the final text, keep the 501/502/504 failure map), then add the provider
name + key env to the selection table (`_REAL_PROVIDERS` / `realProviders` / `REAL_PROVIDERS`). The shipped
adapters are the reference implementation — same port, same honesty rules.

### Environment

| variable | meaning |
|---|---|
| `AI_PROVIDER` | `fake` (default, offline) · `anthropic` / `openai` (shipped adapters) · anything else fails loud |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | the credential for the selected provider — required (non-empty) when that provider is selected; read per call, never logged, never echoed in errors |
| `AI_MODEL` | the one model a wired deployment serves (empty = provider default: `claude-sonnet-4-6` / `gpt-4o`) |
| `AI_TIMEOUT_SECONDS` | per-provider-call HTTP ceiling (default 60, clamped 1..600); breach → `504` |
| `AI_MAX_TOKENS` | completion-token ceiling for providers that require one (anthropic; default 1024) |
| `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` | endpoint base overrides — route through a proxy/gateway or a local test double without code changes (also how the shipped tests prove the adapters offline) |
| `AGENT_MAX_ITERATIONS` | run-loop budget — the provider is called at most this many times per run |
| `AGENT_MAX_MSG_CHARS` / `AGENT_HISTORY_MAX` | per-message and per-session bounds; long content is middle-truncated before storage and before the provider sees it, so prompt size cannot grow without limit |
| `SSE_CHUNK_CODEPOINTS` | the streamed (`?stream=1`) response's delta window in codepoints (default 12) — see Streaming (SSE) above |
| `AI_USAGE_METER_FAKE` | arm usage metering for the offline fake (`1` = a fake run records a zero-cost `llm_usage` event, the offline-provable wire; default `0` keeps the fake free — a real provider always meters). Read per call |

## ai_memory

gutencode is **offline + deterministic**, so ai_memory ships the **port + shape + local impl**, never a live network
integration. This is the map for delegating to a hosted memory service, and the two intentional divergences.

### The settled contract (what the managed denominator converges on)
mem0 · Zep · Letta · AWS Bedrock AgentCore Memory · Vertex Memory Bank all expose the same verbs; ours map 1:1:

| ai_memory | the field (mem0 / Zep / Vertex) |
|---|---|
| `POST /ai_memory/memories` | `add` / `memory.add` / `CreateMemory` |
| `GET /ai_memory/memories` (per-scope, paginated) | `get_all` / `search(filters)` / `ListMemories` |
| `GET /ai_memory/memories/{id}` | `get` / `GetMemory` |
| `DELETE /ai_memory/memories/{id}` | `delete` |
| `DELETE /ai_memory/memories?scope=…` | `delete_all(user_id/scope)` / `reset` |

`scope` is the providers' `user_id` / session / namespace partition. To delegate, implement one adapter satisfying
these five verbs against the hosted API and keep `owner` = the authenticated subject on our side.

### Divergence 1 — we ENFORCE retention (the swap is a DOWNGRADE)
The dangerous property here — **BOUNDED growth** (per-owner `MAX_SCOPES × MAX_MEMORIES`, TTL-expiry, importance +
expired-first eviction) — is a **deliberate improvement**: most hosted long-term tiers (mem0 default, Letta archival,
Chroma, AutoGen `ListMemory`) are **grow-forever + explicit-delete-only** and punt retention to you (only Redis
Agent-Memory-Server, Weaviate Object-TTL, AWS `eventExpiryDuration`, Vertex TTL bound it). Swapping to such a provider
**loses** the enforced bound — re-impose it in the adapter (cap on add, TTL, periodic prune) or accept the regression.

### Divergence 2 — retrieval is a deterministic FLOOR, semantic is an OFF-by-default port
v1 retrieval is **recency (created_at desc, id asc) + exact scope/tag filter + ASCII-fold substring `?q=`** — a
labeled floor, honestly *not* "world-class keyword search". World-class long-term retrieval is embedding-dependent
(the Generative-Agents `recency × importance × relevance` score). To add relevance:

- import the **`embedding` PART** (import-legal: a domain may consume a part) to vectorize content on add + rank on
  read. **NEVER** import the vectorstore domain directly — domains never import sibling domains (the verifier's
  `code/boundaries` check walls exactly that). `importance` is already stored (it drives eviction); wiring it into a
  retrieval score is the v2 delta. Keep the port **OFF by default** so the offline build stays deterministic.

### `scope` is a PARTITION, not a security boundary
Only **`owner`** (the authenticated subject) isolates data — `get`/`delete` by id ignore `scope` (the composite row
key is `<owner>\x1f<id>`). Do **not** use `scope` to isolate one agent's memories from another's within an owner; use
distinct owners (tokens) for a real trust boundary.

### Honest limits (what we deliberately don't do in v1)
- **Verbs we OMIT vs mem0/Zep/Letta** — `update` (the store is append-only: a changed memory is a NEW add) and
  `history` / audit-of-forget (mem0 ships `history(id)` "for auditing"; Zep ships bi-temporal `valid_at`/`invalid_at`).
  The "1:1" mapping above covers the five convergent verbs; the audit trail is a **v2 compliance layer**. If you need
  GDPR-style *proof of deletion*, it is not in v1.
- **TTL-expiry is lazy read-hide, not erasure.** An expired memory is deterministically not *retrievable*, but its row
  and index entry are **not deleted** from the datastore until cap-eviction or an explicit `DELETE` reclaims them
  (parity with mem0's `expiration_date`). Only `DELETE`-by-id and cap-eviction **purge**. For guaranteed erasure of
  sensitive context, forget explicitly rather than relying on TTL.
- **The BOUND is on the RETRIEVABLE + counted store.** Per-owner growth is bounded by `MAX_SCOPES × MAX_MEMORIES` on
  the retrievable + counted surface (proven under a concurrent `forget_scope`+`add` race: reads gate on the per-owner
  scope registry, so an orphaned scope index is non-retrievable + non-counted). A row physically orphaned by that rare
  two-key race is reclaimed **lazily** (a v2 sweep), not eagerly.
- **`importance` biases eviction; it is not an absolute pin.** Higher importance survives an *older lower* one, but
  **expired-first dominates importance** (an expired high-importance memory is evicted before a live low one), and
  importance cannot exceed the per-scope cap. Do not treat it as a guaranteed "keep forever" flag.
- **An emptied/all-expired scope still occupies a `MAX_SCOPES` slot** until `DELETE ?scope=` frees it (TTL-expiry does
  not prune the scope from the per-owner registry). Bounded, but a UX quirk for scope-churning workloads.

## ai_provider

`POST /ai/complete` is the one seam every part of your app can use for LLM completions, with response caching
and a **conserved usage meter** (`GET /ai/usage`, admin-only: total requests/tokens/cost always equal the sum
of every billed completion). Out of the box it runs **offline and deterministic**: the built-in provider is a
fake whose output and token counts are pure functions of `(model, prompt)` — free, instant, and honest about
being fake.

**Real adapters SHIP in this build.** Set `AI_PROVIDER=anthropic` or `AI_PROVIDER=openai` plus the matching
key env and every completion round-trips the real API — standard-library HTTP only (no SDK dependency), with
the same response shape, caching, and metering as the offline fake:

```
AI_PROVIDER=anthropic  ANTHROPIC_API_KEY=sk-ant-...   → POST {ANTHROPIC_BASE_URL}/v1/messages
AI_PROVIDER=openai     OPENAI_API_KEY=sk-...          → POST {OPENAI_BASE_URL}/v1/chat/completions
```

**The honesty contract:** nothing ever pretends. If `AI_PROVIDER` names a real provider whose key env is not
set, completions **fail loud instead of faking**:

```
POST /ai/complete   with AI_PROVIDER=anthropic and no ANTHROPIC_API_KEY
-> 501 application/problem+json
   {"detail":"provider 'anthropic' needs ANTHROPIC_API_KEY — see INTEROP.md", ...}
```

- `AI_PROVIDER` unset / `fake` → the offline deterministic completion (unchanged, always works, no network).
- `AI_PROVIDER=anthropic|openai` **with** the key env set → the shipped adapter calls the real API.
- `AI_PROVIDER=anthropic|openai` **without** its key env → `501` naming the exact variable to set.
- Any other value → `501` with `unknown provider '<value>' — see INTEROP.md`.
- Every refusal and every upstream failure is checked/raised **before the cache and the meter** — a failed
  call is **never billed and never cached**, and `GET /ai/usage` keeps working. Identical in Python, Go, Node.

This knob is shared with the agent module: one `AI_PROVIDER` value describes the one provider your build runs.

### How the wired path behaves

- **One configured model per deployment.** The wired gateway serves `AI_MODEL` (or the provider default:
  anthropic `claude-sonnet-4-6`, openai `gpt-4o`). The request's `model` field selects among the *offline*
  tiers only; under a wired provider any value falls back to the configured model — callers cannot escalate
  your spend by naming a bigger model. Run several deployments (or a gateway) if you need several models.
- **Failure map.** Upstream non-2xx → `502` problem+json carrying the upstream status plus a ≤200-character
  body snippet with your key value redacted (credentials are never echoed; headers are never dumped). Timeout
  (`AI_TIMEOUT_SECONDS`, default 60s) or any network/DNS failure → `504`. A 2xx whose body is not the
  documented response shape → `502`. The adapter never invents text.
- **Caching still applies.** An identical `(model, prompt)` replays the stored answer and is never re-billed —
  for a sampling LLM that means "same prompt, same answer, billed once", and a cache hit never touches the
  network. If you want fresh sampling per call, remove the cache read **and** write together — the meter's
  conservation property holds either way.
- **Billing honesty.** The provider's real `input/output` token counts are billed into the meter (contained to
  the safe integer range; a malformed usage payload bills 0 rather than poisoning the meter). `cost` stays `0`
  because no price table is baked in — prices move; multiply tokens by your contracted rates at read time, or
  bill money units yourself where the usage is recorded. Per-call spend attribution lives in the `llm_usage`
  module (`POST /llm_usage/events`), the shipped cost ledger.
- **No provider-native streaming.** The adapter returns one complete text per call. (The agent module's run
  route streams by chunking its final output at the transport — that keeps working unchanged on top of these
  adapters; wiring native token deltas end-to-end is a customization.)

### The seam

Each language has the same three adjacent pieces: the **gate** (which enforces the contract above), the
**offline completion**, and the **shipped real adapter** (the reference implementation for any further
provider you add — same response shape, same failure map):

| language | file | gate | offline | shipped adapter |
|---|---|---|---|---|
| Python | `python/app_pkg/domains/ai_provider.py` | `_select_provider()` | `_fake_complete(...)` | `_real_complete(...)` |
| Go | `go/internal/domains/ai_provider/ai_provider.go` | `aiProviderSelect()` | `aiProviderFake(...)` | `aiProviderCallReal(...)` |
| Node | `node/src/domains/ai_provider.js` | `providerSelect()` | `fakeComplete(...)` | `realComplete(...)` |

The response shape to preserve (the routes, tests, and meter all depend on it):

```json
{"model": "<model>", "output": "<completion text>",
 "usage": {"prompt_tokens": N, "completion_tokens": N, "cost": N}}
```

To add another provider, mirror the shipped adapter: add its name + key env to the provider tables, build the
request, extract `(text, usage)`, and keep the 501/502/504 failure map — the gate, cache, and meter need no
changes. You only need to wire the language you actually deploy.

### Environment

| variable | meaning |
|---|---|
| `AI_PROVIDER` | `fake` (default, offline) · `anthropic` / `openai` (shipped adapters) · anything else fails loud |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | the credential for the selected provider — required (non-empty) when that provider is selected; read per call, never logged, never echoed in errors |
| `AI_MODEL` | the one model a wired deployment serves (empty = provider default: `claude-sonnet-4-6` / `gpt-4o`) |
| `AI_TIMEOUT_SECONDS` | per-call HTTP ceiling for a wired provider (default 60, clamped 1..600); breach → `504` |
| `AI_MAX_TOKENS` | completion-token ceiling for providers that require one (anthropic; default 1024) |
| `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` | endpoint base overrides — route through a proxy/gateway, an OpenAI-compatible server, or a local test double without code changes |

The base-URL knobs are trusted operator configuration (like `DATABASE_URL`) — they are also exactly how the
shipped tests prove the adapters offline, by pointing them at a local stub that speaks the provider's wire
shape.

## chat_threads

gutencode is **offline + deterministic**, so chat_threads ships the **port + shape + local impl**, never a live
network integration. This is the map for composing it with a model provider, and the intentional divergences.

### The settled contract (what the field converges on)
OpenAI's Conversations API, Convex's Agent component, and the Vercel AI SDK's persisted UIMessage all converge on
the same two-level model — a conversation/thread object plus an ordered list of immutable turn items; ours maps 1:1:

| chat_threads | the field |
|---|---|
| `POST /chat_threads` | create conversation / `createThread` |
| `GET /chat_threads` (mine, newest activity first) | `listThreadsByUserId` (OpenAI has NO list API — we add it) |
| `GET /chat_threads/{id}` | retrieve conversation / `getThread` |
| `PATCH /chat_threads/{id}` (title/metadata) | update conversation metadata / `updateThreadMetadata` |
| `DELETE /chat_threads/{id}` (cascade) | delete conversation (OpenAI does NOT cascade to items — we do) |
| `POST /chat_threads/{id}/messages` | create item / save message |
| `GET /chat_threads/{id}/messages` (seq ASC) | list items / `listMessages` |

`seq` is Convex's per-thread incrementing `order` integer, minted server-side inside one atomic read-modify-write
on the thread row. The metadata bounds (16 pairs, 64-char keys, 512-char values) are OpenAI's published numbers.
The closed role set `user|assistant|system|tool` is the AI SDK's persisted union.

### The composition recipe (this domain never calls a model)
chat_threads PERSISTS turns; generating an assistant turn is the agent seam's job. The app's chat handler (or the
customer's own agent loop) composes the two over HTTP/app code — never a cross-domain import:

1. `POST /chat_threads/{id}/messages` — append the **user** turn.
2. Run the agent / model call (the `agent` domain or any provider SDK), feeding it the transcript.
3. `POST /chat_threads/{id}/messages` — append the **assistant** turn (put model/usage provenance in the
   message's `metadata`, the per-turn slot the AI SDK calls UIMessage.metadata).

The `agent` domain's session ring buffer is the model's bounded CONTEXT window (drop-oldest by design);
chat_threads is the durable, user-facing HISTORY (reject-past-cap, never silently drops). Write each turn to both
if you use both — they answer different questions.

### Replay projections (per provider)
- **OpenAI Chat/Responses** — `GET .../messages` in seq order maps 1:1 to `{role, content}[]`; all four roles are
  legal input roles.
- **Anthropic Messages** — project `system` turns into the TOP-LEVEL `system` parameter and keep `user`/`assistant`
  in the array (strict user/assistant alternation is the provider's trained shape — merge consecutive same-role
  turns per your app's policy); `tool` turns become tool_result content blocks.
- **Vercel AI SDK** — one message ↔ one UIMessage (role + a single text part); `metadata` carries the per-turn
  provenance (model id, token usage).
- **Convex Agent** — `seq` ↔ `order` (a flat model: step sub-ordering collapses into additional seqs).

### Divergences (deliberate, labeled)
- **Bounded BOTH ways, reject-past-cap.** The hosted references grow forever (create + delete only); chat_threads
  caps threads-per-owner AND messages-per-thread and answers a loud 422 past either cap — never silent eviction,
  because dropping a user's chat history is data loss. Free space by deleting threads. (Contrast: `ai_memory`
  evicts, because memory is lossy by contract; history is a record.)
- **Content is a single text string.** Structured content parts (tool-call blocks, images) are a v2; project a
  parts array by flattening to text (the AI SDK flatten) or storing a serialized form your replay understands.
- **Turn alternation is NOT enforced.** Any role sequence stores (OpenAI and Convex are liberal too); alternation
  is a replay-projection concern, handled per provider above.
- **No idempotency key on append.** None of the references ships one; a duplicated text turn is a UX wart, not
  damage (unlike money or egress). If your client retries blindly, dedupe client-side; a keyed append is a v2 option.
- **Polling, not streaming.** Reads are request/response; a live-updates channel can ride on top later.

### Honest limits (what v1 deliberately does not do)
- **Crash residue is lazily reclaimed.** Every mid-operation crash lands on the SAFE side: a create tear leaves a
  ghost cap slot (invisible; freed only by a future sweep); an append tear leaves a seq GAP (`last_seq` stays the
  honest high-water mark of accepted appends — order is never affected); a delete tear leaves orphan message rows
  that the liveness gate makes unreachable (404 everywhere) until physically reclaimed. None of these can violate
  ordering, isolation, or the caps.
- **`last_seq` counts ACCEPTED appends, not retrievable turns.** After a rare append tear the transcript can be
  shorter than `last_seq`; the transcript itself is always gap-tolerant and in order.
- **No message edit/delete, no archive.** History is immutable ("edit" = append a new turn); removal is the
  thread-level cascade delete. An archive status flag is a v2 option.

## evals

`evals` is **offline and deterministic by construction**: it stores immutable golden suites and scores
**caller-provided** outputs with pure, byte-identical-×3 scorers. It never calls a model, a network, or the clock
(except the test-clock seam for `created_at`). That is the whole point — a scored run is reproducible forever. A real
deployment swaps richer machinery in **behind these same routes**; the offline core is the port.

### The settled shape (what a real eval harness agrees on)
The convergent offline-harness contract (promptfoo `providerOutput`, OpenAI Evals `sample{input,ideal}`, Inspect
`Sample{input,target}` + `Score`, Braintrust autoevals, LangChain evaluators):
- **suite** = a named, immutable set of **cases**, each `{id, scorer, expected}`.
- **score** = apply the scorers to **provided outputs** → per-case `{case_id, pass}` + `{passed, total, all_pass}`.
- the caller **provides the outputs** (promptfoo's `providerOutput` = "skip the provider call"); generating them is
  the *agent / ai_provider* domain's job, not the harness's.

### Swap-point 1 — generated outputs (instead of caller-provided)
A production harness generates the candidate output by calling a model, then scores it. In gutencode that is a
**consumer composition**, not a change here: the caller drives `agent`/`ai_provider` to produce the output, then
`POST /evals/suites/{name}/score` with it. The suite (the golden expectations) and the deterministic verdict stay in
`evals`; only the *source of the output* moves upstream. No route changes.

### Swap-point 2 — model-graded / judge scorers (the non-deterministic tier)
The field's other half is LLM-as-judge (`llm-rubric`, `factuality`, `model-graded-*`) and embedding similarity
(`similar`, cosine). These are **deliberately out of scope**: they need a model/network and are non-deterministic, so
they cannot live in an offline, ×3-byte-identical core. A real deployment adds a judge scorer as a **provider port**
(mirroring `ai_provider`): the suite's case carries the rubric, the port calls the judge, the verdict is advisory
(unpinned, like the rag float score). The deterministic scorers below remain the trustworthy, reproducible floor.

### Deliberate v2 scorers (genuine ×3 / zero-dep boundaries, NOT gaps)
Each is excluded for a concrete, measured reason — not an oversight:

| scorer | why it is v2 (the boundary) | the v2 shape |
|---|---|---|
| **full Unicode casefold** (ß→ss, Turkish-i) | Go's full casefold + NFC live only in `golang.org/x/text`, which the **modernc-only** go build cannot import (and the shared-part Go build is dependency-free — an `x/text` import would fail to compile); Node has no native casefold. Only Python `str.casefold()` works. | embed a **pinned `CaseFolding.txt` + NFC table** in all three languages, proven identical ×3 (a real surface, not a free rider). v1 ships **ASCII case-fold** (A–Z↔a–z, non-ASCII raw) — ×3-trivial and zero-dep. |
| **json_equal** (structural JSON ==) | ×3 number handling needs raw-token access: Python distinguishes `1` (int) from `1.0` (float) by type; Node's `JSON.parse` collapses both; Go's `encoding/json` gives `float64`. Detecting `>2^53` and non-integer numbers identically ×3 needs `UseNumber`/a source-reviver/int-type checks. Strict dup-key rejection needs a hand-rolled ×3 scanner (the RE2≠PCRE class we exclude regex for). | a pinned strict ×3 JSON scanner (reject NaN/Inf/dup-key/>2^53/non-integer/over-depth) + a recursive structural value-compare. |
| **regex** | RE2 (go) ≠ PCRE (python) ≠ ECMAScript (node): lookbehind, backrefs, and `\b`-on-unicode diverge — a non-deterministic-×3 scorer is a category error against this domain's invariant. | a documented **RE2-only** subset (the common intersection), validated ×3. |
| **float-similarity** (BLEU / ROUGE / Jaro / cosine / Levenshtein-ratio) | float ratios + language-specific tokenization diverge ×3 (the rag "scores are floats, deliberately NOT pinned" lesson). | integer edit-distance + an integer threshold (the distance is ×3-safe; the ratio is not), with a pinned algorithm. |

### The store backend
State is the durable store seam (SQLite default; Postgres via `DATABASE_URL`) — the same `<owner>\x1f<name>` key and
`owner`-scoped scan run on either backend, byte-identically ×3. Nothing here changes for the swap.

## job_queue

gutencode is offline and deterministic, so `jobs` ships the **shape + a local store-backed implementation that IS
the deterministic oracle**, plus this map for delegating to a managed broker in production. There is no live
network integration in the build — you wire one behind the same routes.

### The contract this domain implements

A job is `{id, owner, kind, payload, queue, status, attempts, max_attempts, run_at, lease_until, created_at,
updated_at, last_error}`; `status ∈ {queued, running, done, dead}`. The lifecycle is the field-universal one:

```
enqueue ─▶ queued ─(claim)─▶ running ─(complete)─▶ done
                      ▲           │
                      └─(fail, retries left: backoff)┘
                                  │
                              (fail at max / reclaim at max)─▶ dead
```

- **enqueue** (`POST /job_queue`, owner-authenticated) — stamps the owner from the caller, returns the job.
- **claim** (`POST /job_queue/claim`, service) — leases the lowest-id ready job to a worker and returns a **lease token**;
  also reclaims a `running` job whose lease has lapsed (a crashed worker's job).
- **complete / fail** (`POST /job_queue/{id}/complete|fail`, service) — require the **current** lease token (a stale
  worker is fenced out); fail retries with deterministic backoff or dead-letters at `max_attempts`.
- **get / list** (`GET /job_queue/{id}`, `GET /job_queue`, owner-authenticated) — owner-scoped; the lease token is never
  exposed to the owner.

**Delivery is at-least-once** — a worker may crash after doing the work but before `complete`, so the job is
re-delivered. Handlers MUST be idempotent. No queue offers true exactly-once; this matches SQS / River / BullMQ /
Sidekiq.

### Mapping the envelope onto a managed broker

Select a provider behind a `JOB_QUEUE_PROVIDER` env (default `store` — the local oracle). A non-default value is a
fail-loud stub until wired; the routes and the envelope stay identical.

| concept | jobs (local oracle) | AWS SQS | River (Postgres) | BullMQ (Redis) | Sidekiq (Redis) |
|---|---|---|---|---|---|
| enqueue | `POST /job_queue` -> store row | `SendMessage` | `Insert` (`river_job`) | `queue.add` | `perform_async` |
| claim/lease | `do()`-CAS, lowest id | `ReceiveMessage` (visibility timeout) | `SELECT … FOR UPDATE SKIP LOCKED` | move-to-active + lock token | reliable-fetch (`RPOPLPUSH`) |
| the lease token | rotating `lease_token` | the receipt handle | the row lock | the job lock token | the working-queue entry |
| complete | `status=done` | `DeleteMessage(receipt)` | `complete` | `moveToCompleted(token)` | ack (remove from working) |
| fail + backoff | `run_at = now + min(base·2^n, cap)` | re-appear after visibility | `snooze`/retry | `moveToFailed` + backoff | retry set (`count^4+15`) |
| reclaim (crash) | lease-lapse reclaim in `claim` | visibility timeout | stuck-job rescuer | stalled-lock check | reliable-fetch recovery |
| dead-letter | `status=dead` (terminal, listable) | DLQ | `discarded` | `failed` set | `dead` set |

**Deliberate divergence — no jitter.** Real brokers jitter the backoff to avoid a thundering herd (Sidekiq always,
River ±10%, BullMQ opt-in). gutencode is deterministic and identical across three languages, so the backoff is
exact (`run_at = now + min(base·2^attempts, cap)`). When delegating to a provider, add the provider's jitter at the
boundary; the in-process oracle stays deterministic so its behavior is byte-reproducible and testable.

**Deliberate divergence — synchronous recovery.** There is no background sweeper thread; lease recovery happens
lazily inside `claim` (the next claimant reclaims a lapsed job), and lease expiry is read from the test-clock seam.
A managed broker runs its own background reaper; the offline oracle does not need one.

## llm_usage

`llm_usage` is a **per-call LLM token + cost meter**: an event carries token counts, the server derives the dollar
cost from a fixed, code-reviewed price table (an unknown `(provider, model)` is `422`, never a silent `$0`), and the
per-owner aggregate is derived on read (`GET /llm_usage/summary`). It is the **AI-spend ledger** every metered agent
run feeds. This doc is its port: how events get in, and how billing reads them out.

### How events arrive (three ways)

1. **Automatically, from a metered producer (the shipped wire).** When both `agent` and `llm_usage` are in your build,
   every agent run meters each provider call **for the run's authenticated caller** — via the core `core.usage_record`
   seam, which `llm_usage` registers its own recorder into (so this domain stays the single writer of its store and
   the single cost authority). Real providers always meter; the offline fake meters only when `AI_USAGE_METER_FAKE=1`.
   The metering is **availability-first**: it can never break a run (a failed write is logged with the event id for a
   safe replay). Wiring another producer is the same seam — see the `agent` INTEROP.
2. **Manually, from your own server code.** `POST /llm_usage/events` with `{identifier, provider, model, <token
   dims>}` and the caller's bearer token. The **`identifier` is the idempotency key** (use the provider's response id,
   e.g. `msg_…` / `chatcmpl-…`): recording is **exactly-once on `(owner, identifier)`** — a byte-identical retry
   replays `201`; the same identifier with a **different** cost-input is `409` (no silent re-bill). This is also how
   you **replay** an event an automatic write logged as failed — it is safe because it is exactly-once.
3. **Batch / import.** The same `POST /llm_usage/events`, one call per historical usage record, each with a stable
   `identifier` so a re-run of the import is idempotent.

The event carries **token counts only** — there is deliberately no `cost` field, so a client can never smuggle a
price. `cost_nanodollars` is server-derived and returned. Summary and events are **owner-scoped** (the bearer subject),
so a caller only ever sees its own spend.

### The metered→billed recipe (v1 — a documented composition, no new capability)

Billing is fixed-catalog by design (`invoices` derives each line's `amount` server-side). Usage-based billing is a
real capability change (usage line-items, proration, thresholds) — **v1 ships the recipe, not the capability.** On
your billing cycle (monthly, or on demand), per customer:

1. **Read the spend.** `GET /llm_usage/summary?from=<epoch>&to=<epoch>` as that customer → `cost_nanodollars` (the
   grand total) + a `by_model` breakdown, for the window.
2. **Convert to minor units with an explicit rounding policy.** `cost_nanodollars` is nanodollars (1e-9 USD).
   Cents = `ceil(cost_nanodollars / 10_000_000)` — **ceil-to-cent is a deliberate choice** (favor-the-house; document
   whichever policy you pick, and apply it once per invoice, not per line, to avoid rounding drift).
3. **Bill it.** `POST /invoices` with a usage line for that cent amount (and, if you charge a flat base fee, keep your
   `POST /billing/subscriptions`). Then finalize → pay through the normal invoice lifecycle. All existing routes; the
   invoice's own conservation + immutability gates still hold.

```
GET  /llm_usage/summary?from=1719792000&to=1722470400   ->  {"cost_nanodollars": 41_250_000, "by_model": [...]}
                                                             cents = ceil(41_250_000 / 10_000_000) = 5
POST /invoices  {"customer": "...", "lines": [{"desc": "AI usage (Jul)", "amount_minor": 5, ...}]}
POST /invoices/{id}/finalize   ->   ...pay
```

### Credits / entitlement check (a second snippet)

To gate service on a prepaid balance, read the summary **before** serving the expensive call:

```
spent = GET /llm_usage/summary?from=<cycle_start>            # cost_nanodollars this cycle, for this caller
if spent.cost_nanodollars >= entitlement_nanodollars:       # your per-plan budget
    refuse (402 / upgrade prompt)                            # or degrade to a cheaper model
else:
    serve the agent run (which meters the new spend)
```

### Async / at scale (the CUSTOM path)

The automatic wire writes synchronously (one store write, ~ms). At high volume, or to decouple the run from the
meter entirely, drain usage through an outbox/queue into `POST /llm_usage/events` from a worker — the same
exactly-once identifier makes that safe. This is the `reporting`-style documented composition; there is no shipped
drainer by default (usage would otherwise sit invisible), so the synchronous wire is the shipped default.

### What is NOT built (scope fence)

- **Usage-based billing capability** (automated usage line-items, proration, cycle scheduling) — a Wave-2+ product
  decision; v1 is the recipe above.
- **A generalized `{dimensions, quantity}` request meter** — this domain is the *AI-spend* meter only.
- **Provider-signed all-tenant ingestion** — the trust model is owner-self-metering (the app records the run's own
  caller's usage); a signed multi-tenant ingest is v2 backlog.

## prompt_registry

gutencode is **offline + deterministic**, so `prompt_registry` ships the **shape + a local store-backed impl**, not a
live integration. This file is the documented swap-point to a managed prompt-registry provider.

### What ships (the offline default)
A durable, store-backed registry: immutable monotonic **versions** per `(owner, name)`, movable deployment
**labels** (rollback), a pure `content_hash` pin, and a deterministic `{{variable}}` **render**. Everything is local
(sqlite by default, Postgres via `DATABASE_URL`); no network call.

### The managed denominator (the convergent contract this matches)
Langfuse Prompt Management · PromptLayer Prompt Registry · LangSmith Prompt Hub · Humanloop · OpenAI Reusable
Prompts. The settled shape across all five:
- **immutable, append-only versions** (an "edit" mints a new version);
- **rollback = move a named pointer** (label / tag / environment) that maps one-to-one to a version;
- **pin exact content** by a stable per-version id;
- **fetch by `name` + at-most-one of `{version | label}`** → the template + the resolved version;
- **`{{variable}}` templating**, with the **client SDK** doing the variable fill (`.compile(vars)`).

### The swap-point
Two boundaries a deployer can move:
1. **The store** — already a documented seam: set `DATABASE_URL` to run on Postgres/Supabase instead of sqlite (the
   same code on all three runtimes). No code change.
2. **The registry itself** — to use a *hosted* prompt service, a client fetches the raw template from that service
   (`langfuse.get_prompt(name, label=…)` / `promptlayer.get(name, version=…)`) instead of from `GET
   /prompt_registry/prompts/{name}/versions/{version}` here. Both return the **raw template**; the response envelopes
   are isomorphic (`{name, version, template, content_hash}`), so a thin adapter maps one to the other.

### Why we ALSO ship a server `/render` (the deliberate divergence)
The managed providers defer rendering to the **client SDK** (and our get-version serves the raw template too, so a
client *can* render itself — the CONFORM path). We additionally expose `POST /prompt_registry/prompts/{name}/render`
because the gutencode value proposition is a **3-language backend whose behavior is provably identical**: the render
endpoint is the carrier of the goal's *"identical render x3"* property (the same `{{var}}` substitution, byte-for-byte,
in python == go == node), and it keeps rendering **offline + deterministic**. A hosted
service's client-side `.compile()` is its equivalent; ours is server-side so the parity is mechanically proven.

### What is deliberately NOT here (v2 / a later pass)
config/model-params per version, commit messages, chat-message prompts, prompt-to-prompt composition, guarded-delete,
and tags — each is a managed-provider feature beyond this version's floor. The load-bearing
shape (immutable version ⟂ movable pointer + deterministic render) is complete.

## rag

rag ships the **port + shape + a deterministic local impl** — never a live network integration (gutencode is
offline/deterministic). The two routes ARE the port; a production deployment swaps the impl behind them for a real
embedder + vector DB + a smarter splitter, keeping the request/response contract byte-for-byte.

### The contract (what stays fixed across any backend)
```
POST /rag/documents  {doc_id, text}                       -> 201 {doc_id, chunks:N}
POST /rag/query      {query, k?}  (k in 1..50, default 3) -> 200 {top, hits:[ {chunk_id, text, score, source:{doc_id,start,end}} ]}
```
- **chunk_id** = `"<doc_id>#<ordinal>"` (deterministic, re-ingest-stable).
- **source.{start,end}** are **code-point** offsets into the stored document — the citation a UI links to.
- ranking is **score desc, ties by `chunk_id` asc**; scores are floats and deliberately NOT pinned.
- documents are **owner-scoped** (the authenticated caller); a query only ever sees the caller's own corpus.

### The two swap points (the deterministic local impl → a real backend)
| seam | local (shipped) | production swap | the contract it preserves |
|---|---|---|---|
| **embedder** (`embedding` part: `embed`/`cosine`) | an 8-bucket code-point histogram + cosine — deterministic, the test oracle | OpenAI `text-embedding-3`, Cohere `embed`, a local sentence-transformer | `embed(text) -> vector`; an exact-text query self-matches at the top (grounding) |
| **chunker** (`chunking` part: `chunk_*`) | fixed code-point window + overlap (`RAG_CHUNK_SIZE`/`OVERLAP`) | a token / sentence / semantic splitter (LangChain `RecursiveCharacterTextSplitter`, LlamaIndex `SentenceSplitter`) | a chunk carries an in-bounds `source.{start,end}` span; the windows cover `[0,len]` |
| **index/scan** (`store.values` + cosine top-k) | a full O(n) scan, ranked in-process (the documented swap-at-scale limit) | pgvector, Pinecone, Qdrant, Weaviate, FAISS — an ANN index behind the same query | `{top, hits[]}`, at most `k` hits, owner-scoped |

### The denominator this shape matches
- **LlamaIndex** — `NodeWithScore` + `TextNode.start_char_idx/end_char_idx` + `source_nodes`; our `hit` is a
  `NodeWithScore` and `source` is the `start/end_char_idx` pair.
- **LangChain** — `Document` + a `TextSplitter` writing `metadata["start_index"]`; our `source.start` is `start_index`.
- **Haystack** — `DocumentSplitter` → `meta.split_idx_start`; same char-offset citation.

A production adapter maps `hits[].source` onto whichever of these the host app already speaks — the char-offset
citation is the common substrate all three expose, which is why an answer built on rag stays **traceable to a source
span** regardless of the embedder/index swapped in behind it.

## reporting

`reporting` is a **self-contained, owner-scoped aggregation store**: you ingest typed FACT rows into a named
dataset, then run GROUP BY rollups over them. It is offline and deterministic — there is no live network
integration. This doc is the port: how you **populate** it, its **immutability contract**, and how you **back it at
scale**.

### 1 · Populate it — the CQRS read-model contract (reporting does NOT read your other tables)

reporting is a **read model your application FEEDS**, not a live view over your operational data. The generated
backend enforces a hard boundary rule: a domain may only touch its own store namespace and the shared `core`/`parts`
seams — so `reporting` **cannot** read the `records` store (or any other domain's). It aggregates over the facts
**you** put into it. Populate `reporting_facts` by one of:

- **Dual-write** — when your app writes a source row (e.g. a `records` create/update, an order, a deal-stage
  change), also `POST /reporting/facts` with your projection of that row into `{dataset, key, dimensions, measures}`.
- **A pipeline / batch job** — periodically read your source data and `POST` the facts (an ETL into the read model).
- **An outbox → consumer** — emit a domain event on each source change and have a consumer translate it to a fact.

A **fact** is your denormalized projection: `dimensions` are the string labels you GROUP BY / filter on (stage,
region, model, plan…), `measures` are the integers you SUM/MIN/MAX (amount in minor units, counts, durations,
tokens). Choose minor units so every measure — and every SUM — stays within ±(2^53−1); a SUM that would exceed that
fails loud with `422` rather than returning a wrapped or precision-lost number.

### 2 · Immutability & the `key` contract (how exactly-once works)

Ingest is **exactly-once and immutable** on `(owner, dataset, key)`. The `key` is your stable per-fact id (the
Mixpanel `$insert_id` / Segment `messageId` model):

- A **retried** `POST` with the same `(dataset, key)` is safely idempotent — it returns the original fact, so a
  network retry never double-counts a SUM.
- A `POST` that reuses a `(dataset, key)` with **different** `dimensions`/`measures` is **silently dropped** — the
  original immutable fact is returned. To *correct* a fact, ingest a **compensating fact** (a new `key`, e.g. a
  negative measure), the way an accounting ledger posts a reversal. Do **not** reuse a key to "update" data.
- Consequences of a mis-chosen key are yours to own: a key that is **too coarse** (collides across distinct events)
  **under-counts**; a key that is **fresh on every retry** (a new UUID per attempt) **over-counts**. Pick one stable
  id per real-world event.

### 3 · Back it at scale — the OLAP swap

The generated implementation computes rollups in-process: it scans the owner's `reporting_facts` (an `O(n)` full
scan, the documented store-swap-at-scale limit — the same as `search`/`ledger`/`llm_usage`) and groups + aggregates
in memory, returning a **bounded page** of groups. This is correct and dependency-free for modest volumes.

At scale, keep the **HTTP contract** (`POST /reporting/query` with `{dataset, group_by, aggregate, filter}` →
`{groups:[{key, values}], next_cursor}`) and swap the storage + compute for a real OLAP engine —
**ClickHouse · Apache Druid · BigQuery · a Cube.dev semantic layer** — pushing the GROUP BY / SUM / MIN / MAX
**down** to the engine. The query envelope maps 1:1 onto Cube's `/load` request, so the port is a storage/compute
substitution behind the same routes and the same aggregate semantics; callers do not change.

### 4 · The aggregate contract (what a caller can rely on)

- Operators: `count` (row count; no field), `sum` / `min` / `max` (over an integer `measure`, named via `field`).
  `AVG` is deliberately omitted — it is non-additive and its division is a cross-language float hazard; compute it
  client-side as `sum / count`.
- `group_by` is a list of dimension names; a fact missing a grouped dimension is grouped under a `null` key value.
- `filter` is equality-only (`{dimension: value}`, implicit AND) over dimensions.
- Group order is **stable and identical across languages** (a content-hash order); a caller who needs an ordinal /
  by-measure sort re-sorts the returned page.
- `SUM` over facts that lack the measure is `0`; `MIN`/`MAX` over no values are omitted from that group.

## secrets_vault

### Read this first — at-rest sealing is OPT-IN
secrets_vault has a built-in at-rest cipher, **off by default**. With **`SECRETS_VAULT_KEK` unset** (the default),
the stored secret bytes are **PLAINTEXT** — the seam is a passthrough, so the offline install stays zero-dependency
and `secure_delete=ON` scrubs a deleted row on disk. Set **`SECRETS_VAULT_KEK`** (base64 of 32 bytes) and every
secret value is **AES-256-GCM sealed** before it hits the store. For the strongest threat model, wire an external
KMS instead (Option A). Either way, the lifecycle, audit, and secure-delete are production-ready — only the at-rest
key policy is your choice.

### The seam — two functions, three languages
Every secret value flows through `_seal(value, name, version)` before storage and `_unseal(stored, name, version)`
on reveal (package shape):
- python `python/router.py`: `_seal` / `_unseal`
- go `go/seal.go`: `svSeal` / `svUnseal`
- node `node/index.js`: `svSeal` / `svUnseal`

The sealed value is a **self-describing blob** `svgcm:<keyver>:<base64(nonce+ciphertext+tag)>` — the scheme tag lets
other schemes/KMS blobs coexist, and `keyver` (a non-secret fingerprint of the key) lets `_unseal` fail loudly on a
wrong or rotated key. The three languages produce **byte-identical** blobs, so a value sealed by one runtime opens on
any other.

### Option B (BUILT-IN) — `SECRETS_VAULT_KEK`, the in-app AES-256-GCM seal
Set `SECRETS_VAULT_KEK` to the base64 of a 32-byte (256-bit) key and sealing engages with **no external service**:
- **Cipher:** AES-256-GCM, the KEK used directly as the AES key; a fresh random **96-bit nonce per record**; a
  128-bit auth tag.
- **AAD = `name + "\x1f" + version`** — the ciphertext is bound to its exact slot, so a stolen blob can't be replayed
  under another secret's name or version.
- **Dependencies:** python needs the `cryptography` package (its stdlib has no AEAD) — it is **lazy-imported only when
  the KEK is set**, so the default install adds nothing and the shipped `code/deps` surface is unchanged; if the KEK
  is set but the package is missing, every seal/unseal fails **loud** (never a silent plaintext store). go and node
  seal with **stdlib** (`crypto/aes`+`crypto/cipher`, `node:crypto`) — no new dep in any case.
- **Generate a key:** `python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"`
- **Threat model:** this protects the **DB-file / backup / replica exfiltration** class (a stolen `.db` or a Postgres
  dead-tuple copy is unreadable without the key). It does **NOT** protect against a fully compromised host that can
  read the process environment AND the database — for that, keep the key off the box with a KMS/HSM (Option A).

### Option A (STRONGEST) — external KMS as the encryption boundary
Route `_seal`/`_unseal` to a managed KMS so the key never lives on the app host. secrets_vault stores only
ciphertext, so a DB-file / backup leak yields nothing even if the host env leaks.
- **AWS KMS** — `_seal` = `kms.Encrypt(KeyId, plaintext)` → base64(CiphertextBlob); `_unseal` = `kms.Decrypt(blob)`.
  At volume, envelope it: `GenerateDataKey` → AES-GCM the value with the DEK → store the wrapped DEK + ciphertext
  (this is the KEK-wraps-DEK model; the built-in Option B is the simpler KEK-direct form, right-sized for one secret
  value per record). Pass the secret's `name`/`version` as the KMS **encryption context** (its AAD).
- **GCP KMS** — `_seal` = `kms.encrypt(keyName, plaintext)`; `_unseal` = `kms.decrypt(keyName, blob)`.
- **HashiCorp Vault (transit)** — `_seal` = `POST /v1/transit/encrypt/<key>` → `vault:v1:<ct>`; `_unseal` =
  `POST /v1/transit/decrypt/<key>`. "Encryption as a service" — no key ever leaves Vault. (Our blob shape mirrors it.)
- **Doppler / 1Password / Akeyless** — if the secret already lives in the provider, store a REFERENCE (the provider
  path) as the value and resolve it in `_unseal` at read time.

> gutencode is offline/deterministic, so the *live* AWS/GCP/Vault network call is NOT shipped — it is yours to wire
> into these two functions. The seam, the blob shape, the built-in AES-GCM seal, and the lifecycle/audit are done.

### CRYPTO-SHRED — irreversible revocation
Destroying the ciphertext OR the key makes a value unrecoverable — the answer to backends that can't scrub bytes:
- **Per-version DESTROY** removes the row; on SQLite `secure_delete=ON` zeroes the freed page. With a KEK engaged the
  row was ciphertext anyway, so even a backend that leaves dead tuples (Postgres, until VACUUM; replicas; backups)
  leaks only unreadable ciphertext.
- **Destroying / rotating `SECRETS_VAULT_KEK`** shreds **every** value sealed under it, everywhere at once — the
  wrong key fails loud (`keyver` mismatch), so the old plaintext is gone the moment the old key is gone.

### Already done for you (independent of the key policy)
- **`secure_delete = ON`** (the store, x3) — a DESTROY / prune zeroes the freed sqlite page.
- **Version lifecycle** — DESTROY (irreversible, scrubs bytes), DISABLE/ENABLE (reversible hide, bytes kept),
  `max_versions` prune. State model = GCP-SM / OpenBao: **ENABLED | DISABLED | DESTROYED** (+ **PRUNED**).
- **Access audit** — every reveal/put/destroy/disable/enable, success AND failure (403 denial / 404 probe) →
  `secrets_vault_access` (**NEVER** the value); `APP_SECRETS_VAULT_AUDIT`: off | deny (default) | all;
  `GET /secrets_vault/access` (admin).

### Version-state vocabulary (all four non-active states are a byte-indistinguishable 404)
| state | reveal | bytes | reversible | visible in metadata |
|---|---|---|---|---|
| **active** (enabled) | returns the value | present | — | implied |
| **disabled** | 404 | KEPT | yes (`/enable`) | yes (`states`) |
| **destroyed** | 404 | SCRUBBED | no | yes (`states`) |
| **pruned** (max_versions) | 404 | gone | no | no (below `min_version`) |

### Configuration
| env | meaning | default |
|---|---|---|
| `SECRETS_VAULT_MAX_VERSIONS` | retained versions per name (oldest pruned past the cap) | `100` |
| `APP_SECRETS_VAULT_AUDIT` | `off` \| `deny` \| `all` | `deny` |
| `SECRETS_VAULT_KEK` | base64 of a 32-byte key → AES-256-GCM seal at rest; unset = plaintext (sealing off) | — |
