// The provider PORT + the deterministic fake (the default and the test oracle — the whole stack runs offline)
// + the SHIPPED real adapters (Anthropic Messages · OpenAI Chat Completions, global fetch only, no SDK) + the
// ONE selection site (AI_PROVIDER env). HONESTY CONTRACT (identical in python/go): the offline fake is the
// default, and a recognized real provider — anthropic, openai — runs the moment its key env is set; a real
// name WITHOUT its key, or any unknown value, is REFUSED per call (a 501 at the run route), NEVER a silent
// fake completion under a real provider's name. Adapters read env per CALL (AI_MODEL · AI_TIMEOUT_SECONDS ·
// AI_MAX_TOKENS · the base-URL overrides — the base URL is both a proxy/gateway feature and the offline test
// seam), return ONE final text (native tool-use/token streaming deliberately not mapped — the SSE mode chunks
// the final output at the transport), and map upstream failure instead of inventing text: non-2xx -> 502 with
// a sanitized <=200-char snippet (the key value is REDACTED, headers never dumped), timeout/network -> 504.
// Protocol of the fake (identical to the python/go fakes): 'use <tool> <args>' -> a structured tool call · a
// tool observation -> 'answer: <obs>' · 'use forever …' -> NEVER finalizes (so the iteration guard is
// provable black-box) · else '[fake] <input>'.
import { envInt } from '../../parts/env_int.js';

// carries an upstream-mapped refusal (502 upstream error / 504 timeout) from an adapter out of the run loop
// to the route, which renders it as the ONE problem+json envelope — before any SSE byte.
export class ProviderFailure extends Error {
  constructor(status, detail) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

// fakeUsage — deterministic NONZERO counts so the metering wire is provable offline (armed via AI_USAGE_METER_FAKE);
// model 'fake' is priced at zero in the meter's table (an explicit priced-at-zero row, not a silent $0). Same ×3.
const fakeUsage = () => ({ model: 'fake', input_tokens: 3, output_tokens: 5, cache_read_input_tokens: 0,
  cache_creation_input_tokens: 0, reasoning_tokens: 0 });

// usageTok — a provider-reported token count, defensively coerced: a non-negative safe integer or 0 (a missing/odd
// field never breaks the run — the usage is best-effort spend attribution, never the run's correctness).
const usageTok = (u, key) => (Number.isSafeInteger(u[key]) && u[key] >= 0 ? u[key] : 0);

const fakeLLM = {
  complete(system, messages) {
    const last = messages[messages.length - 1];
    let runInput = '';
    for (const m of messages) if (m.role === 'user') runInput = m.content;
    if (runInput.startsWith('use forever')) return { tool: 'echo', args: { text: 'again' }, usage: fakeUsage() };
    if (last.role === 'tool') return { final: `answer: ${last.content}`, usage: fakeUsage() };
    if (last.content.startsWith('use ')) {
      const rest = last.content.slice(4).split(/ (.*)/s);
      const tool = rest[0];
      const value = rest[1] || '';
      const args = tool === 'calc' ? { expr: value } : { text: value };
      return { tool, args, usage: fakeUsage() };
    }
    return { final: `[fake] ${last.content}`, usage: fakeUsage() };
  },
};

const ANTHROPIC_VERSION = '2023-06-01'; // the Messages API version pin — a wire constant the API requires
const UPSTREAM_BODY_CAP = 1048576; // UTF-16 units kept of a provider response (a text completion is KBs)

// map the port's roles onto provider wire roles: tool observations become user turns (the minimal-adapter
// doctrine — the model sees the observation as conversation), then consecutive same-role turns merge
// (newline-joined) so the wire alternates user/assistant cleanly. Identical mapping in python/go.
function mergedTurns(messages) {
  const turns = [];
  for (const m of messages) {
    const role = m.role === 'assistant' ? 'assistant' : 'user';
    if (turns.length && turns[turns.length - 1].role === role) {
      turns[turns.length - 1].content += `\n${m.content}`;
    } else {
      turns.push({ role, content: m.content });
    }
  }
  return turns;
}

const shapeFailure = (which) => new ProviderFailure(502, `provider '${which}' upstream error: unexpected response shape`);

// POST a JSON body, return the parsed 2xx JSON — or throw the mapped failure: non-2xx -> 502 with the status
// + a <=200-char snippet with the key value REDACTED (credentials never echo, headers never dump); timeout /
// network / bad endpoint -> 504. The adapter never fabricates a completion.
async function providerPost(which, url, headers, payload, key) {
  const timeout = envInt(process.env.AI_TIMEOUT_SECONDS, 60, 1, 600);
  let resp;
  let text;
  try {
    resp = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers },
                              body: JSON.stringify(payload), signal: AbortSignal.timeout(timeout * 1000) });
    text = await resp.text();
  } catch {
    throw new ProviderFailure(504, `provider '${which}' upstream timeout or network failure`);
  }
  if (!resp.ok) {
    const redacted = key ? text.split(key).join('[redacted]') : text;
    const snippet = [...redacted].slice(0, 200).join('');
    throw new ProviderFailure(502, `provider '${which}' upstream error (HTTP ${resp.status}): ${snippet}`);
  }
  if (text.length > UPSTREAM_BODY_CAP) throw shapeFailure(which);
  try {
    return JSON.parse(text);
  } catch {
    throw shapeFailure(which);
  }
}

// POST {ANTHROPIC_BASE_URL}/v1/messages — x-api-key auth, the system prompt as the top-level `system` field;
// the concatenated text blocks come back as the final answer (the run loop well-forms every output downstream).
const anthropicLLM = {
  async complete(system, messages) {
    const key = process.env.ANTHROPIC_API_KEY; // non-empty — the selection site checked
    const base = (process.env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com').replace(/\/+$/, '');
    const model = process.env.AI_MODEL || 'claude-sonnet-4-6';
    const payload = { model, max_tokens: envInt(process.env.AI_MAX_TOKENS, 1024, 1), messages: mergedTurns(messages) };
    if (system) payload.system = system;
    const data = await providerPost('anthropic', `${base}/v1/messages`,
                                    { 'x-api-key': key, 'anthropic-version': ANTHROPIC_VERSION }, payload, key);
    if (!Array.isArray(data.content)) throw shapeFailure('anthropic');
    let text = ''; // concatenate the text blocks (usually exactly one)
    for (const block of data.content) {
      if (block && block.type === 'text') {
        if (typeof block.text !== 'string') throw shapeFailure('anthropic');
        text += block.text;
      }
    }
    const resp = { final: text };
    if (data.usage) { // the provider's reported spend (metered into llm_usage)
      resp.usage = { identifier: typeof data.id === 'string' ? data.id : undefined, model,
        input_tokens: usageTok(data.usage, 'input_tokens'), output_tokens: usageTok(data.usage, 'output_tokens'),
        cache_read_input_tokens: usageTok(data.usage, 'cache_read_input_tokens'),
        cache_creation_input_tokens: usageTok(data.usage, 'cache_creation_input_tokens'), reasoning_tokens: 0 };
    }
    return resp;
  },
};

// POST {OPENAI_BASE_URL}/v1/chat/completions — Bearer auth, the system prompt riding as the first message;
// choices[0].message.content comes back as the final answer.
const openaiLLM = {
  async complete(system, messages) {
    const key = process.env.OPENAI_API_KEY; // non-empty — the selection site checked
    const base = (process.env.OPENAI_BASE_URL || 'https://api.openai.com').replace(/\/+$/, '');
    const model = process.env.AI_MODEL || 'gpt-4o';
    const turns = mergedTurns(messages);
    if (system) turns.unshift({ role: 'system', content: system });
    const payload = { model, messages: turns };
    const data = await providerPost('openai', `${base}/v1/chat/completions`,
                                    { authorization: `Bearer ${key}` }, payload, key);
    const text = data?.choices?.[0]?.message?.content;
    if (typeof text !== 'string') throw shapeFailure('openai');
    const resp = { final: text };
    if (data.usage) { // openai reports prompt/completion tokens (metered into llm_usage)
      resp.usage = { identifier: typeof data.id === 'string' ? data.id : undefined, model,
        input_tokens: usageTok(data.usage, 'prompt_tokens'), output_tokens: usageTok(data.usage, 'completion_tokens'),
        cache_read_input_tokens: 0, cache_creation_input_tokens: 0, reasoning_tokens: 0 };
    }
    return resp;
  },
};

// the SHIPPED real providers: name -> [key env, adapter]. Adding a provider = one row + one adapter object.
const REAL_PROVIDERS = { anthropic: ['ANTHROPIC_API_KEY', anthropicLLM], openai: ['OPENAI_API_KEY', openaiLLM] };

// the ONE selection site — change AI_PROVIDER env, never a call site. Returns { provider } when this build
// can run it (the fake, or a shipped adapter whose key env is set), else { problem } with the 501 refusal
// detail (byte-identical ×3) naming exactly what to set. 501 is deliberate: not 503 (the missing key is not
// transient; retrying cannot succeed until an operator sets one) and not a 4xx (the request is valid; the
// DEPLOYMENT lacks the capability).
export function getProvider() {
  const which = process.env.AI_PROVIDER || 'fake';
  if (which === 'fake') return { provider: fakeLLM };
  if (Object.hasOwn(REAL_PROVIDERS, which)) {
    const [keyEnv, provider] = REAL_PROVIDERS[which];
    if (!process.env[keyEnv]) return { problem: `provider '${which}' needs ${keyEnv} — see INTEROP.md` }; // empty counts as unset
    return { provider };
  }
  return { problem: `unknown provider '${which}' — see INTEROP.md` };
}
