// The run loop + durable per-session memory. THE INVARIANT: the loop ALWAYS terminates — bounded by
// AGENT_MAX_ITERATIONS (default 6), proven black-box by the 'use forever' contract case.
import { nextId, storeDo, storeGet } from '../../core/runtime.js';
import { usageRecord } from '../../core/usage.js';
import { envInt } from '../../parts/env_int.js';
import { makeWellFormed } from '../../parts/well_formed.js';
import { runTool } from './tools.js';

let warnedUnmetered = false; // the lazy warn-once flag (a real provider running unmetered warns ONCE per process)

// meterCall meters ONE provider call's usage into the core usage sink (which forwards to llm_usage when present).
// NEVER throws — a meter failure must not break the run. Real providers always meter; the fake meters only when
// ARMED (AI_USAGE_METER_FAKE=1), so the default fake stays free + the bar stays inert.
async function meterCall(owner, sessionId, now, u) {
  if (!u) return;
  const provider = process.env.AI_PROVIDER || 'fake';
  if (provider === 'fake' && process.env.AI_USAGE_METER_FAKE !== '1') return; // fake is free + unmetered by default
  // the identifier (exactly-once): the provider's response id when present; else agent's OWN atomic-minted fallback
  const identifier = u.identifier || `agent:${sessionId}:${await nextId('agent_usage_seq')}`;
  const call = { identifier, provider, model: u.model, input_tokens: u.input_tokens, output_tokens: u.output_tokens,
    cache_read_input_tokens: u.cache_read_input_tokens, cache_creation_input_tokens: u.cache_creation_input_tokens,
    reasoning_tokens: u.reasoning_tokens };
  const status = await usageRecord(owner, call, now); // never throws; the run's success is independent of the meter's
  if (status === 'no-meter' && provider !== 'fake' && !warnedUnmetered) {
    warnedUnmetered = true; // lazy, first-real-use only (no boot-time check — the import-order trap)
    process.stderr.write(JSON.stringify({ level: 'warn', event: 'usage_no_meter', provider,
      message: 'no usage meter is registered in this build — LLM spend is NOT being recorded (add the llm_usage domain, or meter externally via POST /llm_usage/events)' }) + '\n');
  }
}

// the agent loop/buffer bounds (max iterations · history ring-buffer · per-message cap) come from env via the
// central env_int part — the ×3-safe parse (trim · reject non-integer/hex/exponent · |value| > 2**53-1 -> default).

function maxIterations() {
  const n = envInt(process.env.AGENT_MAX_ITERATIONS, 6);
  return n >= 1 ? n : 6;
}

// maxHistory: the per-session ring-buffer cap (drop-oldest) — keeps the stored blob, the per-turn feed, and GET
// /messages BOUNDED (the unbounded-history O(n^2)/OOM/cost soft-DoS). MUST be >= maxIterations+2 so a run never evicts
// its own user turn mid-loop. Same env + floor as python config.HISTORY_MAX / go historyMax().
function maxHistory() {
  return Math.max(maxIterations() + 2, envInt(process.env.AGENT_HISTORY_MAX, 200));
}

const MSG_TRUNC = '…[truncated]…'; // advisory only — a tool may emit it; never key a decision on it

// msgMax: the per-message codepoint cap (middle-truncate). Floor 64, default 4000. Same env as python/go.
function msgMax() {
  return Math.max(64, envInt(process.env.AGENT_MAX_MSG_CHARS, 4000));
}

// truncateMiddle bounds s to cap CODE POINTS, keeping the HEAD and TAIL with a marker between (the tool answer/error
// is often at the end) — matches smolagents. Codepoint-based ([...s]), so identical ×3 with python (len) / go (rune).
function truncateMiddle(s, cap) {
  const r = [...s];
  if (r.length <= cap) return s;
  const keep = cap - [...MSG_TRUNC].length;
  if (keep <= 0) return r.slice(0, cap).join('');
  const head = Math.floor(keep / 2);
  return r.slice(0, head).join('') + MSG_TRUNC + r.slice(r.length - (keep - head)).join('');
}

// sseChunkSize: the SSE delta window in CODE POINTS (env SSE_CHUNK_CODEPOINTS via the env_int part; sub-1 ->
// the default 12) — a streamed run response chops the FINAL output at the transport; the run loop is untouched.
function sseChunkSize() {
  const n = envInt(process.env.SSE_CHUNK_CODEPOINTS, 12);
  return n >= 1 ? n : 12;
}

// chunkOutput splits the final output into fixed CODE-POINT windows for the streamed response — the same
// codepoint discipline as truncateMiddle (python len/slice · go []rune · node [...s]), so the delta frames are
// identical ×3 and always concatenate back to exactly the sync output.
export function chunkOutput(s) {
  const r = [...s];
  const k = sseChunkSize();
  const chunks = [];
  for (let i = 0; i < r.length; i += k) chunks.push(r.slice(i, i + k).join(''));
  return chunks;
}

async function remember(sessionId, role, content) {
  // CONTAIN a lone surrogate (e.g. a decoded `\ud800` JSON escape) -> U+FFFD via the central well_formed part, so the
  // stored content is ALWAYS UTF-8-serializable — else GET /messages (and the run response) raise an uncontained 5xx
  // on encode (the lone-surrogate crash class). Go is identity (its strings are valid UTF-8).
  content = truncateMiddle(makeWellFormed(content), msgMax()); // well-formed THEN size-bounded
  // atomic append via the storeDo seam: a get-then-put RACES — concurrent appends to one session lose a message
  // (the rbac F1 class). storeDo holds the write lock across read+write.
  // RING-BUFFER: keep only the last maxHistory messages (drop-oldest) — the BOUNDED conversation buffer.
  await storeDo('agent_memory', String(sessionId), (cur) => {
    const next = [...(cur || []), { role, content }];
    const max = maxHistory();
    return [next.length > max ? next.slice(next.length - max) : next, null];
  });
}


export async function history(sessionId) {
  return (await storeGet('agent_memory', String(sessionId))) || [];
}

export async function runLoop(provider, sessionId, system, userInput, owner, now) {
  await remember(sessionId, 'user', userInput);
  const budget = maxIterations();
  const done = async (output, iterations, terminated) => {
    output = truncateMiddle(makeWellFormed(output), msgMax()); // the RESPONSE matches the stored copy (bounded + contained)
    await remember(sessionId, 'assistant', output);
    return { output, iterations, terminated };
  };
  for (let i = 0; i < budget; i++) {
    // awaited: the fake answers synchronously, a SHIPPED real adapter round-trips HTTP. An adapter's mapped
    // upstream failure (ProviderFailure) propagates out of the loop to the route — the user turn stays in
    // history (it was received); no fabricated assistant turn is ever appended. Identical in python/go.
    const resp = await provider.complete(system, await history(sessionId));
    await meterCall(owner, sessionId, now, resp.usage); // meter this call's spend (never breaks the run)
    if (resp.final !== undefined) return await done(resp.final, i + 1, false); // the agent answered -> done
    const { output, ok } = runTool(resp.tool, resp.args);
    const observation = ok ? output : `error: ${output}`; // graceful, fed back, never a crash
    await remember(sessionId, 'tool', observation);
  }
  return await done('stopped: max iterations reached', budget, true); // the terminate guard
}
