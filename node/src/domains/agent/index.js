// The agent domain — a multi-file AI agent runtime (package shape): swappable provider port · tool registry
// (safe calc, never eval) · durable agents/sessions/memory · a bounded run loop that ALWAYS terminates.
// Store namespaces and counters match the python/go impls.
import { intParam, nextId, problem, requireIdentity, sendJSON, storeGet, storePut, stream, testNow, wantsStream } from '../../core/runtime.js';
import { getProvider, ProviderFailure } from './providers.js';
import { chunkOutput, history, runLoop } from './runtime.js';
// path ids use the runtime's STRICT intParam (rejects 5.0/abc → 422, matching python IntPath + go strconv.Atoi)
// USER-SCOPED: every {agent_id}-addressed route calls requireIdentity FIRST (the runtime
// parses the body before the handler, so auth before validation is correct ×3) AND the agent must be OWNED by the
// caller. The owner is stamped from the token at create (never a body field) and kept OUT of the response (internal,
// like api_keys' secret_hash). A cross-owner id is 404 — byte-identical to a missing id (not-yours == not-found).

// the wire view NEVER includes the owner (internal).
const agentPublic = (a) => ({ id: a.id, name: a.name, system_prompt: a.system_prompt });

// loadAgent expects requireIdentity to have run already; it does the path-int check, loads, then enforces
// owner==caller, returning 404 for a missing OR cross-owner id. Mirrors api_keys' load.
async function loadAgent(res, params, owner) {
  const agentId = intParam(params.agent_id);
  if (agentId === null) { problem(res, 422, 'invalid agent id'); return null; }
  const agent = await storeGet('agent_agents', String(agentId));
  if (agent === undefined || agent.owner !== owner) { problem(res, 404, 'agent not found'); return null; }
  return agent;
}

export async function agentCreate(req, res, params, body) {
  const owner = await requireIdentity(req, res); // authenticated mutation (no/invalid token -> 401)
  if (owner === null) return;
  if (!body || typeof body.name !== 'string' || typeof body.system_prompt !== 'string') {
    return problem(res, 422, 'invalid body');
  }
  // owner derived from the token, never client-set; stored on the record but kept OUT of the response.
  const out = { id: await nextId('agent_agent'), name: body.name, system_prompt: body.system_prompt, owner };
  await storePut('agent_agents', String(out.id), out);
  sendJSON(res, 201, agentPublic(out));
}

export async function agentCreateSession(req, res, params) {
  const owner = await requireIdentity(req, res); // identity before the path id
  if (owner === null) return;
  const agent = await loadAgent(res, params, owner); // owner-or-404 before creating a session under the agent
  if (agent === null) return;
  const sid = await nextId('agent_session');
  await storePut('agent_sessions', String(sid), agent.id);
  sendJSON(res, 201, { id: sid, agent_id: agent.id });
}

async function sessionOf(res, params) {
  const agentId = intParam(params.agent_id);
  const sessionId = intParam(params.session_id);
  if (agentId === null || sessionId === null) {
    problem(res, 422, 'invalid id');
    return null;
  }
  if ((await storeGet('agent_sessions', String(sessionId))) !== agentId) {
    problem(res, 404, 'session for this agent not found');
    return null;
  }
  return { agentId, sessionId };
}

export async function agentRun(req, res, params, body) {
  const owner = await requireIdentity(req, res); // identity before path + body validation
  if (owner === null) return;
  const agent = await loadAgent(res, params, owner); // owner-or-404 FIRST
  if (agent === null) return;
  const ids = await sessionOf(res, params); // then the session<->agent binding
  if (!ids) return;
  if (!body || typeof body.input !== 'string') return problem(res, 422, 'invalid body');
  const sel = getProvider();
  if (sel.problem) return problem(res, 501, sel.problem); // fail LOUD per call — never silent fake output (see providers.js)
  let result;
  try {
    // owner = the run's authenticated subject (owner-self-metering, executed server-side — the spend lands in THIS
    // user's llm_usage summary); now = the request clock (keeps the test-clock seam coherent).
    result = await runLoop(sel.provider, ids.sessionId, agent.system_prompt, body.input, owner, testNow(req));
  } catch (e) {
    // a wired adapter's upstream failure — mapped 502/504, rendered as the ONE problem+json envelope BEFORE
    // any SSE byte (streaming only begins after every guard AND the run have completed).
    if (e instanceof ProviderFailure) return problem(res, e.status, e.detail);
    throw e;
  }
  const out = { session_id: ids.sessionId, ...result };
  if (wantsStream(req)) {
    // SSE mode (?stream=1, or Accept: text/event-stream) — the SAME run result, chunked at the transport: the
    // delta frames concatenate to exactly `result.output`, and `event: done` carries this exact sync body.
    return stream(res, chunkOutput(result.output), out);
  }
  sendJSON(res, 200, out);
}

// READ is USER-SCOPED: identity FIRST, then owner-or-404, THEN the session<->agent
// binding. A non-owner reading another's messages -> 404; no token -> 401.
export async function agentMessages(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  if ((await loadAgent(res, params, owner)) === null) return;
  const ids = await sessionOf(res, params);
  if (!ids) return;
  sendJSON(res, 200, await history(ids.sessionId));
}
