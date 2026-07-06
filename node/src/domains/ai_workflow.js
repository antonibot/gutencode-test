// ai_workflow — multi-step pipelines over a running value: each step's output threads into the next. The
// dangerous property is TERMINATION + CONTAINMENT: a run ALWAYS terminates (MAX_STEPS bounds every run) and a
// failing or unknown step is CONTAINED (the run stops gracefully with ok:false and the trace so far — never a
// crash, never a 5xx). String ops slice and measure by CODEPOINTS (spread, not .length) — the x3-identical
// semantic. Definitions are durable. Store names and shapes match the python/go impls.
import { intParam, nextId, problem, requireIdentity, sendJSON, storeGet, storePut } from '../core/runtime.js';

const MAX_STEPS = 50;
// state in store: seq "ai_workflow_def" · ns "ai_workflow_defs" String(id) -> {id, steps}

// one step. Returns [newValue, ok] — unknown/invalid ops report ok=false, they never throw.
function apply(op, value, step) {
  const text = typeof step.text === 'string' ? step.text : '';
  if (op === 'append') return [value + text, true];
  if (op === 'prepend') return [text + value, true];
  if (op === 'truncate') {
    const n = Number.isInteger(step.n) && step.n >= 0 ? step.n : 0;
    return [[...value].slice(0, n).join(''), true]; // CODEPOINT slicing — parity with python/go
  }
  if (op === 'length') return [String([...value].length), true]; // CODEPOINT count
  return [value, false];
}

export async function aiWorkflowCreate(req, res, params, body) {
  if ((await requireIdentity(req, res)) === null) return; // authenticated mutation (no/invalid token -> 401)
  if (!body || !Array.isArray(body.steps) || body.steps.length === 0) {
    return problem(res, 422, 'a workflow needs at least one step');
  }
  for (const step of body.steps) {
    if (!step || typeof step !== 'object' || Array.isArray(step) || typeof step.op !== 'string' || step.op === '') {
      return problem(res, 422, "every step must be an object with a string 'op'");
    }
  }
  const wid = await nextId('ai_workflow_def');
  await storePut('ai_workflow_defs', String(wid), { id: wid, steps: body.steps });
  sendJSON(res, 201, { id: wid, steps: body.steps.length });
}

export async function aiWorkflowRun(req, res, params, body) {
  if ((await requireIdentity(req, res)) === null) return; // authenticated mutation (no/invalid token -> 401)
  const wid = intParam(params.workflow_id);
  if (wid === null) return problem(res, 422, 'invalid workflow id');
  if (!body || typeof body.input !== 'string') return problem(res, 422, 'invalid body');
  const wf = await storeGet('ai_workflow_defs', String(wid));
  if (wf === undefined) return problem(res, 404, 'workflow not found');
  let value = body.input;
  let ok = true;
  const trace = [];
  // TERMINATION: never more than MAX_STEPS, whatever was defined
  for (const step of wf.steps.slice(0, MAX_STEPS)) {
    const [next, stepOk] = apply(step.op, value, step);
    value = next;
    if (!stepOk) { ok = false; break; } // CONTAINMENT: stop gracefully, keep the trace so far
    trace.push({ op: step.op, output: value });
  }
  if (ok && wf.steps.length > MAX_STEPS) ok = false; // the budget itself was exceeded — report it, loudly
  sendJSON(res, 200, { output: value, steps_run: trace.length, ok, trace });
}
