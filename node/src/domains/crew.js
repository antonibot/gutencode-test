// crew — multi-agent orchestration: named roles that each process the running value and hand off to the next.
// The load-bearing invariant is TERMINATION UNDER CYCLES: the handoff graph MAY cycle (A->B->A is a legal
// definition), so MAX_HANDOFFS bounds every run — infinite ping-pong is impossible, and hitting the bound is
// reported (terminated:false), never disguised as success. A handoff to an UNKNOWN role is CONTAINED (the run
// stops gracefully with the trace so far). Handoffs THREAD. Store names and shapes match the python/go impls.
import { intParam, nextId, problem, requireIdentity, sendJSON, storeGet, storePut } from '../core/runtime.js';
import { isWellFormed } from '../parts/well_formed.js';

const MAX_HANDOFFS = 25;
// state in store: seq "crew_def" · ns "crew_defs" String(id) -> {id, roles}

export async function crewCreate(req, res, params, body) {
  if ((await requireIdentity(req, res)) === null) return; // authn -> validation: auth BEFORE decode (×3)
  if (!body || !Array.isArray(body.roles) || body.roles.length === 0) {
    return problem(res, 422, 'a crew needs at least one role');
  }
  const seen = new Set();
  for (const role of body.roles) {
    if (!role || typeof role !== 'object' || Array.isArray(role) || !isWellFormed(role.name)) {
      return problem(res, 422, "every role must be an object with a well-formed string 'name'");
    }
    if ('next' in role && typeof role.next !== 'string') {
      return problem(res, 422, "'next' must be a string role name");
    }
    if (seen.has(role.name)) return problem(res, 422, 'role names must be unique');
    seen.add(role.name);
  }
  const cid = await nextId('crew_def');
  await storePut('crew_defs', String(cid), { id: cid, roles: body.roles });
  sendJSON(res, 201, { id: cid, roles: body.roles.length });
}

export async function crewRun(req, res, params, body) {
  if ((await requireIdentity(req, res)) === null) return; // authn -> validation: auth BEFORE any work (×3)
  const cid = intParam(params.crew_id);
  if (cid === null) return problem(res, 422, 'invalid crew id');
  if (!body || typeof body.input !== 'string') return problem(res, 422, 'invalid body');
  const crew = await storeGet('crew_defs', String(cid));
  if (crew === undefined) return problem(res, 404, 'crew not found');
  const byName = Object.fromEntries(crew.roles.map((r) => [r.name, r]));
  let current = crew.roles[0];
  let value = body.input;
  const trace = [];
  let terminated = false;
  while (trace.length < MAX_HANDOFFS) { // TERMINATION: the bound holds whatever the graph shape
    value = `${value} [${current.name}]`; // the role's tagged contribution — THREADING by construction
    trace.push({ role: current.name, output: value });
    if (!('next' in current)) { terminated = true; break; } // a clean finish: the chain ended by design
    const next = byName[current.next];
    if (next === undefined) break; // CONTAINED: an unknown handoff stops gracefully, trace kept
    current = next;
  }
  sendJSON(res, 200, { output: value, handoffs: trace.length, terminated, trace });
}
