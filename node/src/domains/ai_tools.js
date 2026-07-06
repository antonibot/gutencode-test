// ai_tools — the typed tool belt: a registry of tools any caller invokes over HTTP. Each tool declares a TYPED
// CONTRACT — a description + an input_schema (JSON Schema: per-arg type + which are required) — and the args are
// VALIDATED against it. The dangerous property is SAFE EXECUTION: an invoke whose args violate the contract (a
// missing required arg, OR an arg of the wrong type) is CONTAINED (ok:false + the error, HTTP 200 — a tool failure
// is a RESULT, never a crash or a 5xx), an unknown tool is an honest 404, and every tool is deterministic and
// BOUNDED (repeat is capped — output can never explode). String ops work by CODEPOINTS (spread), the x3-identical
// semantic; text is normalized to well-formed Unicode (a lone surrogate -> U+FFFD via toWellFormed, matching go's
// decoder + python) so a result is always serializable. Integer args are STRICT and x3-identical within the
// safe-integer range (5.0 / "5" / true / null AND any magnitude beyond +/-(2**53-1) rejected via isStrictInt +
// Number.isSafeInteger). The registry is static policy (no store). Matches the python/go impls.
import { isStrictInt, problem, requireIdentity, sendJSON } from '../core/runtime.js';
import { isWellFormed, makeWellFormed } from '../parts/well_formed.js';

const REPEAT_CAP = 100;

const text = (a) => a.text; // validated: text is a string

// the ONE registry: name -> {desc, args:[{name,type,required,desc}], fn}. Static policy, identical x3. The
// input_schema (listing), the required[] and the per-arg validation are all DERIVED from args — one source per tool.
const TOOLS = {
  upper: {
    desc: 'Uppercase the text by Unicode codepoint.',
    args: [{ name: 'text', type: 'string', required: true, desc: 'the text to uppercase' }],
    fn: (a) => text(a).toUpperCase(),
  },
  reverse: {
    desc: 'Reverse the text by Unicode codepoint (non-BMP characters stay whole).',
    args: [{ name: 'text', type: 'string', required: true, desc: 'the text to reverse' }],
    fn: (a) => [...text(a)].reverse().join(''), // codepoint reverse
  },
  wordcount: {
    desc: 'Count the whitespace-separated words in the text.',
    args: [{ name: 'text', type: 'string', required: true, desc: 'the text to count words in' }],
    fn: (a) => String(text(a).split(/\s+/).filter(Boolean).length),
  },
  repeat: {
    desc: 'Repeat the text n times; n is clamped to 0..100 so the output can never explode.',
    args: [
      { name: 'text', type: 'string', required: true, desc: 'the text to repeat' },
      { name: 'n', type: 'integer', required: false, desc: 'how many times to repeat (clamped to 0..100; default 1)' },
    ],
    fn: (a) => {
      let n = typeof a.n === 'number' ? a.n : 1; // validated: present -> a strict int, absent -> the default (1)
      if (n < 0) n = 0;
      return text(a).repeat(Math.min(n, REPEAT_CAP)); // BOUNDED: output can never explode
    },
  },
};
const ORDER = ['repeat', 'reverse', 'upper', 'wordcount']; // sorted, deterministic x3

// DERIVE the JSON-Schema input_schema from the arg specs (one source per tool).
function inputSchema(args) {
  const properties = {};
  const required = [];
  for (const ar of args) {
    properties[ar.name] = { type: ar.type, description: ar.desc };
    if (ar.required) required.push(ar.name);
  }
  return { type: 'object', properties, required };
}

// Validate args against the typed contract: every required arg present + every present arg the declared type.
// Returns the error string, or null when valid. Unknown (undeclared) args are IGNORED — lenient. STRICT integer
// (reject 5.0 / "5" / true / null) via isStrictInt — the node half of the runtime strict-int seam
// (FLOAT_LITERAL_KEYS), identical x3 with python + go RequireIntRaw.
function validate(args, specs) {
  for (const sp of specs) {
    if (!(sp.name in args)) {
      if (sp.required) return `missing required arg '${sp.name}'`;
      continue;
    }
    const v = args[sp.name];
    if (sp.type === 'string') {
      if (typeof v !== 'string') return `arg '${sp.name}' must be a string`;
      args[sp.name] = makeWellFormed(v); // central: lone surrogate -> U+FFFD (well_formed part); keeps output x3 + serializable
    }
    // STRICT integer AND within the x3-safe range: isStrictInt rejects 5.0/"5"/true/null; Number.isSafeInteger rejects |n| > 2**53-1
    if (sp.type === 'integer' && (!isStrictInt(args, sp.name) || !Number.isSafeInteger(v))) return `arg '${sp.name}' must be an integer`;
  }
  return null;
}

export async function aiToolsList(req, res) {
  // read-scope: public — the global static tool catalog (each tool's name + typed contract), identical for every caller.
  sendJSON(res, 200, ORDER.map((name) => ({ name, description: TOOLS[name].desc, input_schema: inputSchema(TOOLS[name].args) })));
}

export async function aiToolsInvoke(req, res, params, body) {
  if ((await requireIdentity(req, res)) === null) return; // any authenticated caller may invoke (no/invalid token -> 401)
  const args = body && body.args !== undefined ? body.args : {};
  if (typeof args !== 'object' || args === null || Array.isArray(args)) {
    return problem(res, 422, 'invalid body');
  }
  const name = params.tool_name;
  if (!isWellFormed(name)) return problem(res, 422, 'tool name must be non-empty with no control characters');
  // own-property ONLY: a prototype-chain name (__proto__, toString, constructor) is NOT a tool — else TOOLS[name]
  // would resolve up Object.prototype, bypass the 404, and crash validate(args, undefined) with an uncontained 500.
  if (!Object.hasOwn(TOOLS, name)) return problem(res, 404, 'tool not found');
  const entry = TOOLS[name];
  const err = validate(args, entry.args);
  if (err !== null) {
    // CONTAINED: a contract violation is a RESULT the caller can read — never a crash, never a 5xx
    return sendJSON(res, 200, { tool: name, ok: false, output: '', error: err });
  }
  sendJSON(res, 200, { tool: name, ok: true, output: entry.fn(args), error: null });
}
