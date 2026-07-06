// evals — a deterministic, OFFLINE scoring harness for model outputs (same ×3 as evals.py / evals.go). Store an
// IMMUTABLE owner-scoped golden SUITE (a named set of cases, each {id, scorer, expected}), then SCORE caller-PROVIDED
// outputs against it — evals NEVER calls a model. The dangerous property is SCORE-SOUNDNESS: the verdict is
// SERVER-DERIVED over a FROZEN suite (the score body carries ONLY outputs; a smuggled pass/passed is never read), and
// DETERMINISTIC ×3 — score(scorer, output, expected) is a PURE function whose per-case pass is byte-identical in
// python==go==node and reproducible across runs/restart.
//
// IDENTITY + ISOLATION: every route requireIdentity FIRST (the runtime already parsed the body / emitted 413/422,
// so auth-before-validation holds ×3). No/invalid token -> 401. A suite is USER-SCOPED two ways: the store key is the
// composite `<owner>\x1f<name>` (caller B can NEVER clobber caller A's suite name — the separator is a control char
// isWellFormed rejects, so it can't be forged), and every read filters on the authenticated owner FIELD (not-yours ==
// 404, existence never leaks). The owner is stamped from the token, never a body field. A suite is IMMUTABLE-on-create:
// a 2nd create of the same name -> 409 via the atomic storeDo claim seam.
//
// Scorers are authored HERE (the ×3 source of truth): exact/contains/starts_with/ends_with are raw code-point ops;
// iexact/icontains use an ASCII case-fold (A-Z<->a-z, non-ASCII raw — identical ×3; full Unicode casefold is a v2);
// equals_int parses a CANONICAL integer bounded to ±(2^53-1) (>2^53 rejects uniformly via Number.isSafeInteger).
// Scoring is STATELESS; the pass verdict + integer counts are pinned, never a float. Regex / float-similarity /
// json_equal are DELIBERATELY v2.
import { problem, requireIdentity, sendJSON, storeDo, storeGet, storeValues, testNow } from '../core/runtime.js';
import { envInt } from '../parts/env_int.js';
import { paginate } from '../parts/paginate.js';
import { isWellFormed, makeWellFormed } from '../parts/well_formed.js';

const MAX_SAFE_INT = 9007199254740991;                         // 2**53-1
const MAX_CASES = envInt(process.env.EVALS_MAX_CASES, 500, 1);
const MAX_EXPECTED = envInt(process.env.EVALS_MAX_EXPECTED_BYTES, 8192, 1);
const MAX_OUTPUT = envInt(process.env.EVALS_MAX_OUTPUT_BYTES, 65536, 1);

const SCORERS = new Set(['exact', 'contains', 'starts_with', 'ends_with', 'iexact', 'icontains', 'equals_int']);
const INT_RE = /^-?(0|[1-9][0-9]*)$/;

// asciiFold: A-Z -> a-z, every other code point RAW (identical ×3 — A-Z are single BMP code units, so this matches
// python's chr(ord+32) and go's rune map exactly; unlike toLowerCase(), which diverges on ß/Turkish-i).
const asciiFold = (s) => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));

// strictInt: a CANONICAL integer within ±(2^53-1), else null. Number.isSafeInteger rejects a magnitude past 2^53
// (a >2^53 literal parses to a lossy float that is not a safe integer) -> rejected uniformly ×3.
function strictInt(s) {
  if (!INT_RE.test(s)) return null;
  const v = Number(s);
  return Number.isSafeInteger(v) ? v : null;
}

// the PURE deterministic verdict — a code/regex-shaped output/expected is scored as plain TEXT, never executed. Both
// sides are already contained.
function scoreOne(scorer, output, expected) {
  switch (scorer) {
    case 'exact': return output === expected;
    case 'contains': return output.includes(expected);
    case 'starts_with': return output.startsWith(expected);
    case 'ends_with': return output.endsWith(expected);
    case 'iexact': return asciiFold(output) === asciiFold(expected);
    case 'icontains': return asciiFold(output).includes(asciiFold(expected));
    case 'equals_int': {
      const eo = strictInt(output);
      const ee = strictInt(expected);
      return eo !== null && ee !== null && eo === ee;
    }
    default: return false;
  }
}

const meta = (s) => ({ name: s.name, owner: s.owner, case_count: s.case_count, created_at: s.created_at });

export async function evalsCreateSuite(req, res, params, body) {
  const owner = await requireIdentity(req, res);              // authn BEFORE validation (runtime already parsed the body)
  if (owner === null) return;
  if (!body || !isWellFormed(body.name)) return problem(res, 422, 'the suite name must be non-empty with no control characters');
  if (!Array.isArray(body.cases) || body.cases.length < 1) return problem(res, 422, 'a suite needs at least one case');
  if (body.cases.length > MAX_CASES) return problem(res, 422, 'too many cases');
  const seen = new Set();
  const cases = [];
  for (const c of body.cases) {
    if (!c || typeof c !== 'object' || !isWellFormed(c.id)) return problem(res, 422, 'each case id must be non-empty with no control characters');
    if (seen.has(c.id)) return problem(res, 422, `duplicate case id '${c.id}'`);
    seen.add(c.id);
    if (!SCORERS.has(c.scorer)) return problem(res, 422, 'unknown scorer');
    if (typeof c.expected !== 'string') return problem(res, 422, 'each case needs a string expected value');
    if ([...c.expected].length > MAX_EXPECTED) return problem(res, 422, 'a case expected value is too large');
    const expected = makeWellFormed(c.expected);             // contain BEFORE store/compare (lone surrogate -> U+FFFD)
    if (c.scorer === 'equals_int' && strictInt(expected) === null) {
      return problem(res, 422, 'an equals_int expected must be a canonical integer within the safe range');
    }
    cases.push({ id: c.id, scorer: c.scorer, expected });
  }
  cases.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)); // deterministic id-asc order ×3
  const now = testNow(req);                                      // server clock (test seam ?now); never client-set
  const record = { name: body.name, owner, cases, case_count: cases.length, created_at: now };
  // IMMUTABLE create-once through the atomic storeDo seam: two racers -> exactly one writes (201), the other -> 409.
  const outcome = await storeDo('evals_suites', `${owner}\x1f${body.name}`,
    (cur) => (cur !== undefined ? [undefined, 'conflict'] : [record, 'ok']));
  if (outcome === 'conflict') return problem(res, 409, 'a suite with this name already exists');
  // expose owner + created_at (server-set — proves the mass-assign discard) + case_count (server-derived)
  sendJSON(res, 201, { name: body.name, owner, case_count: cases.length, created_at: now });
}

export async function evalsListSuites(req, res) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  // read-scope: only the caller's own suites leave the store (filtered on the authenticated owner FIELD), name-sorted
  // for a stable paged walk (storeValues order is NOT stable ×3), then a BOUNDED page; a stranger -> empty page, never 403.
  const mine = (await storeValues('evals_suites')).filter((s) => s.owner === owner)
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)).map(meta);
  const q = new URL(req.url, 'http://localhost').searchParams;
  const { items, next, ok } = paginate(mine, q.get('cursor') || '', q.get('limit') || '');
  if (!ok) return problem(res, 422, 'invalid cursor or limit');
  sendJSON(res, 200, { results: items, next_cursor: next });
}

export async function evalsGetSuite(req, res, params) {
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  if (!isWellFormed(params.name)) return problem(res, 404, 'suite not found'); // a malformed name can't exist -> 404
  const s = await storeGet('evals_suites', `${owner}\x1f${params.name}`);      // cross-owner name -> different slot -> 404
  if (s === undefined) return problem(res, 404, 'suite not found');
  sendJSON(res, 200, { name: s.name, owner: s.owner, case_count: s.case_count, created_at: s.created_at, cases: s.cases });
}

export async function evalsScore(req, res, params, body) {
  // STATELESS: score caller-PROVIDED outputs against the FROZEN suite; return the verdict, store nothing. The body
  // carries ONLY outputs -> a smuggled pass/passed/all_pass is never read (SCORE-SOUNDNESS; proven by I-SCORE-DERIVED).
  const owner = await requireIdentity(req, res);
  if (owner === null) return;
  if (!isWellFormed(params.name)) return problem(res, 404, 'suite not found');
  const s = await storeGet('evals_suites', `${owner}\x1f${params.name}`);      // read-scope: cross-owner name -> 404
  if (s === undefined) return problem(res, 404, 'suite not found');
  if (!body || typeof body.outputs !== 'object' || body.outputs === null || Array.isArray(body.outputs)) {
    return problem(res, 422, 'outputs must be an object');
  }
  const results = [];
  let passed = 0;
  for (const c of s.cases) {                                    // stored id-asc -> deterministic result order ×3
    const out = body.outputs[c.id];
    if (typeof out !== 'string') return problem(res, 422, `missing or non-string output for case '${c.id}'`);
    if ([...out].length > MAX_OUTPUT) return problem(res, 422, 'an output is too large');
    const p = scoreOne(c.scorer, makeWellFormed(out), c.expected); // contain the output BEFORE compare (no 5xx on a surrogate)
    results.push({ case_id: c.id, pass: p });
    if (p) passed += 1;
  }
  sendJSON(res, 200, { results, passed, total: results.length, all_pass: passed === results.length });
}
