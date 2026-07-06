// The tool belt: a dispatcher that NEVER crashes (missing tool -> a graceful error observation) and the
// built-ins — calc (a recursive-descent parser over + - * / % and parentheses; NEVER an eval; one-decimal
// output so all three languages produce identical observations) and echo.

export function runTool(name, args) {
  if (name === 'calc') return { output: calc(String((args && args.expr) || '')), ok: true };
  if (name === 'echo') return { output: String((args && args.text) || ''), ok: true };
  return { output: `tool '${name}' not found`, ok: false };
}

function tokens(expr) {
  const out = [];
  let i = 0;
  while (i < expr.length) {
    const c = expr[i];
    if (c === ' ') { i++; continue; }
    if ('+-*/%()'.includes(c)) { out.push(c); i++; continue; }
    if ((c >= '0' && c <= '9') || c === '.') {
      let j = i;
      while (j < expr.length && ((expr[j] >= '0' && expr[j] <= '9') || expr[j] === '.')) j++;
      out.push(expr.slice(i, j));
      i = j;
      continue;
    }
    return null; // any other character -> invalid (never executed, never evaluated)
  }
  return out;
}

function calc(expr) {
  const toks = tokens(expr);
  if (!toks || toks.length === 0) return 'error: invalid expression';
  const p = { toks, pos: 0 };
  const v = parseExpr(p);
  if (v === null || p.pos !== p.toks.length) return 'error: invalid expression';
  if (!Number.isFinite(v)) return 'error: invalid expression'; // ±Infinity (1/0) / NaN (1%0) -> invalid, matching python/go (one observation ×3)
  return v.toFixed(1);
}

const peek = (p) => (p.pos < p.toks.length ? p.toks[p.pos] : '');

function parseExpr(p) {
  let v = parseTerm(p);
  if (v === null) return null;
  while (peek(p) === '+' || peek(p) === '-') {
    const op = p.toks[p.pos++];
    const r = parseTerm(p);
    if (r === null) return null;
    v = op === '+' ? v + r : v - r;
  }
  return v;
}

function parseTerm(p) {
  let v = parseUnary(p);
  if (v === null) return null;
  while (peek(p) === '*' || peek(p) === '/' || peek(p) === '%') {
    const op = p.toks[p.pos++];
    const r = parseUnary(p);
    if (r === null) return null;
    if (op === '*') v *= r;
    else if (op === '/') v /= r;
    else v = Math.trunc(v) % Math.trunc(r);
  }
  return v;
}

function parseUnary(p) {
  if (peek(p) === '-') {
    p.pos++;
    const v = parseUnary(p);
    return v === null ? null : -v;
  }
  if (peek(p) === '(') {
    p.pos++;
    const v = parseExpr(p);
    if (v === null || peek(p) !== ')') return null;
    p.pos++;
    return v;
  }
  const tok = peek(p);
  if (tok === '' || !/^[0-9.]+$/.test(tok)) return null;
  const v = Number(tok);
  if (!Number.isFinite(v)) return null;
  p.pos++;
  return v;
}
