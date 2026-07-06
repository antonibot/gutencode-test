import http from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { db, nextId, storeGet, storePut, storeValues, storeDelete, storeDo, apiKeyResolve } from './store.js';

// The durable store + atomic id mint + the storeDo RMW seam live in ./store.js (split out so this file stays under
// the 400-LOC budget and the Postgres driver has a home). Re-export the public store surface so domains import it
// from core/runtime.js exactly as before — the surface is byte-identical.
export { db, nextId, storeGet, storePut, storeValues, storeDelete, storeDo };

// MaxBodyBytes caps a request body (DoS guard). 1 MiB is generous for JSON APIs.
const MAX_BODY_BYTES = 1 << 20;

// problem+json (RFC 9457) — mirrors the python errors runtime + go runtime.go.
export function problem(res, status, detail) {
  res.writeHead(status, { 'Content-Type': 'application/problem+json' });
  res.end(JSON.stringify({ type: 'about:blank', title: detail, status, detail }));
}

export function sendJSON(res, status, value) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(value));
}

// wantsStream: did the caller opt into the Server-Sent-Events response MODE on a stream-capable route? The
// canonical `?stream=1` query flag, or an `Accept: text/event-stream` header (content negotiation, honored as
// the equivalent). Never a body field — the request body stays byte-identical between the two modes.
export function wantsStream(req) {
  const url = new URL(req.url, 'http://localhost');
  return url.searchParams.get('stream') === '1' || (req.headers.accept || '').includes('text/event-stream');
}

// stream: a Server-Sent Events response — each text delta rides one `event: delta` frame as {"delta":"<text>"},
// then ONE terminal `event: done` frame carries the FULL sync-shape body, so the streamed response always
// reconstructs to exactly the non-streamed one. All guards run BEFORE this is called (a pre-stream refusal keeps
// the normal problem+json envelope); a failure AFTER the first byte cannot change the already-sent 200, so it
// becomes a terminal `event: error` frame (the same problem shape, as frame data) and the stream closes.
// setHeader (not a bare writeHead) keeps the request-id/CORS headers already stamped; flushHeaders + a write per
// frame push each frame as it is produced; `Cache-Control: no-cache` + `X-Accel-Buffering: no` tell reverse
// proxies not to buffer the frames (a buffering proxy is the #1 real-world SSE failure — also disable proxy
// buffering at the proxy).
export function stream(res, deltas, done) {
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();
  const frame = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  try {
    for (const chunk of deltas) frame('delta', { delta: chunk });
    frame('done', done);
  } catch {
    frame('error', { type: 'about:blank', title: 'internal error', status: 500, detail: 'internal error' });
  }
  res.end();
}

// the non-enumerable marker the parser hangs off every object: a Set of field names whose JSON literal was a non-integer number (5.0/1e2), shared across nested objects so isStrictInt works at any depth.
const FLOAT_LITERAL_KEYS = Symbol('floatLiteralKeys');

// intParam: STRICT integer from a PATH segment, or null — accept ONLY a bare integer literal (reject 5.0/1e2/abc); ×3 parity with go strconv.Atoi / python IntPath.
export function intParam(raw) {
  return /^-?\d+$/.test(raw) ? Number(raw) : null;
}

// isStrictInt: STRICT integer body field — true ONLY for an integer literal (reject 5.0/1e2/"5"/true/null) via FLOAT_LITERAL_KEYS, AND within the ±(2**53-1) safe range. Number.isSafeInteger rejects a magnitude past 2**53 (where this float loses precision while go's Atoi caps at int64 + python is arbitrary-precision) → bounded uniformly ×3; ×3 parity with python SafeInt / go RequireInt.
export function isStrictInt(holder, key) {
  if (!holder || typeof holder !== 'object') return false;
  const v = holder[key];
  if (typeof v !== 'number' || !Number.isSafeInteger(v)) return false;
  const fk = holder[FLOAT_LITERAL_KEYS];
  return !(fk && fk.has(key));
}

// testNow: the test-clock seam — a `now` query parameter is honored ONLY under APP_TEST_CLOCK=1; in production
// the parameter is IGNORED and real time is used. Mirrors python clock.current and go testNow exactly.
export function testNow(req) {
  if (process.env.APP_TEST_CLOCK === '1') {
    // STRICT ?now parse: accept ONLY a pure integer literal — parseInt is LENIENT ("1000garbage" -> 1000), which would
    // make a malformed override diverge ×3 (node honors it where python int()/go strconv.ParseInt reject it and fall
    // back to real time). A non-integer ?now is ignored, identical ×3.
    const raw = new URL(req.url, 'http://localhost').searchParams.get('now') || '0';
    const v = /^-?\d+$/.test(raw) ? Number(raw) : 0;
    if (v > 0) return v;
  }
  return Math.floor(Date.now() / 1000);
}

// one structured JSON access-log line to stderr (set LOG_LEVEL=silent to suppress).
function logLine(level, rid, method, path, status, ms, errMsg) {
  if (process.env.LOG_LEVEL === 'silent') return;
  const entry = { level, request_id: rid, method, path, status, ms };
  if (errMsg) entry.error = errMsg;
  process.stderr.write(JSON.stringify(entry) + '\n');
}

// tiny method+path router + cross-cutting server behaviour (request id · access log · body cap · opt-in CORS · 500-on-throw). {name} params.
export function createServer(routes) {
  // CORS is OPT-IN via CORS_ALLOWED_ORIGINS — comma-separated exact origins (e.g.
  // "https://app.example.com,http://localhost:3000") or the single wildcard '*'. Unset/empty disables it
  // entirely: no header is added and OPTIONS routes exactly as before. Parsed ONCE here; each request then
  // does an exact-string match against the list (never a pattern or suffix match).
  const corsOrigins = (process.env.CORS_ALLOWED_ORIGINS || '').split(',').map((o) => o.trim()).filter(Boolean);
  const server = http.createServer(async (req, res) => {
    const start = Date.now();
    const rid = randomBytes(8).toString('hex'); req.requestId = rid; // req.requestId = handlers' AU-3 'source' for a domain audit ×3
    res.setHeader('X-Request-Id', rid);
    const done = (level, err) => logLine(level, rid, req.method, (req.url || '').split('?')[0], res.statusCode, Date.now() - start, err);
    try {
      if (corsOrigins.length > 0) {
        // The CORS decision for this request: the allowlist entry to echo (the exact matched origin, or '*'),
        // else null. An unlisted Origin is NEVER echoed back — reflecting the caller's Origin would grant every
        // site access.
        const origin = req.headers.origin;
        const allowOrigin = !origin ? null
          : (corsOrigins.includes('*') ? '*' : (corsOrigins.includes(origin) ? origin : null));
        // Answer a CORS preflight (OPTIONS + Origin + Access-Control-Request-Method) BEFORE routing: 204 always,
        // carrying the Access-Control-* grant only for an allowed origin — the browser treats the bare 204 as a
        // denial, and the allowlist is never revealed. An OPTIONS without both headers routes as normal.
        if (req.method === 'OPTIONS' && origin && req.headers['access-control-request-method']) {
          if (allowOrigin) {
            res.setHeader('Access-Control-Allow-Origin', allowOrigin);
            res.setHeader('Access-Control-Allow-Methods', req.headers['access-control-request-method']);
            res.setHeader('Access-Control-Allow-Headers',
              req.headers['access-control-request-headers'] || 'Authorization, Content-Type, Idempotency-Key');
            res.setHeader('Access-Control-Max-Age', '600');
            if (allowOrigin !== '*') res.setHeader('Vary', 'Origin');
          }
          res.statusCode = 204;
          res.end();
          return done('info');
        }
        // An actual (non-preflight) request from an allowed origin carries the grant on EVERY response, errors
        // included — a browser app can only READ a 4xx/5xx body when the grant is present.
        if (allowOrigin) {
          res.setHeader('Access-Control-Allow-Origin', allowOrigin);
          res.setHeader('Access-Control-Expose-Headers', 'X-Request-Id');
          if (allowOrigin !== '*') res.setHeader('Vary', 'Origin'); // the grant varies by Origin, so caches must key on it
        }
      }
      const url = new URL(req.url, 'http://localhost');
      if (/%2f|%5c/i.test(url.pathname)) { problem(res, 404, 'not found'); return done('warn'); } // reject encoded path-sep %2F/%5C pre-routing (it splits a segment on python; captured intact on go/node) — uniform 404 ×3
      // REJECT a DUPLICATED query parameter (?x=1&x=2) BEFORE routing — frameworks disagree on a repeat (starlette LAST, go/node FIRST) -> uniform 422 (canonical-input stance, like the dup-header reject); every scalar identical ×3
      const _qk = [...url.searchParams.keys()];
      if (_qk.length !== new Set(_qk).size) { problem(res, 422, 'duplicate query parameter'); return done('warn'); }
      let raw = '';
      let tooBig = false;
      for await (const chunk of req) {
        if (tooBig) continue;                  // DRAIN the rest, discard - replying mid-upload makes the OS
        raw += chunk;                          // reset the connection (the client sees an abort, never the 413);
        if (raw.length > MAX_BODY_BYTES) {     // memory stays capped, requestTimeout bounds the read
          tooBig = true;
          raw = '';
        }
      }
      if (tooBig) { problem(res, 413, 'request body too large'); return done('warn'); }
      let body = null;
      if (raw) {
        // STRICT-INT seam: JSON.parse collapses 5 and 5.0 to one number, so a field meant to be an integer
        // would accept 5.0/1e2 (diverging from python StrictInt + go's int decode). The source-access reviver
        // (node>=21) sees each number's raw token; we record the KEY of any non-integer numeric literal and hang
        // the shared set off every parsed object (FLOAT_LITERAL_KEYS) so isStrictInt() can reject it ×3.
        try {
          // a non-integer numeric literal records its key on ITS HOLDER (`this`) — object-scoped, not a shared name set, so a nested float can't poison a different object's same-named strict-int field [×3 strict-int parity fix]
          body = JSON.parse(raw, function (key, value, context) {
            if (typeof value === 'number' && context && typeof context.source === 'string' && /[.eE]/.test(context.source)) {
              let fk = this[FLOAT_LITERAL_KEYS];
              if (!fk) { fk = new Set(); try { Object.defineProperty(this, FLOAT_LITERAL_KEYS, { value: fk, configurable: true }); } catch { /* frozen */ } }
              fk.add(key);
            }
            return value;
          });
        } catch { problem(res, 422, 'invalid body'); return done('warn'); }
      }
      let pathMatched = false;
      for (const [method, pattern, handler] of routes) {
        const names = [];
        const reStr = pattern.replace(/\{([^}]+)\}/g, (_, n) => { names.push(n); return '([^/]+)'; });
        const m = url.pathname.match(new RegExp('^' + reStr + '$'));
        if (!m) continue;
        pathMatched = true;
        if (req.method !== method) continue;
        const params = {};
        // path params are PERCENT-DECODED (like go's PathValue) so a %1F reaches the handler as its control char (×3 validation parity); a malformed escape keeps the raw text for the handler to reject
        names.forEach((n, i) => {
          try { params[n] = decodeURIComponent(m[i + 1]); } catch { params[n] = m[i + 1]; }
        });
        await handler(req, res, params, body, raw); // raw = the exact request bytes (raw-body sig verifiers)
        return done('info');
      }
      // path exists but no method matched -> 405; otherwise unknown route -> 404 (same envelope, all three langs)
      problem(res, pathMatched ? 405 : 404, pathMatched ? 'method not allowed' : 'not found');
      return done('info');
    } catch (err) {
      if (!res.headersSent) problem(res, 500, 'internal error');
      return done('error', String((err && err.stack) || err));
    }
  });
  // timeouts are mandatory in production: a server with no deadline is a slow-loris DoS target (parity with go).
  server.headersTimeout = 10000;
  server.requestTimeout = 30000;
  return server;
}

// ── the cross-cutting AUTH/IDENTITY seam (core-owned sessions) ───────────────────────────────────────────────
// Core-owned sessions (domains read identity via requireIdentity, no auth import). Bearer "<id>.<secret>": keyed by
// the public id; only sha256(secret) stored (leak-safe + constant-time); absolute exp enforced every read;
// rotate+reuse-detect on /refresh; field names are the ×3 contract (full rationale: the python core/store.py docstring).
const SESSION_NS = '_sessions';
const SESSION_INDEX_NS = '_session_index'; // subject -> [id...]; revoke-all is O(k)

function sessionTTL() {
  const v = parseInt(process.env.SESSION_TTL_SECONDS || '', 10);
  return Number.isInteger(v) && v >= 60 ? v : 604800; // 7d (ASVS L1; 43200=12h for L2)
}
function sessionRefresh() {
  const v = parseInt(process.env.SESSION_REFRESH_SECONDS || '', 10);
  return Number.isInteger(v) && v >= 1 ? v : 86400;
}
function sessionReuseGrace() { const v = parseInt(process.env.SESSION_REUSE_GRACE_SECONDS || '', 10); return Number.isInteger(v) && v >= 0 ? v : 10; }
function sha256Hex(s) { return createHash('sha256').update(s).digest('hex'); }
function ctEqualHex(a, b) {
  // constant-time compare of two hex strings; unequal length -> false WITHOUT timingSafeEqual's throw
  const ba = Buffer.from(a, 'utf8'); const bb = Buffer.from(b, 'utf8');
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}
function splitToken(token) {
  const i = (token || '').indexOf('.');
  if (i <= 0 || i >= token.length - 1) return [null, null];
  return [token.slice(0, i), token.slice(i + 1)];
}
async function sessionIndexAdd(subject, sid) {
  await storeDo(SESSION_INDEX_NS, subject, (cur) => {
    const ids = cur || [];
    return ids.includes(sid) ? [ids, null] : [[...ids, sid], null];
  });
}
async function sessionIndexRemove(subject, sid) {
  await storeDo(SESSION_INDEX_NS, subject, (cur) => [(cur || []).filter((id) => id !== sid), null]);
}

// sessionCreate mints a durable "<id>.<secret>" bearer; only sha256(secret) is stored, exp = now + SESSION_TTL.
// `now` defaults to the wall clock. Parity with python/go.
export async function sessionCreate(subject, now) {
  now = (now === undefined || now === null) ? Math.floor(Date.now() / 1000) : Math.floor(now);
  const sid = randomBytes(16).toString('base64url');
  const secret = randomBytes(32).toString('base64url');
  await storePut(SESSION_NS, sid, { subject, secret_hash: sha256Hex(secret), prev_hash: '', prev_at: 0,
    exp: now + sessionTTL(), created_at: now, gen: 1 });
  await sessionIndexAdd(subject, sid);
  return `${sid}.${secret}`;
}

// sessionResolve: "<id>.<secret>" -> subject, or undefined. Enforces now < exp (wall clock), a constant-time
// secret check, and throttled idle-sliding extension. TEST SEAM: under APP_TEST_SESSIONS=1 a 'test:<subject>'
// token resolves to <subject> WITHOUT a stored session — INERT in production.
export async function sessionResolve(token) {
  if (process.env.APP_TEST_SESSIONS === '1' && token.startsWith('test:')) {
    return token.slice(5) || undefined;
  }
  const now = Math.floor(Date.now() / 1000);
  const [sid, secret] = splitToken(token);
  if (sid === null) return undefined;
  const rec = await storeGet(SESSION_NS, sid);
  if (!rec || now >= (rec.exp || 0)) return undefined;
  if (!ctEqualHex(sha256Hex(secret), rec.secret_hash || '')) return undefined;
  const ttl = sessionTTL();
  if (rec.exp - ttl + sessionRefresh() <= now) {            // idle-sliding extension, throttled
    await storeDo(SESSION_NS, sid, (cur) => {
      if (!cur || now >= (cur.exp || 0)) return [undefined, null];
      return [{ ...cur, exp: now + ttl }, null];
    });
  }
  return rec.subject;
}

// sessionRotate rotates a session's secret (/refresh) -> a new "<id>.<secret>" or undefined. Presenting the
// just-rotated (previous) secret is REUSE -> the session is revoked (theft detection); a secret matching neither
// current nor previous is only rejected.
export async function sessionRotate(token, now) {
  now = (now === undefined || now === null) ? Math.floor(Date.now() / 1000) : Math.floor(now);
  const [sid, secret] = splitToken(token);
  if (sid === null) return undefined;
  const newSecret = randomBytes(32).toString('base64url');
  const out = { token: undefined, reuse: false, subject: undefined };
  await storeDo(SESSION_NS, sid, (cur) => {
    if (!cur || now >= (cur.exp || 0)) return [undefined, null];
    out.subject = cur.subject;
    const sh = sha256Hex(secret);
    if (ctEqualHex(sh, cur.secret_hash || '')) {
      out.token = `${sid}.${newSecret}`;
      return [{ ...cur, prev_hash: cur.secret_hash, prev_at: now, secret_hash: sha256Hex(newSecret),
        gen: (cur.gen || 1) + 1, exp: now + sessionTTL() }, null];
    }
    // benign concurrent/retried /refresh within the grace is rejected but does NOT revoke; a stale reuse after = theft.
    if (cur.prev_hash && ctEqualHex(sh, cur.prev_hash) && now - (cur.prev_at || 0) > sessionReuseGrace()) out.reuse = true;
    return [undefined, null];
  });
  if (out.reuse) {
    await storeDelete(SESSION_NS, sid);
    if (out.subject) await sessionIndexRemove(out.subject, sid);
  }
  return out.token;
}

// sessionRevoke drops a session (logout) by its public id; idempotent; also de-indexes the subject.
export async function sessionRevoke(token) {
  const [sid] = splitToken(token);
  if (sid === null) return;
  const rec = await storeGet(SESSION_NS, sid);
  await storeDelete(SESSION_NS, sid);
  if (rec && rec.subject) await sessionIndexRemove(rec.subject, sid);
}

// sessionRevokeAll drops ALL of a subject's sessions (logout-all / post-password-reset) — O(k) via the index.
export async function sessionRevokeAll(subject) {
  const ids = await storeDo(SESSION_INDEX_NS, subject, (cur) => [[], cur || []]);
  for (const sid of (ids || [])) await storeDelete(SESSION_NS, sid);
}

// sessionTTLSeconds — the active absolute session TTL (auth fills the interop envelope's expires_in/at).
export function sessionTTLSeconds() { return sessionTTL(); }

// the cross-cutting THROTTLE seam: a fixed-window counter pre-auth flows use to bound abuse WITHOUT importing ratelimit. Anti-automation. ×3.
export async function throttle(key, limit, window, now) {
  return storeDo('_throttle', key, (cur) => (cur && now - cur.start < window)
    ? [{ start: cur.start, count: cur.count + 1 }, cur.count + 1 <= limit]
    : [{ start: now, count: 1 }, true]);
}

// requireIdentity: the authenticated subject from the bearer, or null after a 401 — from a real session, never a
// self-parsed header.
export async function requireIdentity(req, res) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) { problem(res, 401, 'not authenticated'); return null; }
  let subject = await sessionResolve(header.slice(7));
  if (subject === undefined) subject = await apiKeyResolve(header.slice(7)); // session miss -> try an api-key bearer (owner identity)
  if (subject === undefined) { problem(res, 401, 'invalid or expired token'); return null; }
  return subject;
}

// revokeCurrent — logout-local: the bearer is read in CORE so a domain never parses the auth header.
export async function revokeCurrent(req) {
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ')) await sessionRevoke(h.slice(7));
}

// ── the cross-cutting ADMIN seam (core owns the NOTION; rbac is the management surface) ──────────────────────
// The role store ('rbac_roles') is a core-recognized cross-cutting namespace, exactly as '_sessions' is: rbac is
// the management SURFACE (assign/revoke roles), core owns the NOTION — so ANY domain gates an admin-only operation
// WITHOUT importing rbac (the boundary rule holds: domains -> core only).
const CORE_TEST_ADMIN = 'root'; // the fixed bootstrap admin recognized ONLY under the test seam (inert in production)

// isAdmin: does `subject` hold the 'admin' role? Bootstrap is OUT-OF-BAND (operator seeds rbac_roles at deploy; no
// claimable env-NAME seed). Auto-admin ONLY under the inert APP_TEST_SESSIONS test seam.
export async function isAdmin(subject) {
  if (process.env.APP_TEST_SESSIONS === '1' && subject === CORE_TEST_ADMIN) return true;
  return ((await storeGet('rbac_roles', subject)) || []).includes('admin');
}

// requireAdmin: the authenticated subject REQUIRED to be an admin, or null after sending 401 (no/invalid identity)
// or 403 (valid identity, not an admin). An admin-only domain calls THIS: authn -> authz BEFORE body validation,
// so a non-admin gets 403 not the body's 422 — identical ×3 with python/go.
export async function requireAdmin(req, res) {
  const subject = await requireIdentity(req, res);
  if (subject === null) return null;
  if (!(await isAdmin(subject))) { problem(res, 403, 'this operation requires the admin role'); return null; }
  return subject;
}

// orgRole (SINGLE-SOURCE): owner DERIVED from orgs_records.owner (read FIRST). The membership row {role,status,...}
// grants its role ONLY when status==='active'; a 'pending' (un-accepted) invite confers NOTHING — closes the member-
// identity escalation. Core-owned (teams authorize vs org membership without importing orgs).
export async function orgRole(org, subject) {
  if ((await storeGet('orgs_records', org))?.owner === subject) return 'owner';
  const m = await storeGet('orgs_members', `${org}\x1f${subject}`);
  return m && m.status === 'active' && m.role !== 'owner' ? m.role : undefined; // a membership row NEVER confers 'owner' (single-source defense-in-depth); pending/absent -> no role
}

// ── the cross-cutting SERVICE seam (a trusted service caller, not a user) ─────────────────────────────────────
// CONSTANT-TIME match of the Bearer token vs env SERVICE_TOKEN (a service secret, identity-exempt). Non-service ->
// one non-enumerable 401. Fixed-length sha256 compare (no length leak), identical ×3 with python/go.
export function requireService(req, res) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const want = process.env.SERVICE_TOKEN || 'service_dev_token_change_me'; // env-backed, rotatable; identity-exempt
  const got = createHash('sha256').update(token).digest();
  const exp = createHash('sha256').update(want).digest();
  if (!timingSafeEqual(got, exp)) { problem(res, 401, 'service authorization required'); return null; }
  return 'service';
}
