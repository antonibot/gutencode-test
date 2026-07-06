// CENTRAL signing part: two schemes share ONE hmac primitive (hmacSha256 — the no-drift seam, the ONLY createHmac
// in the app). Same contract as signing.py / signing.go; the three sign byte-identically.
// A complete, standalone ES module.
import { createHmac, timingSafeEqual } from 'node:crypto';

function hmacSha256(secret, message) {
  return createHmac('sha256', secret).update(message).digest();
}

// signV1 = 'v1,' + base64(HMAC(secret, `{id}.{timestamp}.{payload}`)) — the Standard Webhooks shape.
export function signV1(secret, id, timestamp, payload) {
  return 'v1,' + hmacSha256(secret, `${id}.${timestamp}.${payload}`).toString('base64');
}

const MAX_CANDIDATES = 32; // cap the v1 candidates a caller may submit on the PUBLIC /verify (bound the compare work — a DoS guard)

// verifyV1 verifies against ONE secret, accepting a SPACE-delimited MULTI-signature 'v1,<b64> v1,<b64> ...' (a sender
// signs with every active secret during a rotation; accept if THIS secret matches ANY candidate). The multi-SECRET loop
// is the CALLER's. A '.' in id is rejected (the '{id}.{ts}.{payload}' delimiter — signature-confusion); a stale ts
// before any crypto; malformed / foreign-scheme candidates SKIPPED; the count CAPPED; each compare constant-time.
export function verifyV1(secret, id, timestamp, payload, sigHeader, now, tolerance) {
  if (String(id).includes('.')) return false; // the '.'-join delimiter -> a dotted id is signature-confusion
  if (timestamp <= 0) return false; // non-positive ts -> reject (parity with py/go; closes the int64 abs-overflow window)
  if (Math.abs(now - timestamp) > tolerance) return false;
  const expected = Buffer.from(signV1(secret, id, timestamp, payload));
  let seen = 0;
  for (const piece of (sigHeader || '').split(' ')) {
    if (!piece.startsWith('v1,')) continue; // SKIP malformed / foreign-scheme (never sink a valid sibling)
    const given = Buffer.from(piece);
    if (expected.length === given.length && timingSafeEqual(expected, given)) return true; // constant-time per candidate
    seen += 1;
    if (seen >= MAX_CANDIDATES) break; // CAP — bound the work a caller can force (DoS guard)
  }
  return false;
}

// stripeSign = hex(HMAC(secret, `{timestamp}.{payload}`)) — the Stripe 'v1=' value (signed payload = ts.body).
export function stripeSign(secret, timestamp, payload) {
  return hmacSha256(secret, `${timestamp}.${payload}`).toString('hex');
}

// stripeVerify parses a 'Stripe-Signature: t=<ts>,v1=<hex>' header and constant-time checks it within the window.
export function stripeVerify(secret, header, payload, now, tolerance) {
  let timestamp = 0;
  const v1s = [];
  for (const piece of (header || '').split(',')) {
    const i = piece.indexOf('=');
    if (i < 0) continue;
    const k = piece.slice(0, i).trim();
    const v = piece.slice(i + 1).trim(); // strip BOTH sides so 't= 1000 ' / 'v1 = <hex>' parse IDENTICALLY ×3
    if (k === 't') timestamp = parseInt(v, 10) || 0;
    else if (k === 'v1') v1s.push(v); // collect ALL v1 (secret rotation sends several)
  }
  if (timestamp <= 0 || Math.abs(now - timestamp) > tolerance) return false; // non-positive ts / stale -> reject
  const expected = Buffer.from(stripeSign(secret, timestamp, payload));
  return v1s.some((v1) => { // constant-time per candidate; accept if ANY matches
    const given = Buffer.from(v1);
    return expected.length === given.length && timingSafeEqual(expected, given);
  });
}
