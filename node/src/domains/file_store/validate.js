// Byte/name validators for file_store — IDENTICAL in python/go/node. The canonical-round-trip base64 rule, the
// RFC-2045 content_type token allowlist (CR/LF structurally impossible), and the object-key grammar (contained x3,
// no path chars, <=1024 utf-8 bytes).
import { isWellFormed, makeWellFormed } from '../../parts/well_formed.js';

const B64 = /^[A-Za-z0-9+/]*={0,2}$/;
const CT = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/;
const MAX_KEY_BYTES = 1024; // the S3 key limit (utf-8 bytes) — tighter than well_formed's 1024 CODE POINTS

// normKey CONTAINS a lone surrogate (-> U+FFFD, aligning with go's decoder x3) then applies the grammar; null on reject.
export function normKey(raw) {
  const key = makeWellFormed(raw);
  if (!isWellFormed(key) || Buffer.byteLength(key, 'utf8') > MAX_KEY_BYTES
      || key.includes('/') || key.includes('\\') || key === '.' || key === '..') {
    return null;
  }
  return key;
}

// decodeB64 — the x3-identical canonical-round-trip rule (node Buffer.from(base64) accepts anything, so the
// round-trip is the real gate: re-encoding must reproduce the input). Returns a Buffer or null.
export function decodeB64(s) {
  if (!B64.test(s) || s.length % 4 !== 0) return null;
  const raw = Buffer.from(s, 'base64');
  if (raw.toString('base64') !== s) return null;
  return raw;
}

// cleanContentType — a strict RFC-2045 token/token allowlist (the stored type is reflected on download, so CR/LF/
// controls must be structurally impossible). undefined/null -> the octet-stream default. Returns the ct or null.
export function cleanContentType(raw) {
  const ct = raw === undefined || raw === null ? 'application/octet-stream' : raw;
  if (typeof ct !== 'string' || !CT.test(ct)) return null;
  return ct;
}
