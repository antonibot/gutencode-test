// CENTRAL paginate part — the bounded-page + opaque-cursor pagination every LIST endpoint shares: a STABLE-ordered
// slice of items plus an OPAQUE base64url OFFSET cursor. Same contract as paginate.py / paginate.go, the scalar
// codec identical in all three languages. The cross-language SUBTLETY is the cursor codec — a cursor is accepted
// ONLY if re-encoding its decoded offset reproduces it byte-for-byte (rejects padding / trailing bytes /
// non-canonical base64) AND the offset is within JS's exact-integer range (2^53-1), so all three languages
// accept/reject EVERY cursor identically. The codec is three SCALAR functions (encodeCursor / decodeCursor /
// clampLimit) the vectors prove ×3; paginate is the thin composite that rides on them. A standalone ES module.
const PAGE_DEFAULT = 50;
const PAGE_MAX = 200;
const MAX_OFFSET = Number.MAX_SAFE_INTEGER; // 2^53-1 — cursor-offset ceiling (cross-language exact-integer agreement)

// encodeCursor: the opaque forward cursor for offset n: base64url(String(n)), unpadded. n is always >= 0.
export function encodeCursor(n) {
  return Buffer.from(String(n)).toString('base64url');
}

// decodeCursor: a cursor -> its offset, or -1 if malformed. Accepted ONLY if CANONICAL (re-encoding reproduces it)
// and in [0, MAX_OFFSET] — identical reject set ×3. -1 is the unambiguous reject sentinel (a real offset is >= 0).
export function decodeCursor(cursor) {
  const n = Number(Buffer.from(cursor, 'base64url').toString());
  if (!Number.isInteger(n) || n < 0 || n > MAX_OFFSET || encodeCursor(n) !== cursor) return -1; // canonical + bounded
  return n;
}

// clampLimit: a raw limit string -> the effective page size in [1, PAGE_MAX], or 0 if malformed. Empty ->
// PAGE_DEFAULT. 0 is the unambiguous reject sentinel (a valid limit is always >= 1); a non-canonical / < 1 rejects.
export function clampLimit(raw) {
  if (raw === undefined || raw === null || raw === '') return PAGE_DEFAULT;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > MAX_OFFSET || String(n) !== String(raw)) return 0; // canonical + positive + BOUNDED (×3-uniform)
  return Math.min(n, PAGE_MAX);
}

// paginate -> { items, next, ok }. next is null when there is no next page; ok:false on a malformed cursor/limit.
// The composite riding on the vectored scalar codec — a bounded slice over a STABLE-ordered array.
export function paginate(items, cursor, limit) {
  const lim = clampLimit(limit);
  if (lim === 0) return { items: [], next: null, ok: false };
  let offset = 0;
  if (cursor) {
    const off = decodeCursor(cursor);
    if (off < 0) return { items: [], next: null, ok: false };
    offset = off;
  }
  if (offset > items.length) offset = items.length;
  const end = Math.min(offset + lim, items.length);
  const page = items.slice(offset, end);
  const next = end < items.length ? encodeCursor(end) : null;
  return { items: page, next, ok: true };
}
