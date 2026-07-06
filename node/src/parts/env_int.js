// CENTRAL env_int part — parse an integer from a RAW environment value the SAME way in python/go/node, with a
// default and optional clamp bounds. A config knob must resolve IDENTICALLY x3, but bare int()/Atoi()/parseInt()
// disagree on the edges: parseInt('5x')==5 in node but errors in py/go; AND a value past 2**53-1 diverges (go's
// int64 vs node's float vs python's unbounded int). The caller passes the raw value (process.env[name], possibly
// undefined); this is the PURE parse+clamp. Rule: trim; an absent / empty / non-integer /
// |value|>2**53-1 raw -> the default; THEN clamp by the optional bounds (none · floor · lo,hi). A complete ES module.
const INT = /^[+-]?\d+$/;
const MAX_SAFE = 9007199254740991; // 2**53 - 1 (Number.MAX_SAFE_INTEGER) — the x3-safe magnitude ceiling

// envInt parses raw to an int (def when absent / non-integer / unsafe-magnitude), then clamps by 0, 1 (floor), or 2 (lo, hi) bounds.
export function envInt(raw, def, ...bounds) {
  let v = def;
  const s = raw == null ? '' : String(raw).trim();
  if (INT.test(s)) {
    const n = parseInt(s, 10);
    if (Number.isSafeInteger(n)) v = n;
  }
  if (bounds.length >= 1 && v < bounds[0]) v = bounds[0];
  if (bounds.length >= 2 && v > bounds[1]) v = bounds[1];
  return v;
}
