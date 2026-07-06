// CENTRAL chunking part — deterministic fixed-window CODE-POINT chunking for retrieval (the rag pipeline). A document
// is split into overlapping windows of `size` code points advancing by the stride `size - overlap`; the windows cover
// [0, len] with no gap, computed over CODE POINTS ([...text], NOT UTF-16 .length/.slice) so a multibyte or astral
// document chunks IDENTICALLY to python (len) / go ([]rune) in all three languages — the property a UTF-16 .slice would
// silently break. The boundary arithmetic is pure integers (count/start/end scalars proven identical ×3) and the slice is
// clamped (proven identical ×3, no throw); the consumer assembles the span list. Precondition: size >= 1 and
// 0 <= overlap < size — the consumer guards it. Same contract as chunking.py / chunking.go, proven by the vector suite.
// A complete, standalone ES module.

// chunkCount returns the number of chunks the (size, overlap) window produces over text — >= 1 always. Closed form
// over POSITIVE integers, identical ×3.
export function chunkCount(text, size, overlap) {
  const length = [...text].length; // CODE POINTS — parity with python len / go []rune
  if (length <= size) return 1;
  const step = size - overlap;
  return Math.floor((length - size + step - 1) / step) + 1;
}

// chunkStart returns the start offset (code points) of chunk i: i advances by the stride size - overlap.
export function chunkStart(size, overlap, i) {
  return i * (size - overlap);
}

// chunkEnd returns the end offset (code points) of chunk i: start + size, CLAMPED to the document length so the last
// chunk ends exactly at len.
export function chunkEnd(text, size, overlap, i) {
  const length = [...text].length;
  const end = chunkStart(size, overlap, i) + size;
  return end < length ? end : length;
}

// chunkSlice returns text[start:end] by CODE POINT (the spread, NOT UTF-16 .slice), start/end CLAMPED to [0, len]
// (start <= end) so an out-of-range span never throws — keeping the three identical and 5xx-free (the citation-span
// guard) and astral-correct.
export function chunkSlice(text, start, end) {
  const cps = [...text];
  const n = cps.length;
  const s = start < 0 ? 0 : start > n ? n : start;
  const e = end < s ? s : end > n ? n : end;
  return cps.slice(s, e).join('');
}
