// Package chunking — deterministic fixed-window CODE-POINT chunking for retrieval (the rag pipeline). A document is
// split into overlapping windows of `size` code points advancing by the stride `size - overlap`; the windows cover
// [0, len] with no gap, computed over CODE POINTS (go []rune, matching python len/slice + node [...text]) so a
// multibyte or astral document chunks IDENTICALLY in all three languages — the property a UTF-16 .slice would silently
// break. The boundary arithmetic is pure integers (count/start/end scalars proven identical ×3) and the slice is clamped
// (proven identical ×3, no panic); the consumer assembles the span list. Precondition: size >= 1 and 0 <= overlap < size
// — the consumer guards it. Same contract as chunking.py / chunking.js, proven by the shared vectors.
package chunking

// ChunkCount returns the number of chunks the (size, overlap) window produces over text — >= 1 always. Closed form
// over POSITIVE integers, identical ×3.
func ChunkCount(text string, size, overlap int) int {
	length := len([]rune(text)) // CODE POINTS — parity with python len / node [...text]
	if length <= size {
		return 1
	}
	step := size - overlap
	return (length-size+step-1)/step + 1
}

// ChunkStart returns the start offset (code points) of chunk i: i advances by the stride size - overlap.
func ChunkStart(size, overlap, i int) int {
	return i * (size - overlap)
}

// ChunkEnd returns the end offset (code points) of chunk i: start + size, CLAMPED to the document length so the last
// chunk ends exactly at len.
func ChunkEnd(text string, size, overlap, i int) int {
	length := len([]rune(text))
	end := ChunkStart(size, overlap, i) + size
	if end < length {
		return end
	}
	return length
}

// ChunkSlice returns text[start:end] by CODE POINT, start/end CLAMPED to [0, len] (start <= end) so an out-of-range
// span never PANICS (a raw rune-slice would) — keeping the three identical and 5xx-free (the citation-span guard) and
// astral-correct.
func ChunkSlice(text string, start, end int) string {
	runes := []rune(text)
	n := len(runes)
	s := start
	if s < 0 {
		s = 0
	} else if s > n {
		s = n
	}
	e := end
	if e < s {
		e = s
	} else if e > n {
		e = n
	}
	return string(runes[s:e])
}
