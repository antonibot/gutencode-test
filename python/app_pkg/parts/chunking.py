"""CENTRAL chunking part — deterministic fixed-window CODE-POINT chunking for retrieval (the rag pipeline). A
document is split into overlapping windows of `size` code points advancing by the stride `size - overlap`; the
windows cover [0, len] with no gap, and the boundaries + the slice are computed over CODE POINTS (python len/slice,
go []rune, node [...text]) so a multibyte or astral document chunks IDENTICALLY in all three languages — the property
a UTF-16 .slice would silently break. The boundary arithmetic is pure integers (the count/start/end scalars are
proven identical ×3) and the slice is clamped (proven identical ×3, no 5xx); the span LIST is assembled by the consumer (a
[][2]int return is not Go-!=-comparable, so a scalar surface carries the proof). Precondition: size >= 1 and
0 <= overlap < size — the consumer guards it at config load. Same contract as chunking.go / chunking.js, proven by
the shared vector suite."""


def _cplen(text: str) -> int:
    return len(text)  # python len() counts CODE POINTS — parity with go []rune / node [...text]


def chunk_count(text, size, overlap):
    """The number of chunks the (size, overlap) window produces over text — >= 1 always (an empty/short doc is one
    chunk). Closed form over POSITIVE integers so the division is identical ×3 (no language-specific rounding edge)."""
    length = _cplen(text)
    if length <= size:
        return 1
    step = size - overlap
    return (length - size + step - 1) // step + 1


def chunk_start(size, overlap, i):
    """The start offset (code points) of chunk i: i advances by the stride size - overlap. Pure integer arithmetic."""
    return i * (size - overlap)


def chunk_end(text, size, overlap, i):
    """The end offset (code points) of chunk i: start + size, CLAMPED to the document length so the last chunk ends
    exactly at len (the windows cover [0, len])."""
    length = _cplen(text)
    end = chunk_start(size, overlap, i) + size
    return end if end < length else length


def chunk_slice(text, start, end):
    """text[start:end] by CODE POINT, with start/end CLAMPED to [0, len] (start <= end) so an out-of-range span can
    never raise — python/node slicing already clamps, but go []rune slicing would PANIC, so the clamp is what keeps the
    three identical AND 5xx-free (the citation-span guard). Slicing the code points (not UTF-16 units) is what makes an
    astral document slice identically ×3."""
    n = _cplen(text)
    s = 0 if start < 0 else (n if start > n else start)
    e = s if end < s else (n if end > n else end)
    return text[s:e]
