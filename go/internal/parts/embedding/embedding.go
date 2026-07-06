// Package embedding — the deterministic OFFLINE embedder + cosine the retrieval domains (vectorstore, rag) share.
// Embed(text) is an 8-bucket CODE-POINT histogram of the lowercased text (pure integer counts -> bit-identical ×3); it
// is the test oracle, and a real embedder / vector DB swaps in behind the same call. EmbedBucket(text, i) is
// Embed(text)[i] — the per-bucket SCALAR the conformance vectors pin ×3 (a []int return is not comparable with !=, so
// the scalar carries the proof). Cosine is a FLOAT and rides on the consumers' grounding invariant, not a vector. Same
// contract as embedding.py / embedding.js, proven by the shared vectors.
package embedding

import (
	"math"
	"strings"
)

const embeddingDims = 8

// Embed returns the 8-bucket code-point histogram of the lowercased text (pure integer counts -> identical ×3).
func Embed(text string) []int {
	vector := make([]int, embeddingDims)
	for _, ch := range strings.ToLower(text) { // range = CODE POINTS — parity with python ord / node codePointAt
		vector[int(ch)%embeddingDims]++
	}
	return vector
}

// EmbedBucket returns Embed(text)[i] — the per-bucket scalar the vectors pin ×3 (a slice return is not !=-comparable).
func EmbedBucket(text string, i int) int {
	return Embed(text)[i]
}

// Cosine returns the cosine similarity of two integer vectors; 0 if either is the zero vector. A float — NOT
// vector-pinned (float formatting differs ×3); proven by the consumers' grounding invariant.
func Cosine(a, b []int) float64 {
	dot, na, nb := 0, 0, 0
	for i := range a {
		dot += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return float64(dot) / (math.Sqrt(float64(na)) * math.Sqrt(float64(nb)))
}
