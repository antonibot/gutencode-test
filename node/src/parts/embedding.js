// CENTRAL embedding part — the deterministic OFFLINE embedder + cosine the retrieval domains (vectorstore, rag) share.
// embed(text) is an 8-bucket CODE-POINT histogram of the lowercased text (pure integer counts -> bit-identical ×3); it
// is the test oracle, and a real embedder / vector DB swaps in behind the same call. embedBucket(text, i) is
// embed(text)[i] — the per-bucket SCALAR the conformance vectors pin ×3 (a list return is not Go-!=-comparable, so the
// scalar carries the proof). cosine is a FLOAT and rides on the consumers' grounding invariant, not a vector. Same
// contract as embedding.py / embedding.go, proven by the vector suite. A complete, standalone ES module.
const DIMS = 8;

// embed returns the 8-bucket code-point histogram of the lowercased text (pure integer counts -> identical ×3).
export function embed(text) {
  const vector = new Array(DIMS).fill(0);
  for (const ch of text.toLowerCase()) vector[ch.codePointAt(0) % DIMS]++; // for..of = CODE POINTS — parity ×3
  return vector;
}

// embedBucket returns embed(text)[i] — the per-bucket scalar the vectors pin ×3 (a list return is not !=-comparable).
export function embedBucket(text, i) {
  return embed(text)[i];
}

// cosine returns the cosine similarity of two integer vectors; 0 if either is the zero vector. A float — NOT
// vector-pinned (float formatting differs ×3); proven by the consumers' grounding invariant.
export function cosine(a, b) {
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}
