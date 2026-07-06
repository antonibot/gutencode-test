"""CENTRAL embedding part — the deterministic OFFLINE embedder + cosine the retrieval domains (vectorstore, rag)
share. embed(text) is an 8-bucket CODE-POINT histogram of the lowercased text (pure integer counts, so the vector —
and therefore every cosine — is bit-identical in all three languages); it is the test ORACLE, and a real embedder /
vector DB swaps in behind the same call. embed_bucket(text, i) = embed(text)[i] is the per-bucket SCALAR the
conformance vectors pin ×3 (a [int] list return is not Go-!=-comparable, so the scalar carries the proof — probing
every bucket proves the whole vector). cosine is a FLOAT and rides on the consumers' grounding invariant (an
exact-text query self-matches at 1.0), not a vector — exactly as well_formed's make_well_formed is consumer-proven.
Same contract as embedding.go / embedding.js, proven by the shared vector suite."""
import math

_DIMS = 8


def embed(text):
    """The deterministic offline embedding: an 8-bucket code-point histogram of the lowercased text. Pure integer
    counts -> bit-identical ×3 (python ord, go rune, node codePointAt over the SAME lowercased code points)."""
    vector = [0] * _DIMS
    for ch in text.lower():
        vector[ord(ch) % _DIMS] += 1
    return vector


def embed_bucket(text, i):
    """embed(text)[i] — the per-bucket scalar the vectors pin ×3 (a [int] return is not comparable with Go's !=, so
    the scalar bucket is the conformance-provable surface; probing every bucket proves the whole vector)."""
    return embed(text)[i]


def cosine(a, b):
    """Cosine similarity of two integer vectors; 0.0 if either is the zero vector. A float — NOT vector-pinned (float
    formatting differs ×3); proven by the consumers' grounding invariant (an exact-text self-match == 1.0)."""
    dot = sum(x * y for x, y in zip(a, b))
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na > 0 and nb > 0 else 0.0
