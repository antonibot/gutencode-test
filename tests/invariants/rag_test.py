"""RAG INVARIANTS — correctness proofs for this domain's dangerous properties. Run from the app's python tree
(cwd = <app>/python). Credited by EXIT CODE ONLY. Drives the REAL routes (TestClient) and checks them against an
INDEPENDENT in-test oracle (a re-derived chunker + embedder + slice) — never the shipped code path.

Proves:  I-DENY      every mutating route (both POSTs) is 401 without a valid bearer token, and auth runs BEFORE
                     validation (a no-token + otherwise-422 body is 401, not 422 — no shape leak).
         I-SPAN      every query hit's source span is in-bounds: 0 <= start <= end <= len(stored doc text). A
                     fabricated / stale / out-of-range citation is impossible (the falsifiable citation property —
                     python/node slicing would silently truncate it, go would panic).
         I-CITE      every hit's text is EXACTLY the cited window reconstructed from the test's OWN ingested text +
                     the hit's OWN reported span (an independent slice) — a text<->span mismatch is caught.
         I-GROUND    a stored chunk's vector == embed(its cited slice): querying a chunk's exact text self-matches
                     it among the score-1.0 hits, top at 1.0 (retrieval is grounded in the real source).
         I-SHAPE     a hit exposes EXACTLY {chunk_id,text,score,source{doc_id,start,end}} — owner/vector/ordinal
                     never leak.
         I-OWN       cross-owner isolation: B never retrieves A's chunks, and A+B ingesting the SAME doc_id keep
                     DISTINCT records (the composite key — B cannot overwrite A).
         I-COVER     the chunks of a document cover [0, len] with no gap (no source text is silently unretrievable).
         I-DET       repeated identical queries are identical; the order matches the oracle (score desc, id asc).
         I-BOUND     a query returns at most k hits; a document over RAG_MAX_CHUNKS is rejected 422.
         I-REPLACE   re-ingesting a doc_id replaces its chunks — re-ingesting to FEWER chunks leaves NO stale
                     high-ordinal chunk_id and the old text no longer self-matches.
         I-UNICODE   a lone-surrogate document is contained (U+FFFD) before storage — ingest is 201, a query never
                     5xxs, and the echoed hit text carries no raw lone surrogate."""
import math
import os
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # the test-session seam: `test:<subject>` resolves to <subject> (inert in prod)
# a SMALL window so short documents are genuinely MULTI-chunk (the real pipeline is exercised); MAX small so the
# over-limit probe is cheap. The app reads these at import; the oracle below uses the same numbers.
os.environ["RAG_CHUNK_SIZE"] = "20"
os.environ["RAG_CHUNK_OVERLAP"] = "5"
os.environ["RAG_MAX_CHUNKS"] = "50"

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

SIZE, OVERLAP, MAXC = 20, 5, 50
failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


# ----- the INDEPENDENT oracle (re-derived in the test, NOT imported from the shipped part) -----
def _wf(text):   # lone surrogate -> U+FFFD: what the handler stores, so the test knows the stored text
    return "".join("�" if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in text)


def _embed(text):
    v = [0] * 8
    for ch in text.lower():
        v[ord(ch) % 8] += 1
    return v


def _cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


def _spans(text):   # the independent chunker: code-point windows, stride SIZE-OVERLAP, stop once a window ends at len
    n = len(text)
    step = SIZE - OVERLAP
    spans, i = [], 0
    while True:
        s = i * step
        e = min(s + SIZE, n)
        spans.append((s, e))
        if e >= n:
            return spans
        i += 1


def main():
    with TestClient(app, raise_server_exceptions=False) as c:
        def H(sub):   # the per-subject auth header; H("alice")/H("bob") are the distinct identities the proof exercises
            return {"Authorization": f"Bearer test:{sub}"}

        def ingest(sub, doc_id, text):
            return c.post("/rag/documents", json={"doc_id": doc_id, "text": text}, headers=H(sub))

        def query(sub, q, k=None):
            body = {"query": q} if k is None else {"query": q, "k": k}
            return c.post("/rag/query", json=body, headers=H(sub)).json()

        # I-DENY — deny-by-default + auth BEFORE validation
        check("I-DENY a ingest no token -> 401",
              c.post("/rag/documents", json={"doc_id": "x", "text": "x"}).status_code == 401)
        check("I-DENY b query no token -> 401",
              c.post("/rag/query", json={"query": "x"}).status_code == 401)
        check("I-DENY c ingest forged token -> 401",
              c.post("/rag/documents", json={"doc_id": "x", "text": "x"},
                     headers={"Authorization": "Bearer nope"}).status_code == 401)
        check("I-DENY d query forged token -> 401",
              c.post("/rag/query", json={"query": "x"}, headers={"Authorization": "Bearer nope"}).status_code == 401)
        check("I-DENY e no-token + invalid body -> 401 (auth before validation, no shape leak)",
              c.post("/rag/documents", json={"doc_id": "", "text": ""}).status_code == 401)

        # alice's corpus — varied ASCII docs (multi-chunk under the 20/5 window) + one astral/mixed doc
        docs = {
            "story": "the quick brown fox jumps over the lazy dog near the river bank at dawn",
            "tech": "deterministic chunking embeds each window then ranks by cosine similarity score",
            "mix": "café ☕ data 😀 résumé 日本語 tokens 𝔘𝔫𝔦𝔠𝔬𝔡𝔢 spans here",
        }
        stored = {}
        for doc_id, text in docs.items():
            r = ingest("alice", doc_id, text)
            check(f"ingest {doc_id} -> 201", r.status_code == 201, f"got {r.status_code}")
            stored[doc_id] = _wf(text)

        # a broad query that surfaces every chunk of alice's corpus (k large, small corpus)
        broad = query("alice", "the data tokens here", k=50)
        allhits = broad["hits"]
        check("alice sees her corpus (hits returned)", len(allhits) > 0)

        # I-SPAN — every hit's span is in-bounds for its CURRENT stored document
        span_ok = all(0 <= h["source"]["start"] <= h["source"]["end"] <= len(stored[h["source"]["doc_id"]])
                      for h in allhits)
        check("I-SPAN every hit source span is in-bounds 0<=start<=end<=len", span_ok)

        # I-CITE — every hit's text == the cited window of the test's OWN ingested text (independent slice)
        cite_ok = True
        for h in allhits:
            src = h["source"]
            if h["text"] != stored[src["doc_id"]][src["start"]:src["end"]]:
                cite_ok = False
        check("I-CITE every hit text == the independently-reconstructed cited slice", cite_ok)

        # I-SHAPE — a hit exposes exactly the public keys; owner/vector/ordinal never leak
        shape_ok = all(set(h) == {"chunk_id", "text", "score", "source"}
                       and set(h["source"]) == {"doc_id", "start", "end"} for h in allhits)
        check("I-SHAPE hit keys == {chunk_id,text,score,source{doc_id,start,end}} (no owner/vector/ordinal leak)",
              shape_ok)

        # I-GROUND — query a chunk's EXACT text; its chunk_id is among the score-1.0 hits and top is 1.0
        ground_ok = True
        for doc_id in ("story", "tech"):
            spans = _spans(stored[doc_id])
            for j, (s, e) in enumerate(spans):
                r = query("alice", stored[doc_id][s:e], k=50)
                perfect = [h["chunk_id"] for h in r["hits"] if h["score"] >= 1.0 - 1e-12]
                if f"{doc_id}#{j}" not in perfect or abs(r["hits"][0]["score"] - 1.0) > 1e-12:
                    ground_ok = False
        check("I-GROUND each chunk's exact text self-matches among the 1.0 hits (vector == embed(cited slice))",
              ground_ok)

        # I-COVER — a fresh single-doc corpus so all hits are that doc's chunks; they cover [0, len], no gap
        cov_text = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo"
        ingest("cover", "c1", cov_text)
        cov = query("cover", "alpha echo kilo", k=50)["hits"]
        spans = sorted((h["source"]["start"], h["source"]["end"]) for h in cov)
        gapless = spans[0][0] == 0 and spans[-1][1] == len(cov_text) and all(
            spans[i + 1][0] <= spans[i][1] for i in range(len(spans) - 1))
        check("I-COVER the chunks cover [0,len] with no gap (start0=0, last end=len, consecutive overlap)", gapless)

        # I-DET — repeated identical queries are byte-identical; the order matches the oracle
        q1 = query("alice", "the quick data tokens", k=50)
        q2 = query("alice", "the quick data tokens", k=50)
        check("I-DET repeated identical queries are identical", q1 == q2)
        got = [(h["chunk_id"], round(h["score"], 12)) for h in q1["hits"]]
        qv = _embed(_wf("the quick data tokens"))
        oracle = []
        for doc_id in ("story", "tech", "mix"):
            for j, (s, e) in enumerate(_spans(stored[doc_id])):
                oracle.append((f"{doc_id}#{j}", round(_cosine(qv, _embed(stored[doc_id][s:e])), 12)))
        oracle.sort(key=lambda x: (-x[1], x[0]))
        check("I-DET the order matches the oracle (score desc, chunk_id asc)", got == oracle,
              f"first diff {[x for x in zip(got, oracle) if x[0] != x[1]][:1]}")

        # I-BOUND — k clamps; a document over RAG_MAX_CHUNKS is rejected
        check("I-BOUND at most k hits", len(query("alice", "the data", k=2)["hits"]) == 2)
        over = ingest("bound", "big", "a" * 800)   # 800 cp / step 15 -> ~53 chunks > 50
        check("I-BOUND a document over RAG_MAX_CHUNKS -> 422", over.status_code == 422, f"got {over.status_code}")
        under = ingest("bound", "ok", "a" * 100)
        check("I-BOUND a document under the limit -> 201", under.status_code == 201)

        # I-REPLACE — re-ingest to FEWER chunks: no stale high-ordinal chunk_id, the old text no longer self-matches
        long_text = "alpha bravo charlie delta echo foxtrot golf hotel india juliet"
        ingest("replace", "r1", long_text)
        n_long = query("replace", long_text, k=50)
        check("I-REPLACE the long doc is multi-chunk", len({h["chunk_id"] for h in n_long["hits"]}) > 1)
        ingest("replace", "r1", "zulu")   # now 1 chunk
        after = query("replace", long_text, k=50)
        ids = {h["chunk_id"] for h in after["hits"]}
        check("I-REPLACE no stale high-ordinal chunk_id survives the shrink", ids <= {"r1#0"}, f"ids={ids}")
        perfect = [h["chunk_id"] for h in after["hits"] if h["score"] >= 1.0 - 1e-12]
        check("I-REPLACE the old text no longer self-matches the re-ingested id", "r1#0" not in perfect)

        # I-OWN — cross-owner isolation + the composite-key WRITE wall. Two DISTINCT identities H("alice") + H("bob")
        # both ingest doc_id "shared" with DIFFERENT single-chunk text. Each self-matches ONLY their own; neither owner
        # can clobber or read the other (the composite <owner>\x1f<doc_id> key + the owner-FIELD scan filter).
        c.post("/rag/documents", json={"doc_id": "shared", "text": "alice secret"}, headers=H("alice"))
        c.post("/rag/documents", json={"doc_id": "shared", "text": "bob notes"}, headers=H("bob"))
        ra = c.post("/rag/query", json={"query": "alice secret", "k": 50}, headers=H("alice")).json()
        rb = c.post("/rag/query", json={"query": "alice secret", "k": 50}, headers=H("bob")).json()  # bob queries alice's EXACT text
        check("I-OWN a alice's own shared#0 self-matches her text (her record is intact)",
              any(h["chunk_id"] == "shared#0" and h["score"] >= 1.0 - 1e-12 for h in ra["hits"]))
        check("I-OWN b bob never retrieves alice's content (same doc_id, cross-owner — the corpus-leak wall)",
              all("secret" not in h["text"] and "alice" not in h["text"] for h in rb["hits"]))
        rb2 = c.post("/rag/query", json={"query": "bob notes", "k": 50}, headers=H("bob")).json()
        check("I-OWN c bob's own shared#0 self-matches (the composite key kept the two records distinct — no clobber)",
              any(h["chunk_id"] == "shared#0" and h["score"] >= 1.0 - 1e-12 for h in rb2["hits"]))

        # I-UNICODE — a lone surrogate is contained before storage; ingest 201, query never 5xxs, no raw surrogate
        # echoed. The surrogate is sent as a RAW json \u escape (httpx cannot UTF-8-encode a lone surrogate via json=);
        # the server's json parser decodes it to a lone surrogate, which the handler contains to U+FFFD.
        raw_sur = '{"doc_id": "u1", "text": "x\\ud800y needle payload here"}'
        ru = c.post("/rag/documents", content=raw_sur, headers={**H("uni"), "content-type": "application/json"})
        check("I-UNICODE a lone-surrogate ingest is contained -> 201", ru.status_code == 201, f"got {ru.status_code}")
        qu = c.post("/rag/query", json={"query": "needle payload here"}, headers=H("uni"))
        check("I-UNICODE b a query over the contained doc never 5xxs", qu.status_code == 200, f"got {qu.status_code}")
        echoed = "".join(h["text"] for h in qu.json()["hits"])
        check("I-UNICODE c no raw lone surrogate is ever echoed (U+FFFD substituted)",
              all(not 0xD800 <= ord(ch) <= 0xDFFF for ch in echoed))

    print(f"RAG INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
