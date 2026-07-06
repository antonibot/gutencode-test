"""VECTORSTORE INVARIANTS — correctness proofs for this domain's dangerous properties. Run against the BUILT
python app (cwd = <app>/python). Credited by EXIT CODE ONLY.

Proves:  I1 GROUNDING — over a randomized corpus, an exact-text query ALWAYS self-matches as the top hit with
            score 1.0 (the nearest stored document wins; retrieval cannot drift).
         I2 ordering — hits sort score desc, ties by id asc; the ordering matches an independent oracle.
         I3 the k bound — a query returns at most k hits, k=1 returns exactly the top.
         I4 determinism — the same query returns the identical hit list, repeatedly.
         I5 replace-on-reindex — after re-indexing an id, the OLD text no longer self-matches to it.
         I6 strict input.
         I7 deny-by-default — every mutating route (both POSTs) is 401 without a valid bearer token (the core identity seam).
         I8 cross-owner isolation (read-scoping) — a document is USER-SCOPED: alice's query NEVER returns bob's
            docs and bob's query NEVER returns alice's docs (two subjects via the auth seam), even for a query whose
            EXACT text another owner indexed (score 1.0); the owner field never leaks into the hit shape."""
import math
import os
import random
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # enable the core test-session seam: `test:<subject>` resolves to <subject>

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.app import app  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def embed(text):
    v = [0] * 8
    for ch in text.lower():
        v[ord(ch) % 8] += 1
    return v


def cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


def main():
    random.seed(11)
    words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf"]
    # every mutating route needs a token. Pass `test:alice` explicitly on each authed call (rather than a
    # client default) so the no-token I7 probes below can truly omit the Authorization header — httpx MERGES a
    # client-default header over per-request headers, so a default can't be "unset" to test the anonymous path.
    H = {"Authorization": "Bearer test:alice"}   # the authenticated caller; resolves under APP_TEST_SESSIONS=1
    with TestClient(app, raise_server_exceptions=False) as c:
        def q(query, k=None):
            body = {"query": query} if k is None else {"query": query, "k": k}
            return c.post("/vectors/query", json=body, headers=H).json()

        # I7 — deny-by-default: a mutating route is 401 without a valid bearer token (no / forged token).
        check("I7a index no token -> 401",
              c.post("/vectors", json={"id": "x", "text": "x"}).status_code == 401)
        check("I7b query no token -> 401",
              c.post("/vectors/query", json={"query": "x"}).status_code == 401)
        check("I7c index forged token -> 401",
              c.post("/vectors", json={"id": "x", "text": "x"},
                     headers={"Authorization": "Bearer nosuchtoken"}).status_code == 401)
        check("I7d query forged token -> 401",
              c.post("/vectors/query", json={"query": "x"},
                     headers={"Authorization": "Bearer nosuchtoken"}).status_code == 401)
        # auth runs BEFORE validation: a no-token request with an otherwise-422 body is 401, not 422 (×3)
        check("I7e no-token + invalid body -> 401 (auth before validation)",
              c.post("/vectors/query", json={"query": ""}).status_code == 401)

        corpus = {}
        for i in range(1, 26):
            text = " ".join(random.choice(words) for _ in range(random.randint(2, 8)))
            corpus[f"doc{i:02d}"] = text
            c.post("/vectors", json={"id": f"doc{i:02d}", "text": text}, headers=H)

        # I1 — grounding: 10 random exact-text queries must self-match at the top with score 1.0
        grounded = True
        for doc_id in random.sample(sorted(corpus), 10):
            r = q(corpus[doc_id], k=50)
            top = r["hits"][0]
            # ties at score 1.0 can only be DUPLICATE texts; the self id must be among the 1.0 hits
            perfect = [h["id"] for h in r["hits"] if h["score"] >= 1.0 - 1e-12]
            grounded &= doc_id in perfect and abs(top["score"] - 1.0) < 1e-12
        check("I1 exact-text queries self-match at the top with score 1.0 (10 random probes)", grounded)

        # I2 — ordering vs an independent oracle
        r = q("alpha bravo charlie", k=50)
        got = [(h["id"], round(h["score"], 12)) for h in r["hits"]]
        qv = embed("alpha bravo charlie")
        oracle = sorted(((i, round(cosine(qv, embed(t)), 12)) for i, t in corpus.items()),
                        key=lambda x: (-x[1], x[0]))
        check("I2 the ordering matches the oracle (score desc, id asc)", got == oracle,
              f"first diff at {[x for x in zip(got, oracle) if x[0] != x[1]][:1]}")

        # I3 — the k bound
        check("I3a at most k hits", len(q("alpha", k=5)["hits"]) == 5)
        one = q(corpus["doc01"], k=1)
        check("I3b k=1 returns exactly the top", len(one["hits"]) == 1 and one["top"] == one["hits"][0]["id"])

        # I4 — determinism
        check("I4 identical queries are identical", all(q("alpha bravo", k=10) == q("alpha bravo", k=10)
                                                        for _ in range(3)))

        # I5 — replace-on-reindex
        c.post("/vectors", json={"id": "doc01", "text": "zzz qqq jjj xxx"}, headers=H)
        r = q(corpus["doc01"], k=50)
        perfect = [h["id"] for h in r["hits"] if h["score"] >= 1.0 - 1e-12]
        check("I5 the old text no longer self-matches to the re-indexed id", "doc01" not in perfect)

        # I6 — strict input (authenticated, so validation is actually reached: 422 not 401)
        for bad in ({}, {"query": ""}, {"query": 7}, {"query": "x", "k": 0}, {"query": "x", "k": "many"},
                    {"query": "x", "k": 51}):
            check(f"I6 invalid query body {bad!r} -> 422",
                  c.post("/vectors/query", json=bad, headers=H).status_code == 422)

        # I8 — cross-owner isolation (read-scoping): a document is USER-SCOPED to its indexer. The whole corpus
        # above belongs to alice (H). Introduce a SECOND subject, bob, via the auth seam and prove neither owner can
        # ever retrieve the other's docs — not even by querying the EXACT text the other indexed (a score-1.0 match
        # that, unscoped, would top the results). The owner is stamped from the token, never client-set.
        HB = {"Authorization": "Bearer test:bob"}   # a DISTINCT authenticated caller (resolves under the test seam)

        def q_as(headers, query, k=50):
            return c.post("/vectors/query", json={"query": query, "k": k}, headers=headers).json()

        alice_secret_text = corpus["doc02"]   # an exact alice document (alice owns it; bob must never see it)
        # bob has indexed NOTHING yet: querying alice's exact text returns an EMPTY result, not alice's doc
        rb = q_as(HB, alice_secret_text)
        check("I8a bob's query over an empty-for-bob corpus returns no hits (alice's docs are invisible)",
              rb["hits"] == [] and rb["top"] is None)

        # bob indexes his OWN doc, then re-queries alice's exact text: his only hit is his own doc, never alice's —
        # even though alice's doc is a perfect (1.0) match for that text. This is the leak the scoping closes.
        c.post("/vectors", json={"id": "bobdoc", "text": "bob private vector payload"}, headers=HB)
        rb2 = q_as(HB, alice_secret_text)
        bob_ids = {h["id"] for h in rb2["hits"]}
        alice_ids = set(corpus)
        check("I8b bob's hits never include ANY of alice's doc ids (cross-owner read denied)",
              bob_ids.isdisjoint(alice_ids) and bob_ids <= {"bobdoc"})
        check("I8c bob querying alice's EXACT text does NOT surface alice's perfect match",
              all(h["id"] != "doc02" for h in rb2["hits"]))

        # symmetric: alice querying bob's exact text never returns bob's doc; alice still sees her own corpus
        ra = q_as(H, "bob private vector payload")
        check("I8d alice's hits never include bob's doc (isolation is symmetric)",
              all(h["id"] != "bobdoc" for h in ra["hits"]))
        ra_self = q_as(H, corpus["doc03"])
        check("I8e alice still retrieves her OWN docs after bob indexed (her view is unpolluted)",
              "doc03" in {h["id"] for h in ra_self["hits"]})

        # the owner field stays INTERNAL: it never appears in the hit shape (only id/text/score)
        check("I8f the owner field never leaks into the hit shape",
              all(set(h) == {"id", "text", "score"} for h in (rb2["hits"] + ra["hits"] + ra_self["hits"])))

    print(f"VECTORSTORE INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
