"""SEARCH INVARIANTS — correctness proofs for this domain's dangerous properties.
Run against the python app (cwd = <app>/python). Credited by EXIT CODE ONLY.

USER-SCOPED: a document belongs to the caller who indexed it, and a query sees ONLY the caller's own corpus.
index + query require the core identity seam; the OWNER is stamped from the authenticated subject at index (never a
body field), and a doc that isn't yours is invisible to your query (the api_keys not-yours==not-found pattern over a
corpus scan). Tokens come from the real session seam (register+login) under APP_TEST_SESSIONS=1, exactly as api_keys
proves its isolation. The retrieval-honesty proofs (I1–I7) run as a single owner (alice); isolation is I0 + I8.

Proves:  I0 deny-by-default — index AND query are 401 without a valid bearer token (no anonymous read of the corpus).
         I1 AND-complete — over a randomized corpus, every document containing ALL query terms appears.
         I2 AND-sound — no returned document is missing any query term (checked against a python oracle).
         I3 token boundary — a substring of a token never matches; punctuation splits tokens.
         I4 case-insensitive — queries and corpus match regardless of case.
         I5 deny-by-default — empty / symbol-only queries return [], never the corpus.
         I6 deterministic ranking — frequency desc then id asc, stable across repeated identical queries.
         I7 replace-on-reindex — after re-indexing an id, its OLD tokens stop matching.
         I8 USER-SCOPED / CROSS-OWNER ISOLATION — alice's query NEVER returns bob's docs and vice-versa: a doc indexed
            by one owner is invisible to the other (whole-token match present but filtered out). The store key is the
            COMPOSITE <owner>\x1f<id>, so two owners indexing the SAME id land in DISTINCT slots — caller B can NOT
            overwrite caller A's id (the cross-owner WRITE wall), and the query only surfaces the row whose owner ==
            caller. The owner-stamp is the TOKEN's: a smuggled `owner` in the index body cannot override it. The stored
            owner is private (never echoed in the index/query body)."""
import os
import random
import re
import sys

os.environ["APP_TEST_SESSIONS"] = "1"   # the `test:` bearer + real register/login resolve only under this seam

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.core import store  # noqa: E402
from app_pkg.app import app  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def toks(text):
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def main():
    random.seed(7)
    words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]
    with TestClient(app, raise_server_exceptions=False) as c:
        def token_for(u):
            c.post("/auth/register", json={"email": u, "password": f"pw-{u}-1234"})
            return c.post("/auth/login", json={"email": u, "password": f"pw-{u}-1234"}).json()["access_token"]

        def H(t):
            return {"Authorization": f"Bearer {t}"}

        ta, tb = token_for("alice"), token_for("bob")

        def index(doc, t=ta):
            return c.post("/search/index", json=doc, headers=H(t))

        def q(term, t=ta):
            return c.get("/search/query", params={"q": term}, headers=H(t)).json()["results"]

        # I0 — deny-by-default: BOTH index and query are 401 without a valid bearer (no anonymous corpus read)
        check("I0a index no token -> 401", c.post("/search/index", json={"id": 1, "text": "x"}).status_code == 401)
        check("I0b query no token -> 401", c.get("/search/query", params={"q": "x"}).status_code == 401)
        check("I0c query empty-q no token -> 401 (auth BEFORE deny-by-default)",
              c.get("/search/query").status_code == 401)
        check("I0d query forged token -> 401",
              c.get("/search/query", params={"q": "x"}, headers={"Authorization": "Bearer deadbeef"}).status_code == 401)
        check("I0e query malformed scheme -> 401",
              c.get("/search/query", params={"q": "x"}, headers={"Authorization": ta}).status_code == 401)

        # randomized corpus of 30 docs (alice's)
        corpus = {}
        for i in range(1, 31):
            text = " ".join(random.choice(words) for _ in range(random.randint(3, 10)))
            corpus[i] = text
            index({"id": i, "text": text})

        # I1 + I2 — completeness and soundness vs the oracle, over 20 random 1-2 term queries
        ok_complete, ok_sound = True, True
        for _ in range(20):
            terms = random.sample(words, random.randint(1, 2))
            got = set(q(" ".join(terms)))
            oracle = {i for i, t in corpus.items() if all(term in toks(t) for term in terms)}
            ok_complete &= oracle <= got
            ok_sound &= got <= oracle
        check("I1 AND-complete (no false negatives across 20 random queries)", ok_complete)
        check("I2 AND-sound (no false positives across 20 random queries)", ok_sound)

        # I3 — token boundary
        index({"id": 100, "text": "quick-thinking, well_formed; end."})
        check("I3a a substring never matches ('qui')", 100 not in q("qui"))
        check("I3b punctuation splits tokens ('thinking' matches)", 100 in q("thinking"))
        check("I3c underscore splits too ('formed' matches)", 100 in q("formed"))

        # I4 — case-insensitive both directions
        index({"id": 101, "text": "MiXeD CaSe ZEBRA"})
        check("I4 case-insensitive (query 'zebra' finds 'ZEBRA', 'MIXED' finds 'MiXeD')",
              101 in q("zebra") and 101 in q("MIXED"))

        # I5 — deny-by-default (authenticated, but no terms)
        check("I5 empty / symbol-only queries return [] (never the corpus)",
              q("") == [] and q("!!! --- ???") == [])

        # I6 — deterministic ranking: build a controlled frequency ladder
        index({"id": 201, "text": "kiwi"})
        index({"id": 202, "text": "kiwi kiwi"})
        index({"id": 203, "text": "kiwi kiwi"})
        first = q("kiwi")
        check("I6a frequency desc, then id asc", first == [202, 203, 201], f"got {first}")
        check("I6b stable across repeated queries", all(q("kiwi") == first for _ in range(3)))

        # I7 — replace-on-reindex: old tokens stop matching
        index({"id": 300, "text": "ephemeral topic"})
        check("I7a indexed and findable", 300 in q("ephemeral"))
        index({"id": 300, "text": "completely different now"})
        check("I7b the OLD token no longer matches after replace", 300 not in q("ephemeral"))
        check("I7c the NEW token matches", 300 in q("different"))

        # I8 — USER-SCOPED / cross-owner isolation: bob's docs are invisible to alice and vice-versa.
        index({"id": 400, "text": "alpha shared secretword"}, t=ta)   # alice's doc, distinct id
        index({"id": 401, "text": "alpha shared bobword"}, t=tb)      # bob's doc, distinct id, SAME 'shared' token
        a_shared = q("shared", t=ta)
        b_shared = q("shared", t=tb)
        check("I8a alice's 'shared' query returns alice's doc, NOT bob's", 400 in a_shared and 401 not in a_shared)
        check("I8b bob's 'shared' query returns bob's doc, NOT alice's", 401 in b_shared and 400 not in b_shared)
        check("I8c alice cannot retrieve bob's exclusive token ('bobword')", q("bobword", t=ta) == [])
        check("I8d bob cannot retrieve alice's exclusive token ('secretword')", q("secretword", t=tb) == [])
        # alice's whole corpus stays hers: none of bob's ids ever leak into alice's broad-term result
        check("I8e none of bob's docs appear in alice's corpus (oracle: 401 never in any alice result)",
              401 not in set(q("alpha", t=ta)) and 401 not in set(q("shared", t=ta)))
        # SAME-ID cross-owner: both index id 500 with DIFFERENT text — the composite key keeps the rows distinct, so
        # neither owner clobbers the other (with a bare id key, bob's write would overwrite alice's row).
        index({"id": 500, "text": "alphaclob uniquea"}, t=ta)
        index({"id": 500, "text": "betaclob uniqueb"}, t=tb)
        check("I8e1 alice's id-500 survived bob's same-id index (no cross-owner clobber)", q("alphaclob", t=ta) == [500])
        check("I8e2 bob's id-500 is his own (the composite key kept the rows distinct)", q("betaclob", t=tb) == [500])
        check("I8e3 alice cannot see bob's id-500 row", q("betaclob", t=ta) == [])

        # the owner-stamp is the TOKEN's: a smuggled body `owner` cannot override it (the stored owner is alice's).
        sm = index({"id": 402, "text": "smuggled owner attempt"}, t=ta)
        if sm.status_code == 201:
            # white-box: read by the record's id FIELD (the key is now the composite <owner>\x1f<id>, not the bare id)
            rec = next((r for r in store.values("search_docs") if r["id"] == 402), None)
            check("I8f stored owner is the authenticated subject", rec is not None and rec.get("owner") == "alice")
            # even if the body carried owner=bob, bob must NOT be able to read it
            c.post("/search/index", json={"id": 403, "text": "spoof body owner", "owner": "bob"}, headers=H(ta))
            spoof = next((r for r in store.values("search_docs") if r["id"] == 403), None)
            check("I8g smuggled body owner ignored (stamp is the token's)", spoof is None or spoof.get("owner") == "alice")
            check("I8h bob cannot read the smuggled-owner doc ('spoof')", q("spoof", t=tb) == [])
        else:
            check("I8f smuggled owner rejected outright", sm.status_code == 422)

        # the owner is PRIVATE — never echoed in the index or query response bodies
        ix = index({"id": 404, "text": "private owner check"}, t=ta)
        check("I8i index response never echoes the owner", "owner" not in ix.json())
        qr = c.get("/search/query", params={"q": "private"}, headers=H(ta)).json()
        check("I8j query response never echoes the owner", "owner" not in qr and qr["results"] == [404])

    print(f"SEARCH INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
