"""PROMPT_REGISTRY INVARIANTS — correctness proofs for this domain's dangerous property: PIN-HONESTY (when a
consumer asks for (version | label) it gets EXACTLY the bytes pinned, and a named label does NOT move on its own).
Run against the python app (cwd = <app>/python; DATABASE_PATH set by the harness). Credited by EXIT CODE ONLY.
Every check uses a REACHING input — delete the defense in your head and the check goes RED (rule 9).

Proves:  I-IMMUTABLE     a published version's (template, content_hash) is frozen; creating v2 never mutates v1.
         I-PIN-HONEST    content_hash == an INDEPENDENT sha256 over the contained template; a smuggled content_hash
                         is discarded (white-box: the stored row carries the real hash).
         I-LABEL-NO-DRIFT (the HEADLINE) a label set to v1 still resolves to v1 after v2,v3 are published — it does
                         NOT silently follow the newest version; rollback gives the old version's EXACT content;
                         one-to-one (a move strips the old); a missing-version target is 422; an unset label is 404.
         I-RENDER-SAFE   single-pass (a substituted value is not re-scanned -> a data value can't inject a 2nd var);
                         terminates on a self-reference; a missing var is 422; a lone-surrogate data value / template
                         is CONTAINED (U+FFFD), never an uncontained 5xx; the rendered output is bounded (cap -> 422).
         I-WINDOW        the bump-then-write torn window is read-side-defended: a missing version row -> 404, never 500.
         I-OWNER         cross-owner get/render/set-label/meta -> 404; bob creating the SAME name with distinct content
                         does NOT clobber alice's (both survive); bob's list excludes alice's prompts.
         I-CAP           creating past PROMPT_REGISTRY_MAX_VERSIONS is REJECTED (422) and PRESERVES the pinned v1
                         (reject-past-cap, never prune — prompts are referenced); labels reject past MAX_LABELS.
         I-RACE          two processes creating the same (owner,name) get DISTINCT sequential versions; both retrievable."""
import hashlib
import os
import subprocess
import sys

sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient  # noqa: E402

from app_pkg.core import store  # noqa: E402
from app_pkg.app import app  # noqa: E402

failures = []

# owner = the authenticated subject: enable the test-session seam (Bearer test:<subject>, inert in prod).
os.environ["APP_TEST_SESSIONS"] = "1"
ALICE = {"Authorization": "Bearer test:alice"}
BOB = {"Authorization": "Bearer test:bob"}


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


RACE_WORKER = """
import os, sys
sys.path.insert(0, os.getcwd())
from starlette.testclient import TestClient
from app_pkg.app import app
with TestClient(app, raise_server_exceptions=False, headers={"Authorization": "Bearer test:alice"}) as c:
    r = c.post("/prompt_registry/prompts/raced/versions", json={"template": sys.argv[1]})
    print(r.json()["version"] if r.status_code == 201 else f"status={r.status_code}")
"""


def main():
    with TestClient(app, raise_server_exceptions=False, headers=ALICE) as c:
        def create(name, template, headers=None):
            return c.post(f"/prompt_registry/prompts/{name}/versions", json={"template": template}, headers=headers)

        def getv(name, version, headers=None):
            return c.get(f"/prompt_registry/prompts/{name}/versions/{version}", headers=headers)

        def setlabel(name, label, version, headers=None):
            return c.put(f"/prompt_registry/prompts/{name}/labels/{label}", json={"version": version}, headers=headers)

        def render(name, headers=None, **body):
            return c.post(f"/prompt_registry/prompts/{name}/render", json=body, headers=headers)

        # I-IMMUTABLE — v1 frozen after v2 (delete-the-defense: an in-place overwrite would return T2 at v1)
        create("imm", "T1 {{v}}")
        create("imm", "T2 {{v}}")
        r1 = getv("imm", 1).json()
        check("I-IMMUTABLE v1's template is unchanged after v2", r1.get("template") == "T1 {{v}}" and r1.get("version") == 1, f"got {r1}")
        check("I-IMMUTABLE v2 is its own bytes", getv("imm", 2).json().get("template") == "T2 {{v}}")

        # I-PIN-HONEST — content_hash is an independent sha256 over the contained template; smuggled value discarded
        check("I-PIN-HONEST content_hash == sha256(template)", r1.get("content_hash") == sha("T1 {{v}}"), f"got {r1.get('content_hash')}")
        check("I-PIN-HONEST white-box: the stored row carries the real hash",
              store.get("prompt_registry_versions", "alice\x1fimm\x1f1").get("content_hash") == sha("T1 {{v}}"))
        sm = c.post("/prompt_registry/prompts/pin/versions", json={"template": "Z", "content_hash": "forged"}).json()
        check("I-PIN-HONEST a smuggled content_hash is DISCARDED (recomputed)", sm.get("content_hash") == sha("Z"), f"got {sm}")

        # I-LABEL-NO-DRIFT — the HEADLINE: a label does not follow the newest version
        create("drift", "one {{v}}")            # v1
        setlabel("drift", "production", 1)       # production -> v1
        create("drift", "two {{v}}")            # v2 lands UNDER the set label
        create("drift", "three {{v}}")          # v3 lands UNDER the set label
        rd = render("drift", label="production", data={"v": "X"}).json()
        check("I-LABEL-NO-DRIFT production STILL resolves v1 after v2,v3 (no silent newest)",
              rd.get("version") == 1 and rd.get("rendered") == "one X", f"got {rd}")
        # rollback gives the EXACT old content; one-to-one (a move strips the old)
        check("I-LABEL move to v3", render("drift", label="production", data={"v": "X"}).status_code == 200 and
              setlabel("drift", "production", 3).json().get("version") == 3)
        check("I-LABEL after move, production resolves v3", render("drift", label="production", data={"v": "X"}).json().get("version") == 3)
        setlabel("drift", "production", 1)       # rollback
        rb = render("drift", label="production", data={"v": "X"}).json()
        check("I-LABEL rollback to v1 gives v1's EXACT content", rb.get("version") == 1 and rb.get("rendered") == "one X", f"got {rb}")
        meta = c.get("/prompt_registry/prompts/drift").json()
        check("I-LABEL one-to-one: production maps to exactly v1 (moved off 3)", meta.get("labels") == {"production": 1}, f"got {meta.get('labels')}")
        check("I-LABEL a label to a non-existent version -> 422", setlabel("drift", "bad", 99).status_code == 422)
        check("I-LABEL an unset label render -> 404", render("drift", label="ghost", data={"v": "X"}).status_code == 404)

        # I-RENDER-SAFE — single-pass, terminates, contain, cap
        create("rs", "{{x}}")
        check("I-RENDER single-pass: a data value cannot inject a 2nd var",
              render("rs", version=1, data={"x": "{{y}}", "y": "SECRET"}).json().get("rendered") == "{{y}}")
        check("I-RENDER terminates on a self-reference", render("rs", version=1, data={"x": "{{x}}"}).json().get("rendered") == "{{x}}")
        check("I-RENDER a missing variable -> 422", render("rs", version=1, data={}).status_code == 422)
        # the surrogate is sent as a RAW json \u escape via content= (httpx cannot UTF-8-encode a lone surrogate via
        # json=); the server's json parser decodes it to a lone surrogate, which the handler contains to U+FFFD.
        sgd = c.post("/prompt_registry/prompts/rs/render", content='{"version": 1, "data": {"x": "\\ud800"}}',
                     headers={"content-type": "application/json"})
        check("I-RENDER a lone-surrogate data value is CONTAINED (U+FFFD), not 500",
              sgd.status_code == 200 and sgd.json().get("rendered") == "�", f"got {sgd.status_code} {sgd.json()}")
        sgt = c.post("/prompt_registry/prompts/ctemp/versions", content='{"template": "p\\ud800q"}',
                     headers={"content-type": "application/json"})
        check("I-RENDER a lone-surrogate TEMPLATE is contained before hash, not 500", sgt.status_code == 201, f"got {sgt.status_code}")
        check("I-RENDER the contained template stores as U+FFFD", getv("ctemp", 1).json().get("template") == "p�q")
        create("cap", "{{a}}" * 200)
        check("I-RENDER the rendered output is bounded (amplification -> 422)",
              render("cap", version=1, data={"a": "x" * 6000}).status_code == 422)

        # I-WINDOW — the bump-then-write torn window is read-side-defended (a missing version row -> 404, never 500)
        create("win", "W")
        store.delete_("prompt_registry_versions", "alice\x1fwin\x1f1")   # white-box: simulate the torn/crashed window
        check("I-WINDOW a missing version row -> 404 (not a 500)", getv("win", 1).status_code == 404)

        # I-OWNER — cross-owner 404 (read) + write isolation
        create("own", "ALICE {{v}}")             # alice v1
        check("I-OWNER cross-owner get -> 404", getv("own", 1, headers=BOB).status_code == 404)
        check("I-OWNER cross-owner render -> 404", render("own", headers=BOB, version=1, data={"v": "X"}).status_code == 404)
        check("I-OWNER cross-owner set-label -> 404", setlabel("own", "x", 1, headers=BOB).status_code == 404)
        check("I-OWNER cross-owner meta -> 404", c.get("/prompt_registry/prompts/own", headers=BOB).status_code == 404)
        bo = create("own", "BOB {{v}}", headers=BOB)
        check("I-OWNER bob creates HIS OWN 'own' v1 (distinct content)", bo.status_code == 201 and bo.json().get("version") == 1, f"got {bo.json()}")
        check("I-OWNER bob's 'own' v1 is BOB's bytes", getv("own", 1, headers=BOB).json().get("template") == "BOB {{v}}")
        check("I-OWNER alice's 'own' v1 is UNCHANGED — no cross-owner clobber", getv("own", 1).json().get("template") == "ALICE {{v}}")
        bl = c.get("/prompt_registry/prompts", headers=BOB).json()["results"]
        check("I-OWNER bob's list excludes alice's prompts but includes his own",
              all(p["name"] != "imm" for p in bl) and any(p["name"] == "own" for p in bl), f"got {[p['name'] for p in bl]}")

        # I-CAP — reject past MAX_VERSIONS (preserve pins, never prune); reject past MAX_LABELS
        os.environ["PROMPT_REGISTRY_MAX_VERSIONS"] = "2"
        c.post("/prompt_registry/prompts/cap2/versions", json={"template": "c1"})
        c.post("/prompt_registry/prompts/cap2/versions", json={"template": "c2"})
        third = c.post("/prompt_registry/prompts/cap2/versions", json={"template": "c3"})
        check("I-CAP creating past MAX_VERSIONS -> 422", third.status_code == 422, f"got {third.status_code}")
        check("I-CAP the pinned v1 is PRESERVED (reject, not prune)", getv("cap2", 1).json().get("template") == "c1")
        del os.environ["PROMPT_REGISTRY_MAX_VERSIONS"]
        os.environ["PROMPT_REGISTRY_MAX_LABELS"] = "2"
        create("lab", "L")
        check("I-CAP label 1 within cap", setlabel("lab", "l1", 1).status_code == 200)
        check("I-CAP label 2 within cap", setlabel("lab", "l2", 1).status_code == 200)
        check("I-CAP a 3rd DISTINCT label past cap -> 422", setlabel("lab", "l3", 1).status_code == 422)
        check("I-CAP moving an EXISTING label at cap is allowed (not a new label)", setlabel("lab", "l1", 1).status_code == 200)
        del os.environ["PROMPT_REGISTRY_MAX_LABELS"]

    # I-RACE — two processes create the same (owner,name); distinct sequential versions; both retrievable
    if os.getenv("DATABASE_PATH"):
        procs = [subprocess.Popen([sys.executable, "-c", RACE_WORKER, f"raced-{i}"], cwd=os.getcwd(),
                                  env={**os.environ, "LOG_LEVEL": "silent"},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for i in range(2)]
        outs = []
        for p in procs:
            so, se = p.communicate(timeout=120)
            outs.append((p.returncode, (so or "").strip().splitlines()[-1] if (so or "").strip() else se[:120]))
        versions = sorted(int(o) for rc, o in outs if rc == 0 and str(o).isdigit())
        check("I-RACE two racing creates -> distinct sequential versions", versions == [1, 2], f"got {outs}")
        with TestClient(app, raise_server_exceptions=False, headers=ALICE) as c:
            both = {c.get(f"/prompt_registry/prompts/raced/versions/{v}").json().get("template") for v in (1, 2)}
            check("I-RACE both racers' templates are retrievable", both == {"raced-0", "raced-1"}, f"got {both}")
            check("I-RACE latest_version advanced to the max", c.get("/prompt_registry/prompts/raced").json().get("latest_version") == 2)
    else:
        print("  [FAIL] I-RACE NOT RUN — DATABASE_PATH unset")
        failures.append("I-RACE not run")

    print(f"PROMPT_REGISTRY INVARIANTS: {'PASS' if not failures else 'FAIL — ' + ', '.join(failures)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
