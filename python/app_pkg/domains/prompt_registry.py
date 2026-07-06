"""prompt_registry — a versioned, IMMUTABLE prompt-template store with movable deployment LABELS (rollback) and a
deterministic {{variable}} render. The dangerous property is PIN-HONESTY (proven in invariant_test.py):
(1) IMMUTABILITY: each POST mints a NEW monotonic version per (owner,name) through the `do` seam — a published
    version's (template, content_hash) is frozen forever; there is NO update/delete route (append-only).
(2) LABEL NO-DRIFT: a label is a movable pointer to ONE version; setting it MOVES it (one-to-one); creating new
    versions NEVER moves an existing label (no virtual `latest`, no silent default — render/get require an explicit
    {version|label}); rolling a label back resolves to that version's EXACT immutable content.
(3) CONTENT PIN: content_hash = digest_hex over the CONTAINED template — ONE pre-contained string, so the preimage is
    injective by construction (no multi-field ':'-join ambiguity). SERVER-DERIVED; a smuggled content_hash is discarded.
(4) DETERMINISTIC RENDER: render(version|label, data) substitutes {{var}} from a string->string `data` map — the ASCII
    [A-Za-z0-9_] placeholder regex (NOT \\w; go/node diverge on unicode), SCAN the template not the data (deterministic
    x3), SINGLE-PASS (a substituted value is not re-scanned, so a data value can't inject a 2nd var and a self-ref
    terminates), a missing variable is 422 (never a silent blank), the data values are CONTAINED (a lone surrogate ->
    U+FFFD, never an uncontained 5xx) BEFORE substitution, then the rendered output is bounded (the amplification cap).
(5) OWNER-SCOPED: owner = the authenticated subject (require_identity, never a body field); the store key is the
    composite <owner>\\x1f<name> so caller B can NEVER clobber caller A's name (the \\x1f separator is a control char
    well_formed rejects -> the key can't be forged), and a get/render/set-label/meta of another caller's prompt is 404
    (byte-indistinguishable from missing). Names/labels are require_well_formed (control-char-free) THEN contained
    (make_well_formed) so the key + the echoed identifier are always UTF-8-safe.
The managed denominator (Langfuse/PromptLayer/LangSmith Prompt Hub) defers render to the client SDK and serves the raw
template (our get-version does too); our /render is the offline, deterministic, identical-x3 carrier (INTEROP.md).
Same names + DECISIONS in all three languages."""
import os
import re
from typing import Annotated, Dict, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, StrictStr, field_validator

from ..core import clock, store
from ..core.errors import IntPath, SafeInt, invalid, not_found, require_identity
from ..parts.digest import digest_hex
from ..parts.env_int import env_int
from ..parts.paginate import paginate
from ..parts.well_formed import make_well_formed, require_well_formed

router = APIRouter(prefix="/prompt_registry", tags=["prompt_registry"])
_PROMPTS = "prompt_registry_prompts"     # "<owner>\x1f<name>" -> {owner, name, latest_version, labels:{label:version}, created_at}
_VERSIONS = "prompt_registry_versions"   # "<owner>\x1f<name>\x1f<version>" -> {owner, name, version, template, content_hash, created_at}

_PLACEHOLDER = re.compile(r"\{\{([A-Za-z0-9_]+)\}\}")   # ASCII-explicit (go/node \w differ on unicode) -> x3 parity


def _max_versions() -> int:
    return env_int(os.getenv("PROMPT_REGISTRY_MAX_VERSIONS"), 1000, 1)   # reject past the cap (preserve pins; never prune)


def _max_labels() -> int:
    return env_int(os.getenv("PROMPT_REGISTRY_MAX_LABELS"), 50, 1)


def _max_template_bytes() -> int:
    return env_int(os.getenv("PROMPT_REGISTRY_MAX_TEMPLATE_BYTES"), 65536, 1)


def _max_rendered_bytes() -> int:
    return env_int(os.getenv("PROMPT_REGISTRY_MAX_RENDERED_BYTES"), 262144, 1)   # the amplification cap (a small template can render huge)


def _clean(value: str, what: str) -> str:
    # an identifier (name / label): require_well_formed REJECTS a control char (< 0x20, so the \x1f key separator can't
    # be forged) -> 422; make_well_formed then CONTAINS a lone surrogate (>= 0x20, accepted by require) to U+FFFD so the
    # composite key AND the echoed identifier are always UTF-8-serializable (the email_outbox I6a contain-before-serialize
    # rule, applied to the key/name). Go strings are valid UTF-8 already, so MakeWellFormed is identity there -> x3.
    require_well_formed(value, what)
    return make_well_formed(value)


def _pkey(owner: str, name: str) -> str:
    return f"{owner}\x1f{name}"                  # owner-partitioned: B can't clobber A's name (\x1f unforgeable, cleaned)


def _vkey(owner: str, name: str, version: int) -> str:
    return f"{owner}\x1f{name}\x1f{version}"


def _render(template: str, data: dict) -> str:
    # scan the TEMPLATE for {{key}} (never iterate `data` -> deterministic x3); a placeholder with no `data` value is a
    # 422 (never a silent blank). SINGLE-PASS: a substituted value is NOT re-scanned (no recursive injection; a self-ref
    # {{x}}->"{{x}}" terminates). `data` values are already contained by the caller (CONTAIN-before-substitute).
    missing = []

    def repl(m):
        k = m.group(1)
        if k not in data:
            missing.append(k)
            return ""
        return data[k]

    out = _PLACEHOLDER.sub(repl, template)
    if missing:
        raise invalid("template variable not provided")
    return out


def _public_version(rec: dict) -> dict:
    return {"name": rec["name"], "version": rec["version"], "template": rec["template"],
            "content_hash": rec["content_hash"], "created_at": rec["created_at"]}


class CreateIn(BaseModel):
    template: StrictStr     # the ONLY body field read (allowlist) -> a smuggled owner/version/content_hash is ignored

    @field_validator("template")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("must be non-empty")
        return value


class SetLabelIn(BaseModel):
    version: Annotated[SafeInt, Field(ge=1)]    # REQUIRED strict positive int in the 2^53-safe range (x3-identical)


class RenderIn(BaseModel):
    version: Optional[Annotated[SafeInt, Field(ge=1)]] = None
    label: Optional[StrictStr] = None
    data: Dict[str, StrictStr] = {}             # string->string: a numeric/bool value is 422 (no coercion x3)


@router.post("/prompts/{name}/versions", status_code=201)
def create_version(name: str, data: CreateIn, request: Request, owner: str = Depends(require_identity)) -> dict:
    # an authenticated caller mints a version as itself — owner is the token subject, never a body field.
    name = _clean(name, "the prompt name")
    template = make_well_formed(data.template)              # CONTAIN before hash/store (a lone surrogate would 5xx the hash)
    if len(template.encode()) > _max_template_bytes():
        raise invalid("template is too large")
    content_hash = digest_hex(template)                     # server-DERIVED pin over the ONE contained string (injective)
    created_at = clock.current(request)
    mx = _max_versions()
    over = False

    def bump(prompt):                                       # the per-(owner,name) version counter — one atomic RMW
        nonlocal over
        if prompt is None:
            return {"owner": owner, "name": name, "latest_version": 1, "labels": {}, "created_at": created_at}, 1
        if prompt["latest_version"] >= mx:                  # reject past the cap (preserve every pin; never prune)
            over = True
            return None, prompt["latest_version"]           # None -> no write
        version = prompt["latest_version"] + 1
        return {**prompt, "latest_version": version}, version

    version = store.do(_PROMPTS, _pkey(owner, name), bump)
    if over:
        raise invalid(f"too many versions (max {mx})")
    # the immutable version row, written AFTER the do (the callback is pure — no nested store call). A crash here leaves
    # a benign GAP (latest=N, row N absent) that the read-side None-check below turns into a 404, never a torn read.
    store.put(_VERSIONS, _vkey(owner, name, version),
              {"owner": owner, "name": name, "version": version, "template": template,
               "content_hash": content_hash, "created_at": created_at})
    return {"name": name, "version": version, "content_hash": content_hash, "created_at": created_at}


@router.get("/prompts/{name}/versions/{version}")
def get_version(name: str, version: IntPath, owner: str = Depends(require_identity)) -> dict:
    # unbounded-safe: a single immutable version by key; OWNER-scoped — not-yours == 404 (the composite key includes
    # owner, so bob's lookup of alice's version misses). A missing row (torn window / never-written) is also 404.
    name = _clean(name, "the prompt name")
    rec = store.get(_VERSIONS, _vkey(owner, name, version))
    if rec is None:
        raise not_found("prompt version")
    return _public_version(rec)


@router.get("/prompts")
def list_prompts(request: Request, limit: str = "", cursor: str = "", owner: str = Depends(require_identity)) -> dict:
    # read-scope: owner — ONLY the caller's own prompts (owner FIELD == caller); sorted by name (stable x3); BOUNDED
    # through the shared paginate seam (a stranger gets an empty page, never 403).
    rows = sorted((p for p in store.values(_PROMPTS) if p["owner"] == owner), key=lambda p: p["name"])
    page, nxt, ok = paginate([{"name": p["name"], "latest_version": p["latest_version"]} for p in rows], cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/prompts/{name}")
def get_prompt(name: str, owner: str = Depends(require_identity)) -> dict:
    # read-scope: owner — the prompt's metadata (latest_version, the label map, the count); not-yours == 404.
    name = _clean(name, "the prompt name")
    p = store.get(_PROMPTS, _pkey(owner, name))
    if p is None:
        raise not_found("prompt")
    # version_count == latest_version (append-only, no delete -> versions are contiguous 1..latest). latest_version is
    # read-only METADATA — NOT a resolvable render target (no silent-newest; the no-drift stance).
    return {"name": p["name"], "latest_version": p["latest_version"], "version_count": p["latest_version"],
            "labels": p["labels"], "created_at": p["created_at"]}


@router.put("/prompts/{name}/labels/{label}")
def set_label(name: str, label: str, data: SetLabelIn, owner: str = Depends(require_identity)) -> dict:
    # mutation-auth: identity — move a deployment label to point at a version (the rollback/promote op). OWNER-scoped:
    # setting a label on another caller's prompt is 404. The target version must be an EXISTING immutable row (checked
    # against the version ROW, NOT the counter — the counter is bumped before the row is written, the torn window).
    name = _clean(name, "the prompt name")
    label = _clean(label, "the label")
    version = data.version
    if store.get(_PROMPTS, _pkey(owner, name)) is None:
        raise not_found("prompt")                          # not-yours / missing -> 404 (existence never leaks)
    if store.get(_VERSIONS, _vkey(owner, name, version)) is None:
        raise invalid("version does not exist")            # the prompt is ours, but this version row isn't there
    mx = _max_labels()
    outcome = "ok"

    def setl(prompt):                                      # RMW the prompt record's label map atomically
        nonlocal outcome
        if prompt is None:                                # defensive: vanished between the check and the do (append-only -> can't)
            outcome = "no-prompt"
            return None, None
        labels = dict(prompt["labels"])
        if label not in labels and len(labels) >= mx:     # a NEW label past the cap is rejected; MOVING an existing one is fine
            outcome = "too-many"
            return None, None
        labels[label] = version                           # one-to-one: setting MOVES the label (strips its old target)
        return {**prompt, "labels": labels}, None

    store.do(_PROMPTS, _pkey(owner, name), setl)
    if outcome == "no-prompt":
        raise not_found("prompt")
    if outcome == "too-many":
        raise invalid(f"too many labels (max {mx})")
    return {"name": name, "label": label, "version": version}


@router.post("/prompts/{name}/render")
def render_prompt(name: str, data: RenderIn, owner: str = Depends(require_identity)) -> dict:
    # render a version by EXACTLY one of {version|label} (the 5/5 convergent fetch contract — no silent default).
    # OWNER-scoped: rendering another caller's prompt is 404.
    name = _clean(name, "the prompt name")
    if (data.version is None) == (data.label is None):
        raise invalid("provide exactly one of version or label")
    if data.label is not None:
        label = _clean(data.label, "the label")
        p = store.get(_PROMPTS, _pkey(owner, name))
        if p is None:
            raise not_found("prompt")
        version = p["labels"].get(label)
        if version is None:
            raise not_found("label")                       # an unset label -> 404 (no silent fallback to newest)
    else:
        version = data.version
    rec = store.get(_VERSIONS, _vkey(owner, name, version))
    if rec is None:
        raise not_found("prompt version")
    # CONTAIN the data values BEFORE substitution (a lone surrogate can't be UTF-8-serialized -> would 5xx); string->string.
    cdata = {k: make_well_formed(v) for k, v in data.data.items()}
    rendered = _render(rec["template"], cdata)             # scan template, single-pass, missing -> 422
    if len(rendered.encode()) > _max_rendered_bytes():     # RENDER-THEN-VALIDATE: bound the rendered output (amplification)
        raise invalid("rendered output is too large")
    return {"name": name, "version": version, "content_hash": rec["content_hash"], "rendered": rendered}
