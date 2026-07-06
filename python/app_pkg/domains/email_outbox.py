"""email — outbound email behind a provider PORT, with two dangerous properties, both proven:
(1) EXACTLY-ONCE DISPATCH: sending is idempotent on the Idempotency-Key — the claim is ONE atomic
    read-modify-write through the store's `do` seam (claim_once), so two processes racing the same key produce
    ONE recorded message and the loser is served the winner's record. Key reuse with ANY different message
    (recipients, subject, body, template) is a 409 — never a silent re-send, never a dropped Bcc. The slot is
    SCOPED to the authenticated caller (scoped_key), so an Idempotency-Key is PRIVATE — caller B can never replay,
    nor be griefed by, caller A's slot.
(2) HEADER SAFETY: no recorded/dispatched message can carry an INJECTED header — every header-bound field
    (`from`/`to`/`cc`/`bcc`/`reply_to` via valid_email, the rendered `subject` via valid_header_text) rejects
    CR/LF + control/NEL/line-separator, so a `subject` (or a template `data` value rendered INTO the subject) can
    never open a second header line. Validation runs AFTER template rendering (substitution is itself an injection
    surface). We REJECT (422) — deliberately stricter than libraries that silently sanitize.
The cost is OWNER-SCOPED (owner = the authenticated subject, never a body field): listing or reading another
caller's message is 404, byte-indistinguishable from missing. Append-only (no update/delete route); durable (a
keyed send dedups after a restart). Offline/deterministic: the default backend RECORDS the message to the store
(the record IS the outbox); a real provider is the documented `_dispatch` swap-point (see INTEROP.md). Every
route require_identity (no token 401). Same names + DECISIONS in all three languages."""
import os
import re
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, Field, StrictStr

from ..core import clock, store
from ..core.errors import IntPath, conflict, invalid, not_found, require_identity
from ..parts.digest import digest_hex, scoped_key
from ..parts.idempotent_claim import claim_once
from ..parts.paginate import paginate
from ..parts.well_formed import make_well_formed, require_well_formed

router = APIRouter(prefix="/email_outbox", tags=["email_outbox"])

_ROUTE = "POST /email_outbox/messages"           # the dedup-slot discriminator (per-operation, owner-scoped slot)
_MAX_SUBJECT_BYTES = 998                   # RFC 5322 §2.1.1 line length — a hard protocol limit (not env-tunable)


def _env_limit(name: str, default: int) -> int:
    # an operator LIMIT: a positive int within the 2^53-safe range (so go int64 / node safe-int / python big-int
    # AGREE ×3 — the env-knob overflow class); anything else falls back to the default. ×3-identical with go/node.
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        v = int(raw)
    except ValueError:
        return default
    return v if 1 <= v <= (1 << 53) - 1 else default


_MAX_RECIPIENTS = _env_limit("EMAIL_MAX_RECIPIENTS", 50)       # to+cc+bcc combined (the SES/Resend floor)
_MAX_BODY_BYTES = _env_limit("EMAIL_MAX_BODY_BYTES", 262144)   # rendered html+text, UTF-8 octets

# THE TEMPLATE REGISTRY (policy, code-reviewed) — id -> {subject, html, text}; `{{name}}` placeholders are filled
# by name-lookup from the request `data` (string->string). Render SCANS the template for placeholders (never
# iterates the data map -> deterministic ×3). The subject is still header-validated AFTER rendering. NEVER empty.
_TEMPLATES = {
    "verify_email": {"subject": "Verify your email address",
                     "html": "<p>Hi {{name}},</p><p>Confirm your address: {{link}}</p>",
                     "text": "Hi {{name}},\nConfirm your address: {{link}}"},
    "reset_password": {"subject": "Reset your password",
                       "html": "<p>Hi {{name}},</p><p>Reset your password: {{link}}</p>",
                       "text": "Hi {{name}},\nReset your password: {{link}}"},
    "notify": {"subject": "New message: {{title}}", "html": "<p>{{body}}</p>", "text": "{{body}}"},
}
_PLACEHOLDER = re.compile(r"\{\{([A-Za-z0-9_]+)\}\}")   # ASCII-explicit (go/node \w differ on unicode) -> ×3 parity

# valid_email: a strict boundary VALIDATOR — a SUPERSET of the connector email_domain extractor (it rejects
# everything that extractor rejects: CR/LF/space/comma/multi-@/no-dot) PLUS the RFC 5321 length caps + the WHATWG
# dot-atom charset. NO maximalist RFC-5322 regex, NO DNS/MX probe (offline/deterministic). Stricter divergence
# from the extractor: surrounding whitespace is REJECTED (not trimmed) — py strip / go TrimSpace / node trim strip
# different unicode sets, so trimming would diverge ×3.
_MAX_ADDR, _MAX_LOCAL, _MAX_DOMAIN = 254, 64, 255
_LOCAL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.!#$%&'*+/=?^_`{|}~-")
_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def valid_email(s) -> bool:
    if not isinstance(s, str) or not s or len(s) > _MAX_ADDR or s.count("@") != 1:
        return False
    local, _, domain = s.partition("@")
    if not local or not domain or len(local) > _MAX_LOCAL or len(domain) > _MAX_DOMAIN:
        return False
    if any(c not in _LOCAL_CHARS for c in local):
        return False
    labels = domain.split(".")                       # require >=2 labels -> a dot (rejects user@localhost)
    return len(labels) >= 2 and all(_LABEL.match(lbl) for lbl in labels)


# valid_header_text: the HEADER-INJECTION wall — reject CR (U+000D) + LF (U+000A) [the injection MUST] plus the
# rest of C0, DEL, C1 (incl. NEL U+0085) and U+2028/U+2029, so a header-bound value can never open a second header
# line (the Django BadHeaderError pole; we reject rather than sanitize). TAB is collaterally rejected (it is < 0x20).
_HEADER_BAD = frozenset(list(range(0x00, 0x20)) + [0x7F] + list(range(0x80, 0xA0)) + [0x2028, 0x2029])


def valid_header_text(s) -> bool:
    return isinstance(s, str) and not any(ord(c) in _HEADER_BAD for c in s)


def _render(tpl: str, data: dict) -> str:
    # scan the TEMPLATE for {{key}} (never iterate `data` -> deterministic ×3); a placeholder with no `data` value
    # is a 422 (never a silent blank). Single-pass: a substituted value is NOT re-scanned (no recursive injection).
    missing: List[str] = []

    def repl(m):
        k = m.group(1)
        if k not in data:
            missing.append(k)
            return ""
        return data[k]

    out = _PLACEHOLDER.sub(repl, tpl)
    if missing:
        raise invalid("template variable not provided")
    return out


def _h(s: str) -> str:
    return digest_hex(s)                              # pre-hash one variable-length field to fixed colon-free hex


def _hl(xs) -> str:
    return digest_hex(*[_h(x) for x in xs])           # pre-hash each list element -> injective (the scoped_key idiom)


def _body_hash(frm, to, cc, bcc, reply_to, subject, html, text, tid, data) -> str:
    # the fingerprint over EVERY message-determining REQUEST field (pre-render: raw subject/html/text for a raw send,
    # the template id+data for a template send). digest_hex joins with ':' and is NOT injective for free text, so each
    # variable-length field is PRE-HASHED first (the injective-preimage rule) — an added bcc / a changed data value
    # all drift the hash -> a same-key reuse with any different message is a 409, never a silent dedup.
    return digest_hex("from", _h(frm), "to", _hl(to), "cc", _hl(cc), "bcc", _hl(bcc), "reply", _hl(reply_to),
                      "subj", _h(subject), "html", _h(html), "text", _h(text), "tid", _h(tid),
                      "data", digest_hex(*[p for k in sorted(data) for p in (_h(k), _h(data[k]))]))


def _dispatch(rec) -> None:
    # the offline "fake" backend: the stored record IS the sent message (record-to-store — the Django locmem/outbox
    # model). A real backend (smtp/sendgrid/ses) transmits `rec` here; selecting one is the INTEROP swap-point. The
    # caller invokes this ONLY on a fresh claim, so a retried/raced send never dispatches twice.
    return None


def _public(rec) -> dict:
    return {"id": rec["id"], "from": rec["from"], "to": rec["to"], "cc": rec["cc"], "bcc": rec["bcc"],
            "reply_to": rec["reply_to"], "subject": rec["subject"], "created_at": rec["created_at"]}


class TemplateIn(BaseModel):
    id: StrictStr
    data: Dict[str, StrictStr] = {}                   # string->string: a numeric/bool value is 422 (no coercion ×3)


class SendIn(BaseModel):
    from_: StrictStr = Field(alias="from")            # `from` is a python keyword -> the field is `from_`, wire "from"
    to: List[StrictStr]
    cc: List[StrictStr] = []
    bcc: List[StrictStr] = []
    reply_to: List[StrictStr] = []
    subject: Optional[StrictStr] = None
    html: Optional[StrictStr] = None
    text: Optional[StrictStr] = None
    template: Optional[TemplateIn] = None


@router.post("/messages", status_code=201)
def emailOutboxSend(data: SendIn, request: Request, owner: str = Depends(require_identity),
              idempotency_key: Optional[str] = Header(default=None)) -> dict:
    # an authenticated caller sends as itself — `owner` (the dedup slot + the audit) is the token subject, never
    # a body field. FastAPI parses the body (422) before the dependency, so a malformed body is 422 and a no-token
    # caller is 401, identical to go's decode-then-auth precedence ×3.
    frm = data.from_
    if not valid_email(frm):
        raise invalid("from is not a valid email address")
    for lst in (data.to, data.cc, data.bcc, data.reply_to):
        for addr in lst:
            if not valid_email(addr):
                raise invalid("a recipient address is not valid")
    recipients = data.to + data.cc + data.bcc
    if not data.to:
        raise invalid("to must contain at least one recipient")
    if len(recipients) > _MAX_RECIPIENTS:
        raise invalid("too many recipients")
    if len(set(recipients)) != len(recipients):
        raise invalid("a recipient address is duplicated across to/cc/bcc")
    has_tpl = data.template is not None
    has_raw = data.subject is not None or data.html is not None or data.text is not None
    if has_tpl and has_raw:
        raise invalid("provide either a template or subject/body, not both")
    if has_tpl:
        tpl = _TEMPLATES.get(data.template.id)
        if tpl is None:
            raise invalid("unknown template")
        # CONTAIN the data values (a lone surrogate cannot be UTF-8-hashed/serialized) BEFORE render + fingerprint
        tdata = {k: make_well_formed(v) for k, v in data.template.data.items()}
        subject = make_well_formed(_render(tpl["subject"], tdata))
        html = make_well_formed(_render(tpl["html"], tdata))
        text = make_well_formed(_render(tpl["text"], tdata))
        body_hash = _body_hash(frm, data.to, data.cc, data.bcc, data.reply_to, "", "", "", data.template.id, tdata)
    else:
        if data.subject is None or (data.html is None and data.text is None):
            raise invalid("a raw send needs a subject and at least one of html/text")
        # CONTAIN BEFORE the fingerprint (a lone surrogate from a \u-escape cannot be UTF-8-hashed -> would 500)
        subject = make_well_formed(data.subject)
        html = make_well_formed(data.html or "")
        text = make_well_formed(data.text or "")
        body_hash = _body_hash(frm, data.to, data.cc, data.bcc, data.reply_to, subject, html, text, "", {})
    # RENDER-THEN-VALIDATE: header-safety + bounds on the CONTAINED, rendered output (a template `data` value can
    # inject into the rendered subject; containment already ran above).
    if not valid_header_text(subject):
        raise invalid("subject must not contain control characters or line breaks")
    if len(subject.encode()) > _MAX_SUBJECT_BYTES:
        raise invalid("subject is too long")
    if len(html.encode()) + len(text.encode()) > _MAX_BODY_BYTES:
        raise invalid("message body is too large")
    created_at = clock.current(request)

    def build(eid):
        return {"id": eid, "owner": owner, "from": frm, "to": data.to, "cc": data.cc, "bcc": data.bcc,
                "reply_to": data.reply_to, "subject": subject, "html": html, "text": text,
                "created_at": created_at, "body_hash": body_hash}

    if idempotency_key is None:                       # no key -> no dedupe (opt-in, the Resend/Stripe contract)
        eid = store.next_id("email_outbox_message")
        rec = build(eid)
        store.put("email_outbox_messages", str(eid), rec)
        _dispatch(rec)
        return _public(rec)
    if len(request.headers.getlist("idempotency-key")) > 1:
        raise invalid("Idempotency-Key must be a single value")   # ambiguous duplicate -> reject (deterministic ×3)
    require_well_formed(idempotency_key, "Idempotency-Key")
    scoped = scoped_key(_ROUTE, owner, idempotency_key)           # caller-scoped, collision-safe slot
    prior = store.get("email_outbox_messages", scoped)                  # fast path: a settled key never mints
    if prior is None:
        eid = store.next_id("email_outbox_message")        # mint BEFORE the claim (a race loser's id is a harmless gap)
        rec = build(eid)
        prior = claim_once("email_outbox_messages", scoped, rec)        # exactly-once: a racing loser gets the winner
        if prior["id"] == eid:                       # I won the claim -> send ONCE (the fresh branch)
            _dispatch(prior)
    if prior["owner"] != owner:                      # defense-in-depth (the scoped slot already isolates callers)
        raise conflict("Idempotency-Key is not owned by this caller")
    if prior["body_hash"] != body_hash:
        raise conflict("Idempotency-Key reused with a different message")
    return _public(prior)


@router.get("/messages")
def emailOutboxList(request: Request, limit: str = "", cursor: str = "", owner: str = Depends(require_identity)) -> dict:
    # OWNER-scoped audit trail, BOUNDED through paginate; only the caller's own sends, id order (deterministic ×3).
    rows = sorted((r for r in store.values("email_outbox_messages") if r["owner"] == owner), key=lambda r: r["id"])
    page, nxt, ok = paginate([_public(r) for r in rows], cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/messages/{message_id}")
def emailOutboxGet(message_id: IntPath, owner: str = Depends(require_identity)) -> dict:
    # unbounded-safe: a single-record lookup by id (returns at most one row); OWNER-scoped — not-yours == 404,
    # byte-indistinguishable from missing (existence never leaks across callers).
    for r in store.values("email_outbox_messages"):
        if r["id"] == message_id and r["owner"] == owner:
            return _public(r)
    raise not_found("message")
