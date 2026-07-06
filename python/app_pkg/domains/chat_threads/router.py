"""chat_threads — a durable, owner-scoped AI-chat history store whose dangerous property is APPEND-ONLY ORDERED
HISTORY + OWNER ISOLATION + BOUNDED BOTH WAYS (proven in invariant_test.py):
(1) ORDERED: a message's position is a SERVER-MINTED, per-thread strictly-monotonic `seq`, incremented inside ONE
    atomic read-modify-write on the thread row — two racing appends serialize to distinct consecutive seqs (no
    lost update) and the transcript reads back in exactly append order (a replay that reorders turns silently
    corrupts a model's context — the quiet catastrophe of a chat store).
(2) IMMUTABLE: no route edits or deletes a single message; history is a record, not a cache ("edit" in a chat
    product appends a new turn).
(3) BOUNDED BOTH WAYS: messages-per-thread AND threads-per-owner are both capped, REJECT-past-cap 422 — never a
    silent eviction (dropping a user's chat history is data loss; the caller frees space by deleting threads).
    The per-owner total is bounded by MAX_THREADS x MAX_MESSAGES by construction.
(4) OWNER-ISOLATED: owner = the authenticated subject (require_identity, never a body field); rows are keyed by
    the composite <owner>\x1f<id> and <owner>\x1f<id>\x1f<seq> (ids + seqs are server-minted digits and the owner
    is the trusted token subject, so the joined key cannot be forged by any client string); not-yours == 404 on
    every surface. The per-owner thread INDEX is the liveness authority — every per-thread surface gates on it,
    so a delete's crash residue is never resurrected.
(5) CASCADE DELETE: owner-index-FIRST — the cap slot is freed and the thread instantly non-listable, then the row
    is removed and the message rows reaped (unlike providers that leave a deleted conversation's items behind).
`last_seq` is the honest high-water mark of ACCEPTED appends (after a crash between the seq mint and the message
write the transcript can be shorter — never reordered). Content is free text, CONTAINED before store (a lone
surrogate becomes U+FFFD, never a failed re-read) and byte-capped; the title is a display line (control
characters rejected); metadata keys AND values are contained, then bounded on the contained, collapsed dict
(16 pairs, 64-char keys, 512-char values — the field's settled numbers). The role set is CLOSED
(user|assistant|system|tool, exact lowercase). Threads list newest-activity-first (-updated_at, -id); messages
list seq ASC (the replay order); both paginated. Generating an assistant turn is the agent seam's job — this
domain PERSISTS turns, it never calls a model (see INTEROP.md). Same names + DECISIONS in all three languages."""
import os
from typing import Dict, Optional

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, StrictStr

from ...core import clock, store
from ...core.errors import IntPath, invalid, not_found, require_identity
from ...parts.env_int import env_int
from ...parts.paginate import paginate
from ...parts.well_formed import make_well_formed, require_well_formed

router = APIRouter(prefix="/chat_threads", tags=["chat_threads"])
_INDEX = "chat_threads_index"    # "<owner>"                  -> [thread id, ...]  (the liveness set + the thread-COUNT bound)
_THREAD = "chat_threads_thread"  # "<owner>\x1f<id>"          -> {id, owner, title, metadata, created_at, updated_at, last_seq}
_MSG = "chat_threads_message"    # "<owner>\x1f<id>\x1f<seq>" -> {seq, thread_id, owner, role, content, metadata, created_at}

_ROLES = ("user", "assistant", "system", "tool")  # the CLOSED role set, exact lowercase ("User" is 422 — a case-fold would drift x3)
_MAX_TITLE_BYTES = 256           # a title is a display line (a fixed structural bound)
_MAX_META_PAIRS = 16             # metadata bounds: the field's settled numbers (16 pairs, 64-char keys, 512-char values)
_MAX_META_KEY_CHARS = 64
_MAX_META_VALUE_CHARS = 512


def _max_threads() -> int:       return env_int(os.getenv("CHAT_THREADS_MAX_THREADS"), 500, 1)      # threads per owner (reject past cap)
def _max_messages() -> int:      return env_int(os.getenv("CHAT_THREADS_MAX_MESSAGES"), 1000, 1)    # messages per thread (reject past cap)
def _max_content_bytes() -> int: return env_int(os.getenv("CHAT_THREADS_MAX_CONTENT_BYTES"), 16384, 1)


def _tkey(owner: str, tid: int) -> str:           return f"{owner}\x1f{tid}"           # owner-partitioned thread rows (B can't reach A's id)
def _mkey(owner: str, tid: int, seq: int) -> str: return f"{owner}\x1f{tid}\x1f{seq}"  # one immutable slot per (thread, seq)


def _clean_title(raw: str) -> str:
    # An empty title is legal (an untitled thread). A NON-empty title is a display LINE: reject control characters
    # (< 0x20, the shared identifier rule — so the \x1f key-separator class can't even appear), CONTAIN a lone
    # surrogate (>= 0x20, accepted by require) to U+FFFD, then cap bytes.
    if raw == "":
        return ""
    require_well_formed(raw, "the title")
    cleaned = make_well_formed(raw)
    if len(cleaned.encode()) > _MAX_TITLE_BYTES:
        raise invalid("the title is too large")
    return cleaned


def _clean_metadata(metadata: Optional[Dict[str, str]]) -> Dict[str, str]:
    # CONTAIN metadata KEYS and VALUES before store (a lone surrogate in either is a stored poison a later re-read
    # would 500 on), THEN bound the CONTAINED, COLLAPSED dict: pair count + per-key/per-value CODE-POINT lengths.
    # Counting post-containment matches go, whose JSON decode already collapsed distinct lone-surrogate keys into
    # one U+FFFD entry before the handler ever sees the map.
    if not metadata:
        return {}
    out = {}
    for k, v in metadata.items():
        out[make_well_formed(k)] = make_well_formed(v)
    if len(out) > _MAX_META_PAIRS:
        raise invalid(f"too many metadata entries (max {_MAX_META_PAIRS})")
    for k, v in out.items():
        if len(k) > _MAX_META_KEY_CHARS:
            raise invalid(f"a metadata key is too long (max {_MAX_META_KEY_CHARS} characters)")
        if len(v) > _MAX_META_VALUE_CHARS:
            raise invalid(f"a metadata value is too long (max {_MAX_META_VALUE_CHARS} characters)")
    return out


def _clean_content(raw: str) -> str:
    # Message content is free TEXT (multi-line chat turns are the norm), never a key component (keys are the owner
    # + server-minted digits) — so it is CONTAINED (lone surrogate -> U+FFFD) and byte-capped; control characters
    # ride along as data, exactly like a queue payload or a memory note.
    if raw == "":
        raise invalid("content must be a non-empty string")
    cleaned = make_well_formed(raw)
    if len(cleaned.encode()) > _max_content_bytes():
        raise invalid("content is too large")
    return cleaned


def _in_index(owner: str, tid: int) -> bool:
    # The per-owner thread index is LIVENESS-AUTHORITATIVE: a thread is live only while its id is IN the index.
    # Every per-thread surface gates on this, so a delete's crash residue (a row without an index entry) is
    # deterministically 404 — never resurrected.
    return tid in (store.get(_INDEX, owner) or [])


def _thread_public(rec: dict) -> dict:
    return {"id": rec["id"], "title": rec["title"], "metadata": rec["metadata"],
            "created_at": rec["created_at"], "updated_at": rec["updated_at"], "last_seq": rec["last_seq"]}


def _message_public(rec: dict) -> dict:
    return {"seq": rec["seq"], "thread_id": rec["thread_id"], "role": rec["role"], "content": rec["content"],
            "metadata": rec["metadata"], "created_at": rec["created_at"]}


class ThreadIn(BaseModel):
    # NULL PARITY (x3): both fields OPTIONAL; an explicit `null` is treated as ABSENT — identical to go (a JSON
    # null decodes to a nil *T) and node (an explicit null guard). A smuggled owner/id/last_seq/created_at is
    # simply never read (allowlist input model) [guarded_fields: owner].
    title: Optional[StrictStr] = None                # null/absent -> "" (an untitled thread); a number -> 422 (no coercion x3)
    metadata: Optional[Dict[str, StrictStr]] = None  # string->string; a numeric/null/nested value -> 422 (no coercion x3)


class AppendIn(BaseModel):
    role: StrictStr                                  # membership in the CLOSED role set is checked in the handler
    content: StrictStr                               # required; non-empty + containment + byte cap in the handler
    metadata: Optional[Dict[str, StrictStr]] = None  # per-turn provenance (model, usage, ...); same bounds as a thread's


def _reserve_slot(owner: str, tid: int) -> bool:
    """Append `tid` to the per-owner thread index; return True iff REJECTED (past MAX_THREADS)."""
    mx = _max_threads()
    rejected = False

    def fn(tids):
        nonlocal rejected
        cur = tids or []
        if len(cur) >= mx:
            rejected = True
            return None, None                        # reject: leave unwritten (the thread-COUNT bound)
        # unbounded-safe: the per-owner thread list is bounded at MAX_THREADS by the reject-past-cap guard above —
        # a create past the cap is a loud 422, never an eviction (evicting a thread would silently delete a user's
        # chat history). Bounding the number of threads bounds the KEY-SPACE: message rows are per-seq slots under
        # each thread, so the per-owner total is capped at MAX_THREADS x MAX_MESSAGES by construction.
        return cur + [tid], None

    store.do(_INDEX, owner, fn)
    return rejected


@router.post("", status_code=201)
def create_thread(data: ThreadIn, request: Request, owner: str = Depends(require_identity)) -> dict:
    # mutation-auth: identity — an authenticated caller creates a thread as ITSELF; owner is the token subject,
    # never a body field [guarded_fields: owner].
    title = _clean_title(data.title if data.title is not None else "")   # null/absent -> "" (x3 null parity)
    metadata = _clean_metadata(data.metadata)
    now = clock.current(request)
    tid = store.next_id("chat_threads_id")           # server-mint (globally unique); a cap-rejected create wastes it as a benign gap
    if _reserve_slot(owner, tid):                    # bound the thread COUNT first: index-FIRST also means a crash
        raise invalid(f"too many threads (max {_max_threads()})")   # here leaves a ghost cap slot, never an uncounted thread
    rec = {"id": tid, "owner": owner, "title": title, "metadata": metadata,
           "created_at": now, "updated_at": now, "last_seq": 0}
    store.put(_THREAD, _tkey(owner, tid), rec)       # ONE put — the row is born consistent
    return _thread_public(rec)


@router.get("")
def list_threads(limit: str = "", cursor: str = "", owner: str = Depends(require_identity)) -> dict:
    # read-scope: owner — the caller's own threads via the OWNER INDEX (never a store-wide scan), newest activity
    # first, BOUNDED through paginate. An append bumps updated_at, so an active thread rises to the head.
    rows = []
    for tid in (store.get(_INDEX, owner) or []):
        rec = store.get(_THREAD, _tkey(owner, tid))
        if rec is not None:                          # read-side check hides a create-tear ghost slot (index entry, no row)
            rows.append(rec)
    rows.sort(key=lambda r: (-r["updated_at"], -r["id"]))   # newest activity first, tie: newest id (all-integer -> x3 stable)
    page, nxt, ok = paginate([_thread_public(r) for r in rows], cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}


@router.get("/{id}")
def get_thread(id: IntPath, owner: str = Depends(require_identity)) -> dict:
    # read-scope: owner — one thread by key; the composite key includes the owner, so another owner's id is a
    # different slot -> 404 (existence never leaks). Liveness-gated on the index (a delete-tear ghost is 404).
    rec = store.get(_THREAD, _tkey(owner, id))
    if rec is None or not _in_index(owner, id):
        raise not_found("thread")
    return _thread_public(rec)


@router.patch("/{id}")
def update_thread(id: IntPath, data: ThreadIn, request: Request, owner: str = Depends(require_identity)) -> dict:
    # mutation-auth: identity — rename/retag ONE of the caller's threads. At least one field must be present ({} —
    # and, by null parity, {"title": null} — is a no-op request, rejected loudly). Messages are untouched: title
    # and metadata are the ONLY mutable state a thread has (the history itself is immutable).
    if data.title is None and data.metadata is None:
        raise invalid("nothing to update: provide title and/or metadata")
    title = _clean_title(data.title) if data.title is not None else None
    metadata = _clean_metadata(data.metadata) if data.metadata is not None else None
    now = clock.current(request)
    if not _in_index(owner, id):                     # liveness gate: absent / not-yours / delete-tear ghost -> 404
        raise not_found("thread")
    missing = False
    updated = {}

    def fn(row):
        nonlocal missing, updated
        if row is None:
            missing = True
            return None, None
        row = dict(row)
        if title is not None:
            row["title"] = title
        if metadata is not None:
            row["metadata"] = metadata
        row["updated_at"] = now
        updated = row
        return row, None

    store.do(_THREAD, _tkey(owner, id), fn)          # RMW through the atomic seam — never get-then-put
    if missing:
        raise not_found("thread")
    return _thread_public(updated)


@router.delete("/{id}", status_code=204)
def delete_thread(id: IntPath, owner: str = Depends(require_identity)) -> Response:
    # mutation-auth: identity — the cascade delete, owner-index-FIRST: (a) free the cap slot + make the thread
    # non-listable atomically (reads gate on the index), (b) remove the thread row (get/append/messages now 404),
    # (c) reap the message rows. A crash mid-cascade leaves residue only BEHIND the liveness gate (unreachable,
    # reclaimed lazily) — a deleted conversation's turns are never retrievable.
    rec = store.get(_THREAD, _tkey(owner, id))
    if rec is None or not _in_index(owner, id):      # not-yours / absent / already-deleted -> 404 (re-delete is 404)
        raise not_found("thread")

    def drop(tids):
        return [t for t in (tids or []) if t != id], None   # free the cap slot (a filtered rebuild — shrinks)

    store.do(_INDEX, owner, drop)
    fresh = store.get(_THREAD, _tkey(owner, id))     # re-read so the reap covers the freshest accepted seq
    if fresh is not None:
        rec = fresh
    store.delete_(_THREAD, _tkey(owner, id))
    for seq in range(1, rec["last_seq"] + 1):
        store.delete_(_MSG, _mkey(owner, id, seq))   # best-effort reap behind the liveness gate
    return Response(status_code=204)


@router.post("/{id}/messages", status_code=201)
def append_message(id: IntPath, data: AppendIn, request: Request, owner: str = Depends(require_identity)) -> dict:
    # mutation-auth: identity — APPEND one immutable turn to the caller's OWN thread. The seq is DERIVED: minted
    # inside ONE atomic read-modify-write on the thread row (exists-check + cap-check + last_seq+1 + updated_at
    # bump in the same transition), so racing appends serialize to distinct consecutive seqs and a smuggled body
    # seq/owner/thread_id/created_at is never read [derived: seq].
    if data.role not in _ROLES:
        raise invalid("role must be one of user|assistant|system|tool")
    content = _clean_content(data.content)
    metadata = _clean_metadata(data.metadata)
    now = clock.current(request)
    if not _in_index(owner, id):                     # liveness gate: absent / not-yours / deleted -> 404
        raise not_found("thread")
    missing, full, seq = False, False, 0

    def fn(row):
        nonlocal missing, full, seq
        if row is None:
            missing = True
            return None, None
        if row["last_seq"] >= _max_messages():
            full = True
            return None, None                        # reject past the cap — history is never evicted
        row = dict(row)
        row["last_seq"] += 1                         # the seq mint: bounded by the cap, and every increment costs an
        row["updated_at"] = now                      # accepted request, so it can never approach the integer ceiling
        seq = row["last_seq"]
        return row, None

    store.do(_THREAD, _tkey(owner, id), fn)
    if missing:
        raise not_found("thread")
    if full:
        raise invalid(f"thread is full (max {_max_messages()} messages)")
    rec = {"seq": seq, "thread_id": id, "owner": owner, "role": data.role, "content": content,
           "metadata": metadata, "created_at": now}
    store.put(_MSG, _mkey(owner, id, seq), rec)      # the slot is written ONCE, after the mint (the do callback stays
    return _message_public(rec)                      # pure); a crash between mint and write is a seq GAP — never a reorder


@router.get("/{id}/messages")
def list_messages(id: IntPath, limit: str = "", cursor: str = "", owner: str = Depends(require_identity)) -> dict:
    # read-scope: owner — the transcript in REPLAY ORDER: a direct walk of the per-seq slots up to last_seq, so the
    # order is seq ASC by construction and there is NO store-wide scan (cross-owner isolation holds by key
    # construction). Liveness-gated: absent / not-yours / deleted -> 404 (a deleted thread's orphans are unreachable).
    rec = store.get(_THREAD, _tkey(owner, id))
    if rec is None or not _in_index(owner, id):
        raise not_found("thread")
    rows = []
    for seq in range(1, rec["last_seq"] + 1):
        msg = store.get(_MSG, _mkey(owner, id, seq))
        if msg is not None:                          # a mint-tear gap is skipped (order intact, count honest)
            rows.append(_message_public(msg))
    page, nxt, ok = paginate(rows, cursor, limit)
    if not ok:
        raise invalid("invalid cursor or limit")
    return {"results": page, "next_cursor": nxt}
