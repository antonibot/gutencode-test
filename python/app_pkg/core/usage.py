"""Runtime `usage` — a domain-AGNOSTIC usage-metering SINK REGISTRY (dependency inversion). Core owns a generic
hook with a NO-OP default; the meter-owning domain registers its OWN recorder at import (so that domain's namespace
keeps exactly one writer and its price table stays the single cost authority); a producer domain calls usage_record()
after a billable event. INERT by default: with no sink registered every call is a no-op, so a build without a meter
domain is completely unaffected and every existing gate holds. NEVER throws — a sink failure is CONTAINED and logged
here (a broken meter must never break the request that produced the usage; availability over accounting). Mirrors the
require_identity / org_role seam posture: core carries the hook even when the owning domain is absent from a build.
Same surface + semantics in all three languages."""
import json
import os
import sys

_sink = None   # the registered recorder, or None (the no-op default)


def register_usage_sink(fn) -> None:
    """Register THE process's usage recorder (the meter-owning domain calls this at module init). Exactly ONE owner
    per process — a second registration is a loud error (a second writer would fork the single cost authority)."""
    global _sink
    if _sink is not None:
        raise RuntimeError("a usage sink is already registered (one meter owner per process)")
    _sink = fn


def _log_failure(owner: str, identifier, reason: str) -> None:
    if os.getenv("LOG_LEVEL") == "silent":
        return
    # a structured stderr line carrying the identifier + owner so an operator can REPLAY the exact event (the record
    # route is exactly-once on (owner, identifier), so a byte-identical replay is safe). stdout stays clean for probes.
    print(json.dumps({"level": "error", "event": "usage_meter_write_failed",
                      "identifier": identifier, "owner": owner, "reason": reason}), file=sys.stderr, flush=True)


def usage_record(owner: str, call: dict, now: int) -> str:
    """Record ONE usage event for `owner` (the authenticated subject the spend belongs to) through the registered
    sink. Returns a status string and NEVER raises:
      "recorded"     — the sink accepted the event;
      "no-meter"     — no sink registered in this build (the metering hook is inert — a working app, no accounting);
      "failed: <r>"  — the sink raised (an unpriced model, a store error): contained + logged HERE with the
                       identifier, so the run CONTINUES and an operator can replay the event exactly-once.
    `call` = {identifier, provider, model, <token dims>}; `now` = the caller's request clock (the stored event time)."""
    if _sink is None:
        return "no-meter"
    try:
        _sink(owner, call, now)
        return "recorded"
    except Exception as e:                     # a meter write must NEVER break the producing request (availability)
        reason = str(e)
        _log_failure(owner, call.get("identifier") if isinstance(call, dict) else None, reason)
        return "failed: " + reason
