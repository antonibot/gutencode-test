// usage — a domain-AGNOSTIC usage-metering SINK REGISTRY (dependency inversion). Core owns a generic hook with a
// NO-OP default; the meter-owning domain registers its OWN recorder at import (so that domain's namespace keeps
// exactly one writer and its price table stays the single cost authority); a producer domain calls usageRecord()
// after a billable event. INERT by default: with no sink registered every call is a no-op, so a build without a
// meter domain is completely unaffected and every existing gate holds. NEVER throws — a sink failure is CONTAINED
// and logged here (a broken meter must never break the request that produced the usage; availability over
// accounting). Mirrors the requireIdentity / orgRole seam posture. Same surface + semantics ×3.

let sink = null; // the registered recorder, or null (the no-op default)

// registerUsageSink registers THE process's usage recorder (the meter-owning domain calls this at import). Exactly
// ONE owner per process — a second registration throws (a second writer would fork the single cost authority).
export function registerUsageSink(fn) {
  if (sink !== null) throw new Error('a usage sink is already registered (one meter owner per process)');
  sink = fn;
}

function logFailure(owner, identifier, reason) {
  if (process.env.LOG_LEVEL === 'silent') return;
  // a structured stderr line carrying the identifier + owner so an operator can REPLAY the exact event (the record
  // route is exactly-once on (owner, identifier), so a byte-identical replay is safe). stdout stays clean for probes.
  process.stderr.write(JSON.stringify({ level: 'error', event: 'usage_meter_write_failed',
    identifier, owner, reason }) + '\n');
}

// usageRecord records ONE usage event for `owner` (the authenticated subject the spend belongs to) through the
// registered sink. Returns a status string and NEVER throws: 'recorded' (accepted) · 'no-meter' (no sink in this
// build — the hook is inert) · 'failed: <reason>' (the sink threw — an unpriced model, a store error: contained +
// logged HERE with the identifier, so the run CONTINUES and an operator can replay the event exactly-once). `now` =
// the caller's request clock (the stored event time).
export async function usageRecord(owner, call, now) {
  if (sink === null) return 'no-meter';
  try {
    await sink(owner, call, now);
    return 'recorded';
  } catch (e) { // a meter write must NEVER break the producing request (availability)
    const reason = String((e && e.message) || e);
    logFailure(owner, call && call.identifier, reason);
    return 'failed: ' + reason;
  }
}
