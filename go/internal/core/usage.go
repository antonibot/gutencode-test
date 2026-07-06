package core

// usage — a domain-AGNOSTIC usage-metering SINK REGISTRY (dependency inversion). Core owns a generic hook with a
// NO-OP default; the meter-owning domain registers its OWN recorder at init (so that domain's namespace keeps
// exactly one writer and its price table stays the single cost authority); a producer domain calls UsageRecord()
// after a billable event. INERT by default: with no sink registered every call is a no-op, so a build without a
// meter domain is completely unaffected and every existing gate holds. NEVER throws — a sink error/panic is
// CONTAINED and logged here (a broken meter must never break the request that produced the usage; availability
// over accounting). Mirrors the RequireIdentity / OrgRole seam posture. Same surface + semantics ×3.

import (
	"encoding/json"
	"fmt"
	"os"
)

// UsageCall — one billable usage event's shape (identifier + the token dimensions), domain-neutral.
type UsageCall struct {
	Identifier               string
	Provider                 string
	Model                    string
	InputTokens              int64
	OutputTokens             int64
	CacheReadInputTokens     int64
	CacheCreationInputTokens int64
	ReasoningTokens          int64
}

var usageSink func(owner string, call UsageCall, now int64) error

// RegisterUsageSink registers THE process's usage recorder (the meter-owning domain calls this from init()). Exactly
// ONE owner per process — a second registration panics loudly (a second writer would fork the single cost authority).
func RegisterUsageSink(fn func(owner string, call UsageCall, now int64) error) {
	if usageSink != nil {
		panic("a usage sink is already registered (one meter owner per process)")
	}
	usageSink = fn
}

func usageLogFailure(owner, identifier, reason string) {
	if os.Getenv("LOG_LEVEL") == "silent" {
		return
	}
	// a structured stderr line carrying the identifier + owner so an operator can REPLAY the exact event (the record
	// route is exactly-once on (owner, identifier), so a byte-identical replay is safe). stdout stays clean for probes.
	b, _ := json.Marshal(map[string]any{"level": "error", "event": "usage_meter_write_failed",
		"identifier": identifier, "owner": owner, "reason": reason})
	fmt.Fprintln(os.Stderr, string(b))
}

// UsageRecord records ONE usage event for `owner` (the authenticated subject the spend belongs to) through the
// registered sink. Returns a status string and NEVER panics: "recorded" (accepted) · "no-meter" (no sink in this
// build — the hook is inert) · "failed: <reason>" (the sink returned an error or panicked — contained + logged HERE
// with the identifier, so the run CONTINUES and an operator can replay the event exactly-once). `now` = the caller's
// request clock (the stored event time).
func UsageRecord(owner string, call UsageCall, now int64) (status string) {
	if usageSink == nil {
		return "no-meter"
	}
	defer func() { // a sink panic (e.g. a corrupt store row) must NEVER break the producing request (availability)
		if r := recover(); r != nil {
			reason := fmt.Sprintf("%v", r)
			usageLogFailure(owner, call.Identifier, reason)
			status = "failed: " + reason
		}
	}()
	if err := usageSink(owner, call, now); err != nil {
		usageLogFailure(owner, call.Identifier, err.Error())
		return "failed: " + err.Error()
	}
	return "recorded"
}
