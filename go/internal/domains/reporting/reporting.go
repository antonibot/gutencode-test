// Package reporting — a self-contained, owner-scoped read-side AGGREGATION store (a CQRS read model the app FEEDS; it
// does NOT read other domains' stores). Matches python/node; full dangerous-property detail in reporting.py:
// aggregation correctness ×3 · owner-scoped · derived-SUM overflow-safe at 2^53 · deterministic hash order · authenticated.
package reporting

import (
	"encoding/json"
	"net/http"
	"sort"

	"app/internal/core"
	"app/internal/parts/digest"
	"app/internal/parts/idempotent_claim"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

const reportingRoute = "POST /reporting/facts" // the owner-scoped fact-slot discriminator (same string ×3)
const reportingMax int64 = 9007199254740991    // 2^53-1: the ×3-safe integer ceiling

type reportingFact struct {
	Id         string            `json:"id"`
	Owner      string            `json:"owner"`
	Dataset    string            `json:"dataset"`
	Key        string            `json:"key"`
	Dimensions map[string]string `json:"dimensions"`
	Measures   map[string]int64  `json:"measures"`
	CreatedAt  int               `json:"created_at"`
}

var reportingKV = core.NewKV[string, reportingFact]("reporting_facts")

// state: ns "reporting_facts" keyed by the scoped_key slot (== the fact id) -> the whole record; owner-scoped + injective ×3.

func reportingH(s string) string { return digest.DigestHex(s) } // pre-hash a component (colon-free -> injective join)

// contain-BEFORE-hash then validate: surrogate -> U+FFFD, THEN reject empty/control/>1024cp. Every response-bound string incl. KEYS.
func reportingClean(s string) (string, bool) {
	c := well_formed.MakeWellFormed(s)
	if !well_formed.IsWellFormed(c) {
		return "", false
	}
	return c, true
}

type reportingAgg struct{ op, field, as string }

type reportingAggIn struct {
	Op    *string `json:"op"`
	Field *string `json:"field"`
	As    *string `json:"as"`
}

type reportingGroup struct {
	values []any // string or nil (a missing dimension) — the response key
	count  int
	sum    map[string]int64
	min    map[string]int64
	max    map[string]int64
}

func reportingPublic(f reportingFact) map[string]any {
	return map[string]any{"id": f.Id, "owner": f.Owner, "dataset": f.Dataset, "key": f.Key,
		"dimensions": f.Dimensions, "measures": f.Measures, "created_at": f.CreatedAt}
}

func ReportingFactsCreate(w http.ResponseWriter, r *http.Request) {
	in, ok := core.DecodeJSON[struct {
		Dataset    *string                    `json:"dataset"`
		Key        *string                    `json:"key"`
		Dimensions map[string]string          `json:"dimensions"` // a non-string value -> decode error -> 422 ×3
		Measures   map[string]json.RawMessage `json:"measures"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if in.Dataset == nil || in.Key == nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	dataset, dok := reportingClean(*in.Dataset)
	key, kok := reportingClean(*in.Key)
	if !dok || !kok {
		core.WriteProblem(w, 422, "dataset and key must be non-empty with no control characters")
		return
	}
	dims := map[string]string{}
	for k, v := range in.Dimensions {
		ck, ckok := reportingClean(k)
		cv, cvok := reportingClean(v)
		if !ckok || !cvok {
			core.WriteProblem(w, 422, "dimension names and values must be non-empty with no control characters")
			return
		}
		dims[ck] = cv
	}
	meas := map[string]int64{}
	for k, raw := range in.Measures {
		ck, ckok := reportingClean(k)
		iv, ivok := core.RequireIntRaw(raw)
		if !ckok || !ivok {
			core.WriteProblem(w, 422, "measure values must be integers in the safe range")
			return
		}
		meas[ck] = int64(iv)
	}
	slot := digest.ScopedKey(reportingRoute, owner, digest.DigestHex(reportingH(dataset), reportingH(key))) // it IS the id
	prior, settled := reportingKV.Get(slot)
	if !settled {
		fact := reportingFact{Id: slot, Owner: owner, Dataset: dataset, Key: key,
			Dimensions: dims, Measures: meas, CreatedAt: int(core.TestNow(r))}
		prior = idempotent_claim.ClaimOnce(reportingKV, slot, fact) // exactly-once: a repeat (dataset,key) returns the winner
	}
	core.WriteJSON(w, 201, reportingPublic(prior))
}

func ReportingFactsList(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	// SCOPED read: only the caller's own facts leave the store (owner FIELD filter, as stored — never a client value),
	// id-sorted, then a BOUNDED page; a stranger gets an empty page.
	q := r.URL.Query()
	ds := well_formed.MakeWellFormed(q.Get("dataset")) // contain the optional filter (empty = no filter)
	mine := []reportingFact{}
	for _, f := range reportingKV.All() {
		if f.Owner == owner && (ds == "" || f.Dataset == ds) {
			mine = append(mine, f)
		}
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].Id < mine[j].Id })
	views := make([]map[string]any, len(mine))
	for i, f := range mine {
		views[i] = reportingPublic(f)
	}
	page, next, valid := paginate.Paginate(views, q.Get("cursor"), q.Get("limit"))
	if !valid {
		core.WriteProblem(w, 422, "invalid cursor or limit")
		return
	}
	var nc any
	if next != "" {
		nc = next
	}
	core.WriteJSON(w, 200, map[string]any{"results": page, "next_cursor": nc})
}

// reportingValidateAggs -> the parsed aggregates, or (nil, message). Mirrors python/node byte-for-byte.
func reportingValidateAggs(in []reportingAggIn) ([]reportingAgg, string) {
	aggs, seen := []reportingAgg{}, map[string]bool{}
	for _, a := range in {
		if a.Op == nil || (*a.Op != "count" && *a.Op != "sum" && *a.Op != "min" && *a.Op != "max") {
			return nil, "unknown aggregate op"
		}
		var field, as string
		if *a.Op == "count" {
			if a.Field != nil {
				return nil, "count takes no field"
			}
			nm := "count"
			if a.As != nil {
				nm = *a.As
			}
			c, cok := reportingClean(nm)
			if !cok {
				return nil, "aggregate name must be non-empty with no control characters"
			}
			as = c
		} else {
			if a.Field == nil {
				return nil, *a.Op + " requires a field"
			}
			fc, fok := reportingClean(*a.Field)
			if !fok {
				return nil, "aggregate field must be non-empty with no control characters"
			}
			field = fc
			nm := *a.Op + "_" + field
			if a.As != nil {
				nm = *a.As
			}
			c, cok := reportingClean(nm)
			if !cok {
				return nil, "aggregate name must be non-empty with no control characters"
			}
			as = c
		}
		if seen[as] {
			return nil, "duplicate aggregate name"
		}
		seen[as] = true
		aggs = append(aggs, reportingAgg{*a.Op, field, as})
	}
	if len(aggs) == 0 {
		return nil, "at least one aggregate is required"
	}
	return aggs, ""
}

// reportingApply folds ONE fact's measures into a group; returns false on a would-be sum overflow (422). Pure (no seam call) so it may be factored.
func reportingApply(g *reportingGroup, aggs []reportingAgg, measures map[string]int64) bool {
	g.count++
	for _, a := range aggs {
		if a.op == "count" {
			continue
		}
		v, present := measures[a.field]
		if !present {
			continue
		}
		switch a.op {
		case "sum":
			acc := g.sum[a.as]
			if (v > 0 && acc > reportingMax-v) || (v < 0 && acc < -reportingMax-v) { // predict overflow BEFORE the add
				return false
			}
			g.sum[a.as] = acc + v
		case "min":
			if cur, ok := g.min[a.as]; !ok || v < cur {
				g.min[a.as] = v
			}
		case "max":
			if cur, ok := g.max[a.as]; !ok || v > cur {
				g.max[a.as] = v
			}
		}
	}
	return true
}

func ReportingQuery(w http.ResponseWriter, r *http.Request) {
	in, ok := core.DecodeJSON[struct {
		Dataset   *string  `json:"dataset"`
		GroupBy   []string `json:"group_by"` // a non-string element -> decode error -> 422 ×3
		Aggregate []reportingAggIn `json:"aggregate"`
		Filter map[string]string `json:"filter"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	if in.Dataset == nil {
		core.WriteProblem(w, 422, "invalid body")
		return
	}
	dataset, dok := reportingClean(*in.Dataset)
	if !dok {
		core.WriteProblem(w, 422, "dataset must be non-empty with no control characters")
		return
	}
	groupBy := make([]string, 0, len(in.GroupBy))
	for _, n := range in.GroupBy {
		c, cok := reportingClean(n)
		if !cok {
			core.WriteProblem(w, 422, "group_by name must be non-empty with no control characters")
			return
		}
		groupBy = append(groupBy, c)
	}
	aggs, msg := reportingValidateAggs(in.Aggregate)
	if msg != "" {
		core.WriteProblem(w, 422, msg)
		return
	}
	filt := map[string]string{}
	for k, v := range in.Filter {
		ck, ckok := reportingClean(k)
		cv, cvok := reportingClean(v)
		if !ckok || !cvok {
			core.WriteProblem(w, 422, "filter names and values must be non-empty with no control characters")
			return
		}
		filt[ck] = cv
	}
	// id-sorted so the SUM accumulation order (hence any overflow trip) is deterministic ×3; owner conjunct INLINE.
	matching := []reportingFact{}
	for _, f := range reportingKV.All() {
		if f.Owner == owner && f.Dataset == dataset && reportingMatch(f.Dimensions, filt) {
			matching = append(matching, f)
		}
	}
	sort.Slice(matching, func(i, j int) bool { return matching[i].Id < matching[j].Id })
	groups := map[string]*reportingGroup{}
	order := []string{}
	for _, f := range matching {
		values := make([]any, len(groupBy))
		parts := make([]any, len(groupBy))
		for i, n := range groupBy {
			if v, present := f.Dimensions[n]; present {
				values[i], parts[i] = v, digest.DigestHex(v)
			} else {
				values[i], parts[i] = nil, ""
			}
		}
		kh := digest.DigestHex(parts...)
		g := groups[kh]
		if g == nil {
			g = &reportingGroup{values: values, sum: map[string]int64{}, min: map[string]int64{}, max: map[string]int64{}}
			groups[kh] = g
			order = append(order, kh)
		}
		if !reportingApply(g, aggs, f.Measures) {
			core.WriteProblem(w, 422, "an aggregate sum exceeds the safe integer range")
			return
		}
	}
	sort.Strings(order) // ASCII-hex order, identical ×3
	out := []map[string]any{}
	for _, kh := range order {
		g := groups[kh]
		keyObj := map[string]any{}
		for i, n := range groupBy {
			keyObj[n] = g.values[i]
		}
		vals := map[string]any{}
		for _, a := range aggs {
			switch a.op {
			case "count":
				vals[a.as] = g.count
			case "sum":
				vals[a.as] = g.sum[a.as] // 0 if no matching value (documented)
			case "min":
				if x, ok := g.min[a.as]; ok {
					vals[a.as] = x // MIN/MAX of no values -> OMITTED
				}
			case "max":
				if x, ok := g.max[a.as]; ok {
					vals[a.as] = x
				}
			}
		}
		out = append(out, map[string]any{"key": keyObj, "values": vals})
	}
	page, next, valid := paginate.Paginate(out, r.URL.Query().Get("cursor"), r.URL.Query().Get("limit"))
	if !valid {
		core.WriteProblem(w, 422, "invalid cursor or limit")
		return
	}
	var nc any
	if next != "" {
		nc = next
	}
	core.WriteJSON(w, 200, map[string]any{"groups": page, "next_cursor": nc})
}

func reportingMatch(dims, filt map[string]string) bool {
	for fk, fv := range filt {
		if dims[fk] != fv { // a missing dim is "" != a non-empty filter value -> excluded (×3 with py .get/node ===)
			return false
		}
	}
	return true
}

func ReportingFactsDrain(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	// OWNER-scoped filtered DRAIN (relations bulk-delete precedent): dataset REQUIRED (>=1 anchor) + ?<dim>=<val> filters; owner conjunct INLINE. unbounded-safe: a filtered delete drains ALL matching.
	q := r.URL.Query()
	if q.Get("dataset") == "" {
		core.WriteProblem(w, 422, "dataset is required")
		return
	}
	dataset, dok := reportingClean(q.Get("dataset"))
	if !dok {
		core.WriteProblem(w, 422, "dataset must be non-empty with no control characters")
		return
	}
	filt := map[string]string{}
	for k := range q {
		if k == "dataset" {
			continue
		}
		ck, ckok := reportingClean(k)
		cv, cvok := reportingClean(q.Get(k))
		if !ckok || !cvok {
			core.WriteProblem(w, 422, "filter names and values must be non-empty with no control characters")
			return
		}
		filt[ck] = cv
	}
	deleted := 0
	for _, f := range reportingKV.All() {
		if f.Owner == owner && f.Dataset == dataset && reportingMatch(f.Dimensions, filt) {
			reportingKV.Delete(f.Id) // id IS the slot (deterministic scoped_key)
			deleted++
		}
	}
	core.WriteJSON(w, 200, map[string]any{"deleted": deleted})
}
