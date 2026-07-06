// Package evals — a deterministic, OFFLINE scoring harness for model outputs (same ×3 as evals.py / evals.js). Store
// an IMMUTABLE owner-scoped golden SUITE (a named set of cases, each {id, scorer, expected}), then SCORE
// caller-PROVIDED outputs against it — evals NEVER calls a model. The dangerous property is SCORE-SOUNDNESS: the
// verdict is SERVER-DERIVED over a FROZEN suite (the score body carries ONLY outputs; a smuggled pass/passed is never
// read), and DETERMINISTIC ×3 — score(scorer, output, expected) is a PURE function whose per-case pass is byte-identical
// in python==go==node and reproducible across runs/restart.
//
// IDENTITY + ISOLATION, PARSE -> AUTH -> SEMANTIC (identical ×3): the body is decoded FIRST (DecodeJSON drains +
// 413/422), THEN RequireIdentity (no/invalid token -> 401), THEN field validation — so an unauthenticated,
// otherwise-422 body is 401, never a shape leak. A suite is USER-SCOPED two ways: the store key is the composite
// <owner>\x1f<name> (caller B can NEVER clobber caller A's suite name — the \x1f separator is a control char
// IsWellFormed rejects, so it can't be forged), and every read filters on the authenticated owner FIELD (not-yours ==
// 404, existence never leaks). The owner is stamped from the token, never a body field. A suite is IMMUTABLE-on-create:
// a 2nd create of the same name -> 409 via the atomic Do() claim seam.
//
// Scorers are authored HERE (the ×3 source of truth): exact/contains/starts_with/ends_with are raw code-point ops;
// iexact/icontains use an ASCII case-fold (A-Z<->a-z, non-ASCII raw — a byte-range map identical ×3; full Unicode
// casefold lives in golang.org/x/text, which the modernc-only build can't import -> v2); equals_int parses a CANONICAL
// integer bounded to ±(2^53-1) (>2^53 rejects uniformly ×3). Scoring is STATELESS; the pass verdict + integer counts
// are pinned, never a float. Regex / float-similarity / json_equal are DELIBERATELY v2.
package evals

import (
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"app/internal/core"
	"app/internal/parts/env_int"
	"app/internal/parts/paginate"
	"app/internal/parts/well_formed"
)

const evalsMaxSafeInt = 9007199254740991 // 2^53-1: the magnitude every language holds exactly

type evalsCase struct {
	Id       string `json:"id"`
	Scorer   string `json:"scorer"`
	Expected string `json:"expected"`
}

type evalsSuite struct {
	Name      string      `json:"name"`
	Owner     string      `json:"owner"` // the authenticated author; scopes every read, stamped from the token
	Cases     []evalsCase `json:"cases"`
	CaseCount int         `json:"case_count"`
	CreatedAt int         `json:"created_at"`
}

var evalsSuites = core.NewKV[string, evalsSuite]("evals_suites")

var (
	evalsMaxCases    = env_int.EnvInt(os.Getenv("EVALS_MAX_CASES"), 500, 1)
	evalsMaxExpected = env_int.EnvInt(os.Getenv("EVALS_MAX_EXPECTED_BYTES"), 8192, 1)
	evalsMaxOutput   = env_int.EnvInt(os.Getenv("EVALS_MAX_OUTPUT_BYTES"), 65536, 1)
)

// the closed scorer vocabulary — an unknown scorer is a 422 (×3 with python's Literal + node's membership check)
var evalsScorers = map[string]bool{
	"exact": true, "contains": true, "starts_with": true, "ends_with": true,
	"iexact": true, "icontains": true, "equals_int": true,
}

// [0-9] not \d (go \d is ASCII but python \d is Unicode) + no leading zero -> canonical, accept/reject identical ×3
var evalsIntRe = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// evalsAsciiFold: A-Z -> a-z, every other code point RAW (byte-range map, identical ×3 — unlike locale ToLower).
func evalsAsciiFold(s string) string {
	return strings.Map(func(ch rune) rune {
		if ch >= 'A' && ch <= 'Z' {
			return ch + 32
		}
		return ch
	}, s)
}

// evalsStrictInt: a CANONICAL integer within ±(2^53-1), else ok=false. ParseInt caps at int64 so a 20-digit number
// errors; the explicit bound rejects a magnitude in (2^53, 2^63) uniformly ×3.
func evalsStrictInt(s string) (int64, bool) {
	if !evalsIntRe.MatchString(s) {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v > evalsMaxSafeInt || v < -evalsMaxSafeInt {
		return 0, false
	}
	return v, true
}

// evalsScoreOne: the PURE deterministic verdict — a code/regex-shaped output/expected is scored as plain TEXT, never
// executed/compiled (the no-execute-the-output property). Both sides are already contained.
func evalsScoreOne(scorer, output, expected string) bool {
	switch scorer {
	case "exact":
		return output == expected
	case "contains":
		return strings.Contains(output, expected)
	case "starts_with":
		return strings.HasPrefix(output, expected)
	case "ends_with":
		return strings.HasSuffix(output, expected)
	case "iexact":
		return evalsAsciiFold(output) == evalsAsciiFold(expected)
	case "icontains":
		return strings.Contains(evalsAsciiFold(output), evalsAsciiFold(expected))
	case "equals_int":
		eo, ok1 := evalsStrictInt(output)
		ee, ok2 := evalsStrictInt(expected)
		return ok1 && ok2 && eo == ee
	}
	return false
}

func evalsMeta(s evalsSuite) map[string]any {
	return map[string]any{"name": s.Name, "owner": s.Owner, "case_count": s.CaseCount, "created_at": s.CreatedAt}
}

func EvalsCreateSuite(w http.ResponseWriter, r *http.Request) {
	// PARSE first (413/422 + drain), then AUTH (401), then SEMANTIC field validation. ×3.
	in, ok := core.DecodeJSON[struct {
		Name  *string `json:"name"`
		Cases []struct {
			Id       *string `json:"id"`
			Scorer   *string `json:"scorer"`
			Expected *string `json:"expected"` // a non-string expected fails the decode -> 422 (×3 with python StrictStr)
		} `json:"cases"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r) // authenticated mutation (no/invalid token -> 401)
	if !ok {
		return
	}
	if in.Name == nil || !well_formed.IsWellFormed(*in.Name) {
		core.WriteProblem(w, 422, "the suite name must be non-empty with no control characters")
		return
	}
	if len(in.Cases) < 1 {
		core.WriteProblem(w, 422, "a suite needs at least one case")
		return
	}
	if len(in.Cases) > evalsMaxCases {
		core.WriteProblem(w, 422, "too many cases")
		return
	}
	seen := map[string]bool{}
	cases := make([]evalsCase, 0, len(in.Cases))
	for _, c := range in.Cases {
		if c.Id == nil || !well_formed.IsWellFormed(*c.Id) {
			core.WriteProblem(w, 422, "each case id must be non-empty with no control characters")
			return
		}
		if seen[*c.Id] {
			core.WriteProblem(w, 422, "duplicate case id '"+*c.Id+"'")
			return
		}
		seen[*c.Id] = true
		if c.Scorer == nil || !evalsScorers[*c.Scorer] {
			core.WriteProblem(w, 422, "unknown scorer")
			return
		}
		if c.Expected == nil {
			core.WriteProblem(w, 422, "each case needs an expected value")
			return
		}
		if utf8.RuneCountInString(*c.Expected) > evalsMaxExpected {
			core.WriteProblem(w, 422, "a case expected value is too large")
			return
		}
		expected := well_formed.MakeWellFormed(*c.Expected) // contain BEFORE store/compare (lone surrogate -> U+FFFD)
		if *c.Scorer == "equals_int" {
			if _, valid := evalsStrictInt(expected); !valid {
				core.WriteProblem(w, 422, "an equals_int expected must be a canonical integer within the safe range")
				return
			}
		}
		cases = append(cases, evalsCase{Id: *c.Id, Scorer: *c.Scorer, Expected: expected})
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].Id < cases[j].Id }) // deterministic id-asc order ×3
	now := int(core.TestNow(r))                                                 // server clock (test seam ?now); never client-set
	record := evalsSuite{Name: *in.Name, Owner: owner, Cases: cases, CaseCount: len(cases), CreatedAt: now}
	conflict := false
	// IMMUTABLE create-once through the atomic Do() seam: two racers -> exactly one writes (201), the other -> 409.
	evalsSuites.Do(owner+"\x1f"+*in.Name, func(cur evalsSuite, exists bool) (evalsSuite, bool) {
		if exists {
			conflict = true
			return cur, false
		}
		return record, true
	})
	if conflict {
		core.WriteProblem(w, 409, "a suite with this name already exists")
		return
	}
	// expose owner + created_at (server-set — proves the mass-assign discard) + case_count (server-derived)
	core.WriteJSON(w, 201, map[string]any{"name": *in.Name, "owner": owner, "case_count": len(cases), "created_at": now})
}

func EvalsListSuites(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	// read-scope: only the caller's own suites leave the store (filtered on the authenticated owner FIELD), name-sorted
	// for a stable paged walk (All() order is NOT stable ×3), then a BOUNDED page; a stranger -> empty page, never 403.
	mine := make([]evalsSuite, 0)
	for _, s := range evalsSuites.All() {
		if s.Owner == owner {
			mine = append(mine, s)
		}
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].Name < mine[j].Name })
	views := make([]map[string]any, len(mine))
	for i, s := range mine {
		views[i] = evalsMeta(s)
	}
	q := r.URL.Query()
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

func EvalsGetSuite(w http.ResponseWriter, r *http.Request) {
	owner, ok := core.RequireIdentity(w, r) // AUTH first: a no-token probe is 401
	if !ok {
		return
	}
	name := r.PathValue("name")
	if !well_formed.IsWellFormed(name) { // a malformed name can't exist -> 404 (existence never leaks)
		core.WriteProblem(w, 404, "suite not found")
		return
	}
	s, exists := evalsSuites.Get(owner + "\x1f" + name) // cross-owner name -> different slot -> 404
	if !exists {
		core.WriteProblem(w, 404, "suite not found")
		return
	}
	core.WriteJSON(w, 200, map[string]any{"name": s.Name, "owner": s.Owner, "case_count": s.CaseCount,
		"created_at": s.CreatedAt, "cases": s.Cases})
}

func EvalsScore(w http.ResponseWriter, r *http.Request) {
	// STATELESS: score caller-PROVIDED outputs against the FROZEN suite; return the verdict, store nothing. The body
	// carries ONLY outputs -> a smuggled pass/passed/all_pass is never read (SCORE-SOUNDNESS; proven by I-SCORE-DERIVED).
	in, ok := core.DecodeJSON[struct {
		Outputs map[string]any `json:"outputs"`
	}](w, r)
	if !ok {
		return
	}
	owner, ok := core.RequireIdentity(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if !well_formed.IsWellFormed(name) {
		core.WriteProblem(w, 404, "suite not found")
		return
	}
	s, exists := evalsSuites.Get(owner + "\x1f" + name) // read-scope: cross-owner name -> 404
	if !exists {
		core.WriteProblem(w, 404, "suite not found")
		return
	}
	results := make([]map[string]any, 0, len(s.Cases))
	passed := 0
	for _, c := range s.Cases { // stored id-asc -> deterministic result order ×3
		raw, present := in.Outputs[c.Id]
		out, isStr := raw.(string)
		if !present || !isStr { // a missing or non-string output -> 422
			core.WriteProblem(w, 422, "missing or non-string output for case '"+c.Id+"'")
			return
		}
		if utf8.RuneCountInString(out) > evalsMaxOutput {
			core.WriteProblem(w, 422, "an output is too large")
			return
		}
		p := evalsScoreOne(c.Scorer, well_formed.MakeWellFormed(out), c.Expected) // contain the output BEFORE compare
		results = append(results, map[string]any{"case_id": c.Id, "pass": p})
		if p {
			passed++
		}
	}
	total := len(results) // server-derived verdict — never a client field
	core.WriteJSON(w, 200, map[string]any{"results": results, "passed": passed, "total": total, "all_pass": passed == total})
}
