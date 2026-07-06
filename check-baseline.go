// check-baseline.go — offline integrity check. No Python (Go standard library only).
//
// Recomputes the sha256 of every baseline file in .gutencode/manifest.json and compares it to the printed baseline.
// This is the "is this the code I was given, unmodified?" proof — the one check you do NOT need Python for. PROTECTED
// files (the verifiers + the contract) can never be acknowledged. Exit 0 = baseline intact, 1 = tampered.
//
// Run from the export root:
//
//	go run check-baseline.go
//
// For the FULL behavioral proof (your test suite, route contract, error envelope, restart durability) run your own
// suite (`go test ./...`) and, when you have Python, `python verify.py` (it checks all three languages at once).
// Acknowledge intentional edits to a shipped file in .gutencode/accepted.json so this report stays meaningful.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func sha(p string) (string, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("%x", sha256.Sum256(b)), true
}

func main() {
	here, _ := os.Getwd() // run from the export root
	pack := filepath.Join(here, ".gutencode")
	raw, err := os.ReadFile(filepath.Join(pack, "manifest.json"))
	if err != nil {
		fmt.Println("[FAIL] .gutencode/manifest.json missing — this tree is not a verifiable export")
		os.Exit(1)
	}
	var manifest struct {
		Files       map[string]string `json:"files"`
		ContractSHA string            `json:"contract_sha256"`
	}
	if json.Unmarshal(raw, &manifest) != nil || manifest.Files == nil {
		fmt.Println("[FAIL] .gutencode/manifest.json is not readable")
		os.Exit(1)
	}
	// the verification layer — modifying any of these is never acknowledgeable
	protected := map[string]bool{"verify.py": true, "check-baseline.js": true, "check-baseline.go": true}
	accepted := map[string]bool{}
	if ab, err := os.ReadFile(filepath.Join(pack, "accepted.json")); err == nil {
		var a []string
		json.Unmarshal(ab, &a)
		for _, x := range a {
			accepted[x] = true
		}
	}

	rels := make([]string, 0, len(manifest.Files))
	for rel := range manifest.Files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	var missing, drifted, protHits []string
	for _, rel := range rels {
		got, ok := sha(filepath.Join(here, filepath.FromSlash(rel)))
		if !ok {
			if protected[rel] {
				protHits = append(protHits, rel)
			} else {
				missing = append(missing, rel)
			}
			continue
		}
		if got != manifest.Files[rel] {
			if protected[rel] {
				protHits = append(protHits, rel)
			} else if !accepted[rel] {
				drifted = append(drifted, rel)
			}
		}
	}
	if manifest.ContractSHA != "" {
		if got, ok := sha(filepath.Join(pack, "contract.json")); !ok || got != manifest.ContractSHA {
			protHits = append(protHits, ".gutencode/contract.json")
		}
	}

	fail := len(protHits) > 0 || len(missing) > 0 || len(drifted) > 0
	clip := func(s []string) []string {
		if len(s) > 5 {
			return s[:5]
		}
		return s
	}
	if len(protHits) > 0 {
		fmt.Printf("[FAIL] the verification layer was modified — never acknowledgeable: %v\n", clip(protHits))
	}
	if len(missing) > 0 {
		fmt.Printf("[FAIL] %d baseline file(s) MISSING: %v\n", len(missing), clip(missing))
	}
	if len(drifted) > 0 {
		fmt.Printf("[FAIL] %d baseline file(s) modified — acknowledge in .gutencode/accepted.json: %v\n", len(drifted), clip(drifted))
	}
	if !fail {
		fmt.Printf("[ OK ] baseline intact — %d files match .gutencode/manifest.json\n", len(manifest.Files))
	}
	verdict := "INTACT"
	if fail {
		verdict = "TAMPERED"
	}
	fmt.Printf("==== BASELINE: %s ====  (full proof: `go test ./...` + `python verify.py`)\n", verdict)
	if fail {
		os.Exit(1)
	}
}
