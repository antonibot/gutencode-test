// The version LIFECYCLE for secrets_vault (package shape — same package as secrets_vault.go; see python/router.py for
// the full contract): DESTROY (irreversible, scrubs the bytes), DISABLE/ENABLE (reversible hide/show, bytes kept). All
// three share svLifecycle: auth -> version -> well_formed -> atomic Do(transition) -> audit + response.
package secrets_vault

import (
	"net/http"
	"strconv"

	"app/internal/core"
	"app/internal/parts/well_formed"
)

// svLifecycle — the shared destroy/disable/enable shape: auth+version+well_formed -> Do(transition) -> audit+response.
// transition(meta, version) returns (newStates, outcome): outcome "ok" with a non-nil map WRITES; "ok" with nil is an
// idempotent no-write; anything else is a 404. afterOK runs only on a successful write (destroy scrubs the bytes there).
func svLifecycle(w http.ResponseWriter, r *http.Request, action, successState string,
	transition func(secretsVaultMeta, int) (map[string]string, string), afterOK func(string, int)) {
	subject, ok := svRequireAdmin(w, r, action)
	if !ok {
		return
	}
	version, ok := svRequireVersion(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if !well_formed.IsWellFormed(name) {
		core.WriteProblem(w, 422, "the secret name must be non-empty with no control characters")
		return
	}
	outcome := ""
	secretsVaultMetas.Do(name, func(meta secretsVaultMeta, exists bool) (secretsVaultMeta, bool) {
		if !exists {
			outcome = "no-secret"
			return meta, false
		}
		states, oc := transition(meta, version)
		outcome = oc
		if oc != "ok" || states == nil {
			return meta, false // failure, or an idempotent no-write
		}
		meta.States = states
		return meta, true
	})
	if outcome != "ok" {
		svAudit(r, subject, action, name, version, "not_found")
		if outcome == "no-secret" {
			core.WriteProblem(w, 404, "secret not found")
		} else {
			core.WriteProblem(w, 404, "secret version not found")
		}
		return
	}
	if afterOK != nil {
		afterOK(name, version)
	}
	svAudit(r, subject, action, name, version, "allowed")
	core.WriteJSON(w, 200, map[string]any{"name": name, "version": version, "state": successState})
}

func SecretsVaultDestroy(w http.ResponseWriter, r *http.Request) {
	svLifecycle(w, r, "destroy", "destroyed", func(m secretsVaultMeta, v int) (map[string]string, string) {
		if st := svStateOf(m, v); st == "unknown" || st == "pruned" {
			return nil, "no-version"
		}
		s := svCopyStates(m.States)
		s[strconv.Itoa(v)] = "destroyed" // tombstone (idempotent; overrides 'disabled')
		return s, "ok"
	}, func(name string, v int) { secretsVaultVersions.Delete(secretsVaultVKey(name, v)) }) // scrub the plaintext
}

func SecretsVaultDisable(w http.ResponseWriter, r *http.Request) {
	svLifecycle(w, r, "disable", "disabled", func(m secretsVaultMeta, v int) (map[string]string, string) {
		if st := svStateOf(m, v); st == "unknown" || st == "pruned" || st == "destroyed" {
			return nil, "no-version"
		}
		s := svCopyStates(m.States)
		s[strconv.Itoa(v)] = "disabled"
		return s, "ok"
	}, nil)
}

func SecretsVaultEnable(w http.ResponseWriter, r *http.Request) {
	svLifecycle(w, r, "enable", "enabled", func(m secretsVaultMeta, v int) (map[string]string, string) {
		switch svStateOf(m, v) {
		case "active":
			return nil, "ok" // already enabled -> idempotent (no write)
		case "disabled":
			s := svCopyStates(m.States)
			delete(s, strconv.Itoa(v))
			return s, "ok"
		default:
			return nil, "no-version" // destroyed/pruned/unknown can't be re-enabled
		}
	}, nil)
}
