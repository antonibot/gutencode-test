// Package health — the liveness probe.
package health

import (
	"net/http"

	"app/internal/core"
)

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	// read-scope: public — liveness probe, returns only {status}, no domain state.
	core.WriteJSON(w, 200, map[string]string{"status": "ok"})
}
