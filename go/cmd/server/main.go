package main

import (
	"net/http"
	"os"
	"time"

	"app/internal/app"
)

func main() {
	port := "8080"
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}
	// Bind LOOPBACK by default: a dev/test server should not listen on every interface (it also makes desktop
	// firewalls prompt on every run). Deployments set HOST=0.0.0.0 (or the pod IP) explicitly.
	host := "127.0.0.1"
	if h := os.Getenv("HOST"); h != "" {
		host = h
	}
	addr := host + ":" + port
	// Timeouts are mandatory in production: a server with no read/write deadline is a slow-loris DoS target. The two
	// knobs node also has (headers + whole-request) MATCH node's server.headersTimeout/requestTimeout for ×3 wall-clock
	// parity; WriteTimeout/IdleTimeout are go-server knobs node manages differently. (The 1 MiB body cap is the shared
	// ×3 DoS guard; python's request timeout is a uvicorn deployment flag, not app code.)
	srv := &http.Server{
		Addr:              addr,
		Handler:           app.NewServer(),
		ReadHeaderTimeout: 10 * time.Second, // == node server.headersTimeout
		ReadTimeout:       30 * time.Second, // == node server.requestTimeout (generous enough for a slow 1 MiB upload)
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	_ = srv.ListenAndServe()
}
