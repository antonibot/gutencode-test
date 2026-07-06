// The SSE response MODE — the streaming sibling of WriteJSON (runtime.go). A route that declares streaming
// answers plain JSON by default and Server-Sent Events when the caller opts in per request; the two transports
// always carry the same result, so a streamed response reconstructs to exactly the sync one.
package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// WantsStream reports whether the caller opted into the Server-Sent-Events response MODE on a stream-capable
// route: the canonical `?stream=1` query flag, or an `Accept: text/event-stream` header (content negotiation,
// honored as the equivalent). Never a body field — the request body stays byte-identical between the two modes.
func WantsStream(r *http.Request) bool {
	return r.URL.Query().Get("stream") == "1" || strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}

// Stream writes a Server-Sent Events response: each text delta rides one `event: delta` frame as
// {"delta":"<text>"}, then ONE terminal `event: done` frame carries the FULL sync-shape body — so the streamed
// response always reconstructs to exactly the non-streamed one. All guards run BEFORE this is called (a
// pre-stream refusal keeps the normal problem+json envelope); a failure AFTER the first byte cannot change the
// already-sent 200, so it becomes a terminal `event: error` frame (the same problem shape, as frame data) and
// the stream closes. Every frame is flushed as written (statusRecorder forwards http.Flusher); `Cache-Control:
// no-cache` + `X-Accel-Buffering: no` tell reverse proxies not to buffer the frames (a buffering proxy is the
// #1 real-world SSE failure — also disable proxy buffering at the proxy).
func Stream(w http.ResponseWriter, deltas []string, done any) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	frame := func(event string, data any) {
		b, err := json.Marshal(data)
		if err != nil { // unmarshalable payload after the 200 is out — the honest close is the error frame
			event = "error"
			b = []byte(`{"type":"about:blank","title":"internal error","status":500,"detail":"internal error"}`)
		}
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	for _, chunk := range deltas {
		frame("delta", map[string]string{"delta": chunk})
	}
	frame("done", done)
}
