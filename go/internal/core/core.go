package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

// storeOpTimeout bounds every store operation's wait for the single pooled connection. A pure, fast handler never
// approaches it; it converts a HANG into a loud failure for the two contract violations that would otherwise block
// forever: a store call inside a Do() callback (the conn is held by Do — parity with python/node's reentry guard)
// and an Do callback slower than this. Generous so legitimate lock contention (busy_timeout, 5s) resolves first.
// default 10s; STORE_OP_TIMEOUT_MS tunes it (ops/tests use a small value to fail a nested call fast).
func storeOpTimeout() time.Duration {
	if ms, err := strconv.Atoi(os.Getenv("STORE_OP_TIMEOUT_MS")); err == nil && ms > 0 {
		return time.Duration(ms) * time.Millisecond
	}
	return 10 * time.Second
}

func storeCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), storeOpTimeout())
}

// NextID: ONE durable monotonic counter per name. ATOMIC: the increment happens inside the database under the
// write lock (upsert-returning), so two processes minting the same name get DISTINCT ids — never a read-then-write
// race. Parity with python next_id / node nextId; never a process-local counter — that would diverge across workers.
func NextID(name string) int {
	return driver.nextID(name)
}

// DecodeJSON: decode the request body into T, or write a problem+json error and return ok=false. EVERY write
// handler decodes HERE — the JSON body decode lives in this ONE function; never inline it in a handler. The body
// is capped by the server Wrap (MaxBytesReader); an OVERSIZE body is a 413 (parity with python/node), any other
// decode failure is a 422.
func DecodeJSON[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			WriteProblem(w, 413, "request body too large")
		} else {
			WriteProblem(w, 422, "invalid body")
		}
		return v, false
	}
	// STRICT single-value body: reject TRAILING bytes after the JSON value. json.Decoder is a STREAM decoder and
	// silently IGNORES trailing garbage (junk, or a second object) — but python's json.loads and node's JSON.parse both
	// REJECT it. Without this, a Go-only handler would accept `{...}GARBAGE` / `{a}{b}` (a malformed or ambiguous body)
	// with 201 where py/node return 422 — a cross-language parity break on EVERY write route (and on a money route it
	// drives a real capture/refund off a garbage frame). dec.More() peeks the next non-whitespace byte: true on a
	// trailing token (-> 422), false at EOF or on trailing whitespace (allowed). [×3 body-framing parity]
	if dec.More() {
		WriteProblem(w, 422, "invalid body")
		return v, false
	}
	return v, true
}

// IsIntToken: is `s` a bare JSON integer literal (optional leading '-', then digits) — NOT 5.0, 1e2, "5", true.
// The cross-language strict-integer primitive: go/node decode collapse 5 and 5.0 to one number, so strictness
// must read the raw token. Mirrors python's StrictInt (which rejects a float) and node's isStrictInt.
func IsIntToken(s string) bool {
	if s == "" || s == "-" {
		return false
	}
	for i, c := range s {
		if c == '-' && i == 0 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// RequireIntRaw: a STRICT integer from a RAW JSON field (decode an int body field as json.RawMessage, then call
// this). UNLIKE RequireInt(json.Number) — which silently accepts a QUOTED string "100" as 100, because the decoder
// stores the unquoted content in a json.Number — the raw bytes PRESERVE the quotes, so a JSON string / float / bool
// / null / a missing field are ALL rejected: only a bare integer literal passes. This is the type-strict ×3 match
// for python's StrictInt and node's isStrictInt (both reject a string-typed int). Prefer this for body int fields.
func RequireIntRaw(raw json.RawMessage) (int, bool) {
	return RequireInt(json.Number(raw)) // raw keeps the quotes on a string token, so IsIntToken rejects "100"
}

// RequireInt: a STRICT integer from a JSON number token (decode an int field as json.Number, then call this).
// Accepts ONLY an integer literal — rejecting 5.0 / 1e2 / true / null. CAUTION: json.Number unquotes a JSON string,
// so a QUOTED "5" reaches here as 5 and PASSES — for body fields that must reject a string-typed int, use
// RequireIntRaw (json.RawMessage) instead, which sees the quotes. ×3 with python StrictInt for number tokens.
// MaxSafeInt = 2^53-1 (= JS Number.MAX_SAFE_INTEGER): the largest magnitude EVERY language represents exactly. Past
// it python (arbitrary-precision) and node (a precision-lost float) silently accept while go's Atoi caps at int64 —
// so a strict body integer is bounded to this range, rejected uniformly ×3 beyond it.
const MaxSafeInt = 9007199254740991

func RequireInt(n json.Number) (int, bool) {
	if !IsIntToken(string(n)) {
		return 0, false
	}
	i, err := strconv.Atoi(string(n))
	if err != nil || i > MaxSafeInt || i < -MaxSafeInt { // also reject a magnitude past the ×3-safe range
		return 0, false
	}
	return i, true
}

// TestNow: the test-clock seam — a `now` query parameter is honored ONLY under APP_TEST_CLOCK=1 (deterministic
// tests); in production the parameter is IGNORED and real time is used. Mirrors the python and node runtimes.
func TestNow(r *http.Request) int64 {
	if os.Getenv("APP_TEST_CLOCK") == "1" {
		if v, err := strconv.ParseInt(r.URL.Query().Get("now"), 10, 64); err == nil && v > 0 {
			return v
		}
	}
	return time.Now().Unix()
}

// EnvOr: a 12-factor knob with a documented default (every knob is listed in .env.example).
func EnvOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// KV: ONE generic store for all domain state, DURABLE over the sqlite db. The namespace is an EXPLICIT string —
// the SAME name the python and node impls use — so rows map to the same logical store across languages and
// across regenerations.
type KV[K comparable, V any] struct {
	ns string
}

func NewKV[K comparable, V any](ns string) *KV[K, V] {
	return &KV[K, V]{ns: ns}
}

func (s *KV[K, V]) key(k K) string {
	// A string key is stored RAW — byte-identical to what python (store.py) and node (runtime.js) bind, so a
	// DATABASE_PATH round-trips across all three language runtimes (the store's cross-language contract). Marshaling
	// a string key (the old behavior) JSON-QUOTED it ("k"), making Go-written rows invisible to a py/node point-read
	// on a shared DB — a silent cross-language corruption. Only composite/non-string keys take the JSON encoding.
	if str, ok := any(k).(string); ok {
		return str
	}
	b, _ := json.Marshal(k)
	return string(b)
}

func (s *KV[K, V]) Get(k K) (V, bool) {
	var v V
	raw, ok := driver.get(s.ns, s.key(k))
	if !ok {
		return v, false // genuinely absent
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		panic(fmt.Sprintf("store get decode failed: %v", err)) // a corrupt row is loud (parity with python/node)
	}
	return v, true
}

func (s *KV[K, V]) Set(k K, v V) {
	b, _ := json.Marshal(v)
	driver.set(s.ns, s.key(k), string(b))
}

func (s *KV[K, V]) Delete(k K) {
	driver.del(s.ns, s.key(k))
}

func (s *KV[K, V]) All() []V {
	out := []V{}
	for _, raw := range driver.all(s.ns) {
		var v V
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			panic(fmt.Sprintf("store list decode failed: %v", err)) // a corrupt row is loud (parity with python/node)
		}
		out = append(out, v)
	}
	return out
}

// Do = ATOMIC read-modify-write of ONE key, exclusive across PROCESSES: BEGIN IMMEDIATE takes the database
// write lock BEFORE the read, so no other process can interleave between this read and this write (the old
// whole-namespace Do read outside the transaction — a lost-update race). fn(current,
// exists) returns (next, write): write=false leaves the row untouched. Results flow out via the closure. This
// is the seam for claim/consume/append logic (idempotency keys, single-use codes, chain appends) — Get-then-Set
// RACES across processes; Do does not. Mirrors python store.do / node storeDo — one single-key semantic ×3.
func (s *KV[K, V]) Do(k K, fn func(cur V, exists bool) (V, bool)) {
	// the FACADE marshals; the driver owns the txn (lock-before-read) + the reentry guard. fn MUST be pure — a
	// nested store call fails LOUD (parity with python/node's reentry guard).
	driver.do(s.ns, s.key(k), func(rawCur string, exists bool) (string, bool) {
		var cur V
		if exists {
			json.Unmarshal([]byte(rawCur), &cur)
		}
		next, write := fn(cur, exists)
		if !write {
			return "", false
		}
		b, _ := json.Marshal(next)
		return string(b), true
	})
}

// ── the cross-cutting THROTTLE seam (core-owned, store-backed) ───────────────────────────────────────────────
// A fixed-window counter every PRE-AUTH flow uses to bound abuse (login brute-force, reset/verify email-bomb)
// WITHOUT importing the ratelimit DOMAIN (boundary rule: domains -> core only) — the anti-automation seam.
type throttleWindow struct {
	Start int64 `json:"start"`
	Count int   `json:"count"`
}

var coreThrottle = NewKV[string, throttleWindow]("_throttle")

// Throttle — a fixed-window rate limit, atomic across processes (the Do seam): true if ALLOWED (count <= limit in
// the window), false if over. Parity with python store.throttle / node throttle.
func Throttle(key string, limit int, window, now int64) bool {
	allowed := false
	coreThrottle.Do(key, func(cur throttleWindow, exists bool) (throttleWindow, bool) {
		if exists && now-cur.Start < window {
			cur.Count++
			allowed = cur.Count <= limit
			return cur, true
		}
		allowed = true
		return throttleWindow{Start: now, Count: 1}, true
	})
	return allowed
}
