// Package digest — the canonical fingerprint every hashing domain shares: sha256 over the ':'-joined string
// forms of the inputs, hex-encoded. One joining-and-hashing convention, byte-identical across languages, proven
// by the shared vector suite. Same contract as digest.py / digest.js.
package digest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// DigestHex = sha256 hex over ':'-joined string forms (%v renders an int exactly like str()/String()).
func DigestHex(parts ...any) string {
	rendered := make([]string, len(parts))
	for i, p := range parts {
		rendered[i] = fmt.Sprintf("%v", p)
	}
	sum := sha256.Sum256([]byte(strings.Join(rendered, ":")))
	return hex.EncodeToString(sum[:])
}

// ScopedKey = a caller-scoped, COLLISION-SAFE composite slot for a client-supplied key (idempotency keys, charge
// keys, single-use codes): bind the key to the authenticated caller AND the route, so a key is PRIVATE to its
// caller. The two adversarial parts are PRE-HASHED to fixed-length colon-free hex BEFORE the outer ':'-join, so the
// join is INJECTIVE — no (caller, key) pair can forge another's slot (a bare DigestHex(caller, key) would collide:
// DigestHex("a:b","c") == DigestHex("a","b:c")). route is a colon-free literal scoping the slot to ONE operation.
// The composition lives ONCE, here, next to DigestHex. Same contract as digest.py / digest.js.
func ScopedKey(route, caller, key string) string {
	return DigestHex(route, DigestHex(caller), DigestHex(key))
}
