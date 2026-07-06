// CENTRAL digest part — the canonical fingerprint every hashing domain shares: sha256 over the ':'-joined
// string forms of the inputs, hex-encoded. One joining-and-hashing convention, byte-identical across languages.
// Same contract as digest.py / digest.go. A complete ES module.
import { createHash } from 'node:crypto';

// digestHex = sha256 hex over ':'-joined string forms (String(int) renders exactly like str()/%v).
export function digestHex(...parts) {
  return createHash('sha256').update(parts.map(String).join(':')).digest('hex');
}

// scopedKey = a caller-scoped, COLLISION-SAFE composite slot for a client-supplied key (idempotency keys, charge
// keys, single-use codes): bind the key to the authenticated caller AND the route, so a key is PRIVATE to its
// caller. The two adversarial parts are PRE-HASHED to fixed-length colon-free hex BEFORE the outer ':'-join, so the
// join is INJECTIVE — no (caller, key) pair can forge another's slot (a bare digestHex(caller, key) would collide:
// digestHex('a:b','c') === digestHex('a','b:c')). route is a colon-free literal scoping the slot to ONE operation.
// The composition lives ONCE, here, next to digestHex. Same contract as digest.py / digest.go.
export function scopedKey(route, caller, key) {
  return digestHex(route, digestHex(caller), digestHex(key));
}
