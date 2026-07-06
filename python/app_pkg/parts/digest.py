"""CENTRAL digest part — the canonical fingerprint every hashing domain shares: sha256 over the ':'-joined
string forms of the inputs, hex-encoded. ONE joining-and-hashing convention means a chain link
(audit_log: prev:id:action), a body fingerprint (idempotency: amount:N), and a charge fingerprint
(stripe: amount:N:currency:C) are all the SAME composition — and cross-language byte-identity is proven once,
here, by the shared vectors, instead of three times in three domains."""
import hashlib


def digest_hex(*parts) -> str:
    """sha256 hex over ':'-joined string forms — str(int) and a string render identically in all three languages."""
    return hashlib.sha256(":".join(str(p) for p in parts).encode()).hexdigest()


def scoped_key(route: str, caller: str, key: str) -> str:
    """A caller-scoped, COLLISION-SAFE composite slot for a client-supplied key (idempotency keys, charge keys,
    single-use codes): bind the key to the authenticated `caller` AND the `route`, so a key is PRIVATE to its caller
    — caller B can never replay, nor be blocked by, caller A's slot. The two adversarial parts (caller, key) are
    PRE-HASHED to fixed-length colon-free hex BEFORE the outer ':'-join, so the join is INJECTIVE — no (caller, key)
    pair can forge another's slot. A bare digest_hex(caller, key) would COLLIDE: digest_hex("a:b","c") ==
    digest_hex("a","b:c"); pre-hashing each part defeats that (the rbac tuple-delimiter / KEY-FORGERY class). `route`
    is a colon-free literal that scopes the slot to ONE operation. The composition lives ONCE, here, next to
    digest_hex — every consumer (idempotency, stripe, …) inherits it instead of copying the incantation."""
    return digest_hex(route, digest_hex(caller), digest_hex(key))
