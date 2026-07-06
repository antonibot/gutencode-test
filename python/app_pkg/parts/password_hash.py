"""CENTRAL password_hash part — PBKDF2-HMAC-SHA256 password hashing for every credential domain (OWASP ASVS V2
shape: salted, slow, constant-time verify). The pbkdf2 primitive lives HERE alone — a credential domain calls
hash_password/verify_password and never re-derives a key itself. One contract, three languages:
password_hash.go and password_hash.js implement the SAME functions; the three derive identical bytes.
Inputs/outputs are base64 strings so exact bytes can be compared across all three."""
import base64
import hashlib
import hmac

_KEY_LEN = 32


def hash_password(password: str, salt_b64: str, iterations: int) -> str:
    """PBKDF2-HMAC-SHA256(password, salt, iterations) -> base64 of the 32-byte derived key."""
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64), iterations, _KEY_LEN)
    return base64.b64encode(derived).decode()


def verify_password(password: str, salt_b64: str, iterations: int, hash_b64: str) -> bool:
    """Re-derive and compare in CONSTANT TIME — the timing of a wrong password never leaks how wrong it was."""
    return hmac.compare_digest(hash_password(password, salt_b64, iterations), hash_b64)
