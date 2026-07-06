// Package password_hash — PBKDF2-HMAC-SHA256 password hashing for every credential domain (OWASP ASVS V2 shape:
// salted, slow, constant-time verify). The pbkdf2 primitive lives HERE alone. Same contract as password_hash.py /
// password_hash.js, proven by the shared vector suite. Base64 in/out so the JSON vectors pin exact bytes.
package password_hash

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
)

const keyLen = 32

// HashPassword = base64(PBKDF2-HMAC-SHA256(password, salt, iterations)), 32-byte derived key.
func HashPassword(password, saltB64 string, iterations int) string {
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		panic("password_hash: invalid salt encoding") // a corrupt stored salt is unrecoverable — fail loud, never mis-verify
	}
	derived, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLen)
	if err != nil {
		panic("password_hash: key derivation failed")
	}
	return base64.StdEncoding.EncodeToString(derived)
}

// VerifyPassword re-derives and compares in CONSTANT TIME (hmac.Equal).
func VerifyPassword(password, saltB64 string, iterations int, hashB64 string) bool {
	return hmac.Equal([]byte(HashPassword(password, saltB64, iterations)), []byte(hashB64))
}
