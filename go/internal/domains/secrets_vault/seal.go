// The at-rest SEAL for secrets_vault (package shape — same package as secrets_vault.go; see python/router.py for the
// full contract). SECRETS_VAULT_KEK unset = PASSTHROUGH (plaintext, the honest zero-dep default); set it (base64
// 32-byte) and every value is AES-256-GCM sealed. errSeal (wrong/rotated/malformed key, tampered/relocated ciphertext,
// or a value that could not be sealed) surfaces as a 500 at the call site — NEVER plaintext, NEVER garbage. Node/python
// produce the byte-identical blob (nonce+ciphertext+tag), so a blob seals/opens interchangeably across the languages.
package secrets_vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

const svSealScheme = "svgcm"
const svSealPrefix = svSealScheme + ":"

var errSeal = errors.New("secret seal/unseal failure")

// svKEK returns the at-rest KEK (base64 of 32 bytes in SECRETS_VAULT_KEK), or nil if unset (sealing OFF — the
// byte-unchanged default). A malformed key is a LOUD error, never a silent plaintext fallback.
func svKEK() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("SECRETS_VAULT_KEK"))
	if raw == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, errSeal
	}
	return key, nil
}

// svKeyver — a NON-secret key identifier (first 8 hex of sha256(key)): self-describing blob + a loud wrong-key error.
func svKeyver(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])[:8]
}

func svGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errSeal
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errSeal
	}
	return gcm, nil
}

// svSeal — KEK unset -> passthrough (identity, plaintext default). KEK set -> AES-256-GCM: random 96-bit nonce, AAD =
// name\x1fversion (a blob can NOT be replayed under another slot), blob = "svgcm:<keyver>:<b64(nonce+ciphertext+tag)>".
func svSeal(value, name string, version int) (string, error) {
	key, err := svKEK()
	if err != nil || key == nil {
		return value, err
	}
	gcm, err := svGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", errSeal
	}
	ct := gcm.Seal(nil, nonce, []byte(value), []byte(secretsVaultVKey(name, version)))
	return svSealPrefix + svKeyver(key) + ":" + base64.StdEncoding.EncodeToString(append(nonce, ct...)), nil
}

// svUnseal — the inverse. KEK unset -> passthrough. KEK set -> open a seal blob (a wrong/rotated key or a
// relocated/tampered blob is a LOUD error, never plaintext); a value with NO seal prefix is legacy plaintext (pre-KEK).
func svUnseal(stored, name string, version int) (string, error) {
	key, err := svKEK()
	if err != nil || key == nil {
		return stored, err
	}
	if !strings.HasPrefix(stored, svSealPrefix) {
		return stored, nil // legacy plaintext (pre-KEK) — read-through so enabling a KEK is non-breaking
	}
	parts := strings.SplitN(stored, ":", 3)
	if len(parts) != 3 || parts[1] != svKeyver(key) {
		return "", errSeal // malformed, or sealed under a different key
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", errSeal
	}
	gcm, err := svGCM(key)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", errSeal
	}
	pt, err := gcm.Open(nil, raw[:ns], raw[ns:], []byte(secretsVaultVKey(name, version)))
	if err != nil {
		return "", errSeal
	}
	return string(pt), nil
}
