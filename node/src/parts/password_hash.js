// CENTRAL password_hash part — PBKDF2-HMAC-SHA256 password hashing for every credential domain (OWASP ASVS V2
// shape: salted, slow, constant-time verify). The pbkdf2 primitive lives HERE alone. Same contract as
// password_hash.py / password_hash.go; the three derive identical bytes. Base64 in/out so exact bytes can be
// compared. A complete, standalone ES module.
import { pbkdf2Sync, timingSafeEqual } from 'node:crypto';

const KEY_LEN = 32;

// hashPassword = base64(PBKDF2-HMAC-SHA256(password, salt, iterations)), 32-byte derived key.
export function hashPassword(password, saltB64, iterations) {
  const salt = Buffer.from(saltB64, 'base64');
  return pbkdf2Sync(password, salt, iterations, KEY_LEN, 'sha256').toString('base64');
}

// verifyPassword re-derives and compares in CONSTANT TIME (timingSafeEqual; length checked first).
export function verifyPassword(password, saltB64, iterations, hashB64) {
  const expected = Buffer.from(hashPassword(password, saltB64, iterations));
  const given = Buffer.from(hashB64 || '');
  return expected.length === given.length && timingSafeEqual(expected, given);
}
