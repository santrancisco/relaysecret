// RelaySecret crypto — WebCrypto only. No external libs.
//
// RSv1 blob layout (little-endian, but there are no multi-byte ints to worry about):
//
//   offset  size  field
//   ------  ----  -----------------------------------------------------
//   0       8     magic     = "RSv1" + 4x NUL     (ASCII, version tag)
//   8       16    salt      = PBKDF2 salt
//   24      12    iv        = AES-GCM nonce (random, unique per message)
//   36      N     ct||tag   = AES-GCM ciphertext with 16-byte auth tag
//
// Key derivation:
//   passphrase = (userPassword || "") + tempKey
//   key        = PBKDF2-HMAC-SHA256(passphrase, salt, 600_000) -> 256 bits
//
// 600k iterations matches OWASP 2023 / NIST SP 800-132 guidance. The salt is
// 16 bytes (bumped from the archived 8) and the IV is random per-message
// rather than derived, so reusing the same passphrase twice is still safe.
//
// The archived CBC+"Salted__" layout is NOT supported — this is a clean break.

const MAGIC        = new Uint8Array([0x52, 0x53, 0x76, 0x31, 0, 0, 0, 0]); // "RSv1\0\0\0\0"
const MAGIC_LEN    = 8;
const SALT_LEN     = 16;
const IV_LEN       = 12;
const HEADER_LEN   = MAGIC_LEN + SALT_LEN + IV_LEN; // 36
const PBKDF2_ITERS = 600_000;
const KEY_BITS     = 256;

const enc = new TextEncoder();

function buf2hex(buf) {
  const u = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u.length; i++) s += u[i].toString(16).padStart(2, '0');
  return s;
}

async function deriveKey(userPassword, tempKey, salt, usage) {
  const passphrase = (userPassword || '') + (tempKey || '');
  const base = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: KEY_BITS },
    false,
    [usage]
  );
}

export async function encryptBlob(plaintextBytes, userPassword, tempKey) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv   = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key  = await deriveKey(userPassword, tempKey, salt, 'encrypt');
  const ct   = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintextBytes)
  );
  const out = new Uint8Array(HEADER_LEN + ct.length);
  out.set(MAGIC, 0);
  out.set(salt, MAGIC_LEN);
  out.set(iv, MAGIC_LEN + SALT_LEN);
  out.set(ct, HEADER_LEN);
  return out;
}

export async function decryptBlob(blobBytes, userPassword, tempKey) {
  if (blobBytes.length < HEADER_LEN + 16) {
    throw new Error('Blob too small to be a valid RSv1 payload');
  }
  for (let i = 0; i < MAGIC_LEN; i++) {
    if (blobBytes[i] !== MAGIC[i]) {
      throw new Error('Unknown blob format (expected RSv1)');
    }
  }
  const salt = blobBytes.slice(MAGIC_LEN, MAGIC_LEN + SALT_LEN);
  const iv   = blobBytes.slice(MAGIC_LEN + SALT_LEN, HEADER_LEN);
  const ct   = blobBytes.slice(HEADER_LEN);
  const key  = await deriveKey(userPassword, tempKey, salt, 'decrypt');
  // AES-GCM verifies the tag; subtle.decrypt throws on tamper / wrong key.
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new Uint8Array(pt);
}

export async function sha1Hex(bytes) {
  return buf2hex(await crypto.subtle.digest('SHA-1', bytes));
}

export async function sha256Hex(str) {
  return buf2hex(await crypto.subtle.digest('SHA-256', enc.encode(str)));
}

// 32 hex chars = 128 bits of entropy. Used as the URL-fragment temp key.
export function randomTempKey() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return buf2hex(b);
}
