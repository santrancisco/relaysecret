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

// ---------------------------------------------------------------------------
// RSv2 — chunked encryption for large files (>500 MB).
//
// RSv2 blob layout:
//
//   offset  size   field
//   ------  -----  -------------------------------------------------------
//   0       8      magic     = "RSv2" + 4x NUL
//   8       4      chunkSize (uint32 LE, plaintext bytes per chunk)
//   12      8      totalSize (uint64 LE, total plaintext bytes)
//   20      16     salt      = PBKDF2 salt
//   36      12     baseIV    = AES-GCM base nonce (random)
//   48      ...    chunk records (repeated):
//     +0    4      ctLen     (uint32 LE, = plaintextLen + 16 GCM tag)
//     +4    N      ciphertext + 16-byte auth tag
//
// IV derivation per chunk:
//   chunkIV(i) = baseIV XOR (0^8 || uint32_le(i))
//
// Each chunk is independently AES-GCM encrypted/decrypted.
// ---------------------------------------------------------------------------

const MAGIC_V2 = new Uint8Array([0x52, 0x53, 0x76, 0x32, 0, 0, 0, 0]); // "RSv2\0\0\0\0"
const RSv2_HEADER_LEN = 48; // 8 + 4 + 8 + 16 + 12

const CHUNK_LEN_PREFIX = 4; // uint32 LE before each chunk ciphertext

// Read a uint32 LE from a byte array at offset.
function readUint32LE(buf, offset) {
  return buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16) | (buf[offset + 3] << 24);
}

// Write a uint32 LE into a byte array at offset.
function writeUint32LE(buf, offset, val) {
  buf[offset]     = val & 0xff;
  buf[offset + 1] = (val >>> 8) & 0xff;
  buf[offset + 2] = (val >>> 16) & 0xff;
  buf[offset + 3] = (val >>> 24) & 0xff;
}

// Read a uint64 LE from a byte array at offset (returned as Number — fine for ≤2^53).
function readUint64LE(buf, offset) {
  const lo = readUint32LE(buf, offset);
  const hi = readUint32LE(buf, offset + 4);
  return hi * 0x100000000 + lo;
}

// Write a uint64 LE into a byte array at offset.
function writeUint64LE(buf, offset, val) {
  const lo = val >>> 0;
  const hi = Math.floor(val / 0x100000000);
  writeUint32LE(buf, offset, lo);
  writeUint32LE(buf, offset + 4, hi);
}

// Derive a unique IV for each chunk by XORing the chunk index into the
// last 4 bytes of the base IV. This guarantees nonce uniqueness as long as
// the base IV is random (birthday bound negligible for 96-bit nonces).
function deriveChunkIV(baseIV, chunkIndex) {
  const iv = new Uint8Array(baseIV); // copy
  // XOR the little-endian chunk index into the last 4 bytes.
  iv[8]  ^= (chunkIndex & 0xff);
  iv[9]  ^= ((chunkIndex >>> 8) & 0xff);
  iv[10] ^= ((chunkIndex >>> 16) & 0xff);
  iv[11] ^= ((chunkIndex >>> 24) & 0xff);
  return iv;
}

/**
 * encryptChunked — encrypt a file in chunks via an async iterator.
 *
 * @param {AsyncIterable<Uint8Array>} chunkIterator  yields plaintext chunks
 * @param {string}  userPassword   optional password (combined with tempKey)
 * @param {string}  tempKey        URL-fragment key material
 * @param {number}  chunkSize      plaintext bytes per chunk (e.g. 128 MB)
 * @param {number}  totalSize      total plaintext file size
 * @param {function} onProgress    (encryptedBytes, totalBytes) => void
 * @returns {AsyncGenerator<Uint8Array>} yields RSv2 header then encrypted chunk records
 */
export async function* encryptChunked(chunkIterator, userPassword, tempKey, chunkSize, totalSize, onProgress) {
  const salt  = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const baseIV = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key   = await deriveKey(userPassword, tempKey, salt, 'encrypt');

  // Yield the RSv2 header first.
  const header = new Uint8Array(RSv2_HEADER_LEN);
  header.set(MAGIC_V2, 0);
  writeUint32LE(header, 8, chunkSize);
  writeUint64LE(header, 12, totalSize);
  header.set(salt, 20);
  header.set(baseIV, 36);
  yield header;

  let chunkIndex = 0;
  let encrypted = 0;

  for await (const plainChunk of chunkIterator) {
    const iv = deriveChunkIV(baseIV, chunkIndex);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plainChunk)
    );

    // Chunk record: [4-byte length prefix][ciphertext + tag]
    const record = new Uint8Array(CHUNK_LEN_PREFIX + ct.length);
    writeUint32LE(record, 0, ct.length);
    record.set(ct, CHUNK_LEN_PREFIX);
    yield record;

    encrypted += plainChunk.length;
    chunkIndex++;
    if (onProgress) onProgress(encrypted, totalSize);
  }
}

/**
 * decryptChunked — decrypt an RSv2 blob by fetching byte ranges.
 *
 * @param {Uint8Array} headerBytes   first RSv2_HEADER_LEN bytes of the object
 * @param {string}     userPassword  optional password
 * @param {string}     tempKey       URL-fragment key material
 * @param {function}   fetchRange    async (start, end) => Uint8Array
 * @param {function}   onProgress    (decryptedBytes, totalBytes) => void
 * @returns {AsyncGenerator<Uint8Array>} yields decrypted plaintext chunks
 */
export async function* decryptChunked(headerBytes, userPassword, tempKey, fetchRange, onProgress) {
  // Validate magic.
  for (let i = 0; i < MAGIC_LEN; i++) {
    if (headerBytes[i] !== MAGIC_V2[i]) {
      throw new Error('Unknown blob format (expected RSv2)');
    }
  }

  const chunkSize = readUint32LE(headerBytes, 8);
  const totalSize = readUint64LE(headerBytes, 12);
  const salt      = headerBytes.slice(20, 36);
  const baseIV    = headerBytes.slice(36, 48);

  const key = await deriveKey(userPassword, tempKey, salt, 'decrypt');

  let pos = RSv2_HEADER_LEN;
  let chunkIndex = 0;
  let decrypted = 0;

  while (decrypted < totalSize) {
    // Read the 4-byte length prefix. If we're past the end, we get 0 bytes.
    const lenBuf = await fetchRange(pos, pos + CHUNK_LEN_PREFIX);
    if (lenBuf.length === 0) break;
    const ctLen = readUint32LE(lenBuf, 0);

    // Fetch the ciphertext (ctLen includes the 16-byte GCM tag).
    const ctBuf = await fetchRange(pos + CHUNK_LEN_PREFIX, pos + CHUNK_LEN_PREFIX + ctLen);

    const iv = deriveChunkIV(baseIV, chunkIndex);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ctBuf);
    const ptArr = new Uint8Array(pt);

    yield ptArr;

    decrypted += ptArr.length;
    chunkIndex++;
    pos += CHUNK_LEN_PREFIX + ctLen;
    if (onProgress) onProgress(decrypted, totalSize);
  }
}

/**
 * detectFormat — peek at the first 8 bytes to determine RSv1 vs RSv2.
 * Returns 'v1', 'v2', or throws.
 */
export function detectFormat(header) {
  if (header.length < MAGIC_LEN) throw new Error('Header too small');
  let isV1 = true, isV2 = true;
  for (let i = 0; i < MAGIC_LEN; i++) {
    if (header[i] !== MAGIC[i])  isV1 = false;
    if (header[i] !== MAGIC_V2[i]) isV2 = false;
  }
  if (isV1) return 'v1';
  if (isV2) return 'v2';
  throw new Error('Unknown blob format');
}

/**
 * createChunkedEncryptContext — set up key, header, and per-chunk encrypt
 * for multipart upload. The caller keeps this object alive across chunks.
 *
 * Returns { header, encryptChunk(plainChunk, chunkIndex) => Uint8Array }
 *   header:       48-byte RSv2 header (upload once, before any chunks)
 *   encryptChunk: encrypt one plaintext chunk, returning [4-byte len][ct||tag]
 */
export async function createChunkedEncryptContext(userPassword, tempKey, chunkSize, totalSize) {
  const salt   = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const baseIV = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key    = await deriveKey(userPassword, tempKey, salt, 'encrypt');

  // Build the RSv2 header.
  const header = new Uint8Array(RSv2_HEADER_LEN);
  header.set(MAGIC_V2, 0);
  writeUint32LE(header, 8, chunkSize);
  writeUint64LE(header, 12, totalSize);
  header.set(salt, 20);
  header.set(baseIV, 36);

  function encryptChunk(plainChunk, chunkIndex) {
    const iv = deriveChunkIV(baseIV, chunkIndex);
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plainChunk).then(ct => {
      ct = new Uint8Array(ct);
      const record = new Uint8Array(CHUNK_LEN_PREFIX + ct.length);
      writeUint32LE(record, 0, ct.length);
      record.set(ct, CHUNK_LEN_PREFIX);
      return record;
    });
  }

  return { header, encryptChunk };
}
