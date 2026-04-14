// hmacGate.js — optional time-bound HMAC gate.
//
// This exists so an operator can limit who can request a presigned PUT URL
// without adding an account system. The frontend embeds a pair
//   `${unix_expiry}.${hex_hmac_sha256(secret, unix_expiry)}`
// into the ?exp= query param. The Worker recomputes the HMAC with the same
// shared secret and accepts the request iff:
//   1. the timestamp parses as an integer,
//   2. the timestamp is still in the future (now < exp),
//   3. HMAC-SHA256(secret, timestamp_bytes) == supplied hex (constant time).
//
// This is a direct port of `validatetime()` in aws/backend/code/lambda.py.
// We use crypto.subtle HMAC rather than pulling in a dependency so the whole
// surface stays auditable with just the WebCrypto spec open.
//
// When env.HMAC_SECRET === "none" the gate is effectively disabled.

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(b)) return null;
    out[i] = b;
  }
  return out;
}

function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}

// Timing-safe compare over equal-length byte arrays. We xor every byte and
// OR the results; any difference anywhere yields a non-zero accumulator.
function constantTimeEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function hmacSha256(secretUtf8, msgBytes) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secretUtf8),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
  return new Uint8Array(sig);
}

// Returns true if the gate is passed (either disabled or the supplied exp is
// valid and not yet expired). Shape of `exp` matches lambda.py: "<int>.<hex>".
export async function checkHmacGate(env, expParam) {
  if (!env.HMAC_SECRET || env.HMAC_SECRET === 'none') return true;
  if (typeof expParam !== 'string' || expParam.indexOf('.') < 0) return false;

  const [tsStr, sigHex] = expParam.split('.');
  const ts = parseInt(tsStr, 10);
  if (!Number.isFinite(ts)) return false;

  // Expiry check: must be in the future. Matches `int(time.time()) < t`.
  const nowSec = Math.floor(Date.now() / 1000);
  if (nowSec >= ts) return false;

  const expectedHex = sigHex.toLowerCase();
  const expectedBytes = hexToBytes(expectedHex);
  if (!expectedBytes) return false;

  // IMPORTANT: lambda.py signs the *ascii bytes of the timestamp string*
  // (not the integer). We must match that byte-for-byte.
  const actual = await hmacSha256(env.HMAC_SECRET, new TextEncoder().encode(tsStr));
  const actualHex = bytesToHex(actual);
  // Compare as raw bytes, not strings, to avoid early-exit string compare.
  return constantTimeEqual(hexToBytes(actualHex), expectedBytes);
}
