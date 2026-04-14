// keys.js — object key generation. We salt with env.SEED so knowing the time
// is not enough to guess keys; we also mix in 256 bits of crypto randomness.
// Layout matches the original lambda.py so existing lifecycle rules still apply.

const HEX = '0123456789abcdef';

function toHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += HEX[bytes[i] >> 4] + HEX[bytes[i] & 0xf];
  }
  return out;
}

async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return toHex(new Uint8Array(digest));
}

function randomHex(nBytes) {
  const buf = new Uint8Array(nBytes);
  crypto.getRandomValues(buf);
  return toHex(buf);
}

// Single-recipient key: {n}day/{64-hex}
export async function makeSendKey(expireDays, seed) {
  const entropy = `${seed}|${Date.now()}|${randomHex(32)}`;
  const hex = await sha256Hex(entropy);
  return `${expireDays}day/${hex}`;
}

// Tunnel key: 1day/{tunnelHash}/{64-hex}
export async function makeTunnelKey(tunnelHash, seed) {
  const entropy = `${seed}|${Date.now()}|${randomHex(32)}`;
  const hex = await sha256Hex(entropy);
  return `1day/${tunnelHash}/${hex}`;
}

// tunnelHash = first 16 hex chars of sha256(tunnelName). Keeps room names
// out of R2 object listings and shortens the path.
export async function tunnelHash(name) {
  const full = await sha256Hex(name);
  return full.slice(0, 16);
}

// Validation regex for incoming ?key= params. Matches both flavours.
export const KEY_REGEX = /^(\d+)day\/(?:[0-9a-f]{16}\/)?[0-9a-f]{64}$/;

// Sanitise filenames down to a safe charset before we echo them via
// x-amz-meta-* headers. We further base64url-encode upstream so non-ASCII
// can survive HTTP header transport.
export function sanitizeFilename(name) {
  if (typeof name !== 'string') return '';
  // collapse anything outside the safe set to underscore
  const cleaned = name.replace(/[^A-Za-z0-9._-]/g, '_');
  return cleaned.slice(0, 255);
}

// base64url of a utf-8 string, no padding — safe for S3 metadata headers.
export function b64urlEncode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
