// Tiny DOM + formatting helpers. No framework, no deps. Keep it boring.

// Short alias for getElementById — used everywhere.
export const $ = (id) => document.getElementById(id);

// Format a byte count as a human-readable string.
export function formatBytes(bytes) {
  if (bytes === 0 || bytes == null) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const v = bytes / Math.pow(1024, i);
  return (i === 0 ? v.toFixed(0) : v.toFixed(2)) + ' ' + units[i];
}

// Update a status line element. kind = 'ok' | 'err' | 'warn' | null.
export function setStatus(el, message, kind) {
  if (!el) return;
  el.textContent = message || '';
  el.classList.remove('status-ok', 'status-err', 'status-warn');
  if (kind === 'ok')   el.classList.add('status-ok');
  if (kind === 'err')  el.classList.add('status-err');
  if (kind === 'warn') el.classList.add('status-warn');
}

// Parse `?foo=bar&baz=qux` ignoring the fragment. Returns a plain object.
export function getQueryParams() {
  const out = {};
  const q = window.location.search.replace(/^\?/, '');
  if (!q) return out;
  for (const pair of q.split('&')) {
    if (!pair) continue;
    const [k, v] = pair.split('=');
    out[decodeURIComponent(k)] = decodeURIComponent(v || '');
  }
  return out;
}

// URL fragment (the bit after #). We use this for the tempkey — it never
// leaves the browser (not sent in Referer, not logged server-side).
export function getFragment() {
  return window.location.hash.replace(/^#/, '');
}

// Sanitise a filename so it's safe to echo into HTML / download attribute.
// Matches the archived code's allow-list.
export function safeFilename(name) {
  return String(name || '').replace(/[^A-Za-z0-9\-\_\.]/g, '');
}

// Copy text via the modern async clipboard API, with a best-effort fallback.
export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (_) {
    return false;
  }
}

// Convert a byte array to / from a hex string. Used for the clipboard
// transport (KV stores hex so we don't have to think about binary JSON).
export function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}
export function hexToBytes(hex) {
  if (!hex || hex.length % 2) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

// base64url-encode a string (used for the x-amz-meta-filename header, which
// can't contain arbitrary UTF-8 or whitespace on the wire).
export function b64url(str) {
  const utf8 = new TextEncoder().encode(str);
  let bin = '';
  for (let i = 0; i < utf8.length; i++) bin += String.fromCharCode(utf8[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Read a File object as Uint8Array. WebCrypto AES-GCM needs the whole buffer
// in memory — this is the documented 2 GB ceiling.
export function readFileBytes(file) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload  = () => resolve(new Uint8Array(fr.result));
    fr.onerror = () => reject(fr.error);
    fr.readAsArrayBuffer(file);
  });
}
