// Thin wrappers around every Worker route documented in docs/API.md.
// All URLs built from window.CONFIG.workerUrl. Every function throws
// ApiError on non-2xx so callers can branch on .code / .status.

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message || code || ('HTTP ' + status));
    this.status = status;
    this.code = code || 'HTTP_' + status;
  }
}

function base() {
  const u = (window.CONFIG && window.CONFIG.workerUrl) || '';
  return u.replace(/\/$/, '');
}

function qs(params) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null) continue;
    p.set(k, String(v));
  }
  const s = p.toString();
  return s ? '?' + s : '';
}

async function parse(res) {
  let body = null;
  try { body = await res.json(); } catch (_) { /* non-JSON */ }
  if (!res.ok) {
    const code = body && body.code;
    const msg  = body && body.error;
    throw new ApiError(res.status, code, msg);
  }
  return body;
}

async function getJSON(path, params) {
  const res = await fetch(base() + path + qs(params || {}));
  return parse(res);
}

async function postJSON(path, params) {
  const res = await fetch(base() + path + qs(params || {}), { method: 'POST' });
  return parse(res);
}

// --- R2 presign: single-recipient send ---------------------------------
export function getUploadPresign({ region, expire, filename, deleteOnDownload }) {
  return getJSON('/presign/put', {
    region, expire, filename,
    deleteOnDownload: deleteOnDownload ? 'true' : 'false',
  });
}

// --- R2 presign: tunnel/room upload (always 1 day) ---------------------
export function getTunnelUploadPresign({ region, tunnel, filename, deleteOnDownload }) {
  return getJSON('/presign/tunnel-put', {
    region, tunnel, filename,
    deleteOnDownload: deleteOnDownload ? 'true' : 'false',
  });
}

// --- R2 presign: download ---------------------------------------------
export function getDownloadPresign({ region, key }) {
  return getJSON('/presign/get', { region, key });
}

// --- R2 presign: multipart upload (large files) -----------------------
export function getMultipartPresign({ region, expire, filename, chunks, deleteOnDownload, tunnel }) {
  const params = {
    region, expire, filename, chunks,
    deleteOnDownload: deleteOnDownload ? 'true' : 'false',
  };
  if (tunnel) params.tunnel = tunnel;
  return postJSON('/presign/multipart-init', params);
}

// --- Tunnel file listing ----------------------------------------------
export function listTunnel({ region, tunnel }) {
  return getJSON('/tunnel/list', { region, tunnel });
}

// --- Delete an object (bypasses presigning) ---------------------------
export async function deleteObject({ region, key }) {
  const res = await fetch(base() + '/obj' + qs({ region, key }), { method: 'DELETE' });
  return parse(res);
}

// --- VirusTotal SHA1 proxy --------------------------------------------
export function checkSha1(hash) {
  return getJSON('/sha1/' + encodeURIComponent(hash));
}

// --- Clipboard KV -----------------------------------------------------
export function clipboardGet(id) {
  return getJSON('/clipboard/' + encodeURIComponent(id));
}

export async function clipboardPut(id, hexData) {
  const res = await fetch(base() + '/clipboard/' + encodeURIComponent(id), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data: hexData }),
  });
  return parse(res);
}
