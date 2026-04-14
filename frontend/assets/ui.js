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

// ------------------------------------------------------------------
// Progress flow — renders a step-by-step list showing how the app
// is protecting the user's data at each phase. No framework: pure
// DOM + CSS. Returns a small API for the caller to advance.
//
//   const flow = createProgressFlow(containerEl, [
//     'Encrypt bytes with AES-GCM-256',
//     'Request a short-lived upload URL',
//     'Upload ciphertext directly to R2',
//     'Generate share URL with fragment key',
//   ]);
//   flow.start(0);   // mark step 0 as in-progress
//   flow.done(0);    // mark step 0 as complete
//   flow.error(1);   // mark step 1 as failed
//   flow.reset();    // reset everything to pending
// ------------------------------------------------------------------
export function createProgressFlow(containerEl, steps) {
  containerEl.textContent = '';
  containerEl.classList.add('progress-flow-container');
  const ol = document.createElement('ol');
  ol.className = 'progress-flow';
  const nodes = [];
  steps.forEach((label) => {
    const li = document.createElement('li');
    li.className = 'step';
    li.dataset.state = 'pending';

    const icon = document.createElement('span');
    icon.className = 'step-icon';
    icon.setAttribute('aria-hidden', 'true');

    const text = document.createElement('span');
    text.className = 'step-label';
    text.textContent = label;

    li.append(icon, text);
    ol.append(li);
    nodes.push(li);
  });
  containerEl.append(ol);

  const setState = (i, state) => {
    const li = nodes[i];
    if (!li) return;
    li.dataset.state = state;
  };

  return {
    start: (i) => {
      // mark everything before i as done; i as active; rest as pending.
      nodes.forEach((_, j) => {
        if (j < i) setState(j, 'done');
        else if (j === i) setState(j, 'active');
        else setState(j, 'pending');
      });
    },
    done: (i) => setState(i, 'done'),
    doneAll: () => nodes.forEach((_, j) => setState(j, 'done')),
    error: (i) => setState(i, 'error'),
    reset: () => nodes.forEach((_, j) => setState(j, 'pending')),
    show: () => { containerEl.classList.remove('hidden'); },
    hide: () => { containerEl.classList.add('hidden'); },
  };
}

// ------------------------------------------------------------------
// Image modal — click a decrypted image preview to zoom it fullscreen.
// Creates one modal element lazily and reuses it. Dismiss with click
// outside, the close button, or the Escape key.
// ------------------------------------------------------------------
let _modalEl = null;
function ensureImageModal() {
  if (_modalEl) return _modalEl;
  const overlay = document.createElement('div');
  overlay.className = 'image-modal hidden';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.setAttribute('aria-label', 'Image preview');

  const content = document.createElement('div');
  content.className = 'image-modal-content';

  const img = document.createElement('img');
  img.alt = 'Decrypted image enlarged';

  const closeBtn = document.createElement('button');
  closeBtn.type = 'button';
  closeBtn.className = 'image-modal-close';
  closeBtn.setAttribute('aria-label', 'Close preview');
  closeBtn.textContent = '×';

  content.append(img, closeBtn);
  overlay.append(content);
  document.body.append(overlay);

  const hide = () => overlay.classList.add('hidden');
  overlay.addEventListener('click', (e) => { if (e.target === overlay) hide(); });
  closeBtn.addEventListener('click', hide);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !overlay.classList.contains('hidden')) hide();
  });

  _modalEl = { overlay, img };
  return _modalEl;
}

export function showImageModal(src) {
  const { overlay, img } = ensureImageModal();
  img.src = src;
  overlay.classList.remove('hidden');
}
