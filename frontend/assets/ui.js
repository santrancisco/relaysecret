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

// Yield successive Uint8Array slices from a File without loading it all at once.
// Uses File.slice() so the browser only holds one chunk in memory at a time.
export async function* fileChunkIterator(file, chunkSize) {
  let offset = 0;
  while (offset < file.size) {
    const end = Math.min(offset + chunkSize, file.size);
    const slice = file.slice(offset, end);
    yield new Uint8Array(await slice.arrayBuffer());
    offset = end;
  }
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

// ------------------------------------------------------------------
// streamDecryptedDownload — pipe an async-generator of Uint8Array chunks
// directly to a browser download, without accumulating all bytes in RAM.
//
// Strategy (in order of preference):
//   1. File System Access API (showSaveFilePicker) — truly streaming, each
//      chunk is written to disk as it arrives. Available in Chrome/Edge 86+.
//   2. ReadableStream → Response → objectURL blob — the browser streams the
//      Response body into a Blob without requiring a second full copy in JS.
//      Avoids the explicit reassembly loop. Supported everywhere.
//
// Returns { blobUrl, usedPicker } where blobUrl is null if the picker was
// used (the file was already saved), or a blob: URL if the fallback was used
// (caller should set it on an <a download> and click it).
//
// chunkGen must be an async generator yielding Uint8Array.
// onChunk(chunk) is called for each yielded chunk so the caller can update
// progress — it runs before the chunk is written/enqueued.
// ------------------------------------------------------------------
export async function streamDecryptedDownload(filename, chunkGen, onChunk) {
  // --- Path 1: File System Access API ---
  if (typeof window.showSaveFilePicker === 'function') {
    let fileHandle;
    try {
      fileHandle = await window.showSaveFilePicker({ suggestedName: filename });
    } catch (e) {
      // User cancelled the picker — propagate so the caller can handle it.
      if (e && e.name === 'AbortError') throw e;
      // Any other error (permission denied, etc.) — fall through to blob path.
      fileHandle = null;
    }
    if (fileHandle) {
      const writable = await fileHandle.createWritable();
      try {
        for await (const chunk of chunkGen) {
          if (onChunk) onChunk(chunk);
          await writable.write(chunk);
        }
        await writable.close();
      } catch (err) {
        await writable.abort();
        throw err;
      }
      return { blobUrl: null, usedPicker: true };
    }
  }

  // --- Path 2: ReadableStream → objectURL (avoids the reassembly copy) ---
  let resolve;
  const done = new Promise(r => { resolve = r; });

  const stream = new ReadableStream({
    async start(controller) {
      try {
        for await (const chunk of chunkGen) {
          if (onChunk) onChunk(chunk);
          controller.enqueue(chunk);
        }
        controller.close();
      } catch (err) {
        controller.error(err);
      } finally {
        resolve();
      }
    },
  });

  const response = new Response(stream);
  const blob = await response.blob();
  await done;
  const blobUrl = URL.createObjectURL(blob);
  return { blobUrl, usedPicker: false };
}

// ------------------------------------------------------------------
// Upload progress bar — shows a filled bar, part count, bytes, and
// an estimated speed / time remaining during multipart uploads.
//
//   const bar = createUploadProgressBar(containerEl, totalBytes);
//   bar.show();
//   bar.update(bytesUploaded, partsComplete, totalParts);
//   bar.done();    // fills to 100 % and marks complete
//   bar.error();   // shows error state
// ------------------------------------------------------------------
export function createUploadProgressBar(containerEl, totalBytes, { partLabel = 'Part' } = {}) {
  containerEl.textContent = '';
  containerEl.classList.add('upload-progress-wrap');

  const track = document.createElement('div');
  track.className = 'upload-progress-track';
  const fill = document.createElement('div');
  fill.className = 'upload-progress-fill';
  track.append(fill);

  const meta = document.createElement('div');
  meta.className = 'upload-progress-meta';

  const left = document.createElement('span');
  left.className = 'upload-progress-parts';

  const right = document.createElement('span');
  right.className = 'upload-progress-speed';

  meta.append(left, right);
  containerEl.append(track, meta);

  let startTime = null;
  let lastBytes = 0;
  let lastTime = 0;
  // Smoothed speed (exponential moving average, α=0.3)
  let smoothedSpeed = 0;

  function update(uploadedBytes, partsComplete, totalParts) {
    const now = Date.now();
    if (startTime === null) { startTime = now; lastTime = now; }

    const pct = totalBytes > 0 ? Math.min(100, (uploadedBytes / totalBytes) * 100) : 0;
    fill.style.width = pct.toFixed(1) + '%';

    left.textContent =
      partLabel + ' ' + partsComplete + ' / ' + totalParts +
      '  ·  ' + formatBytes(uploadedBytes) + ' / ' + formatBytes(totalBytes);

    // Speed: measure delta since last update, smooth it.
    const dt = (now - lastTime) / 1000;
    if (dt > 0.25) {
      const instantSpeed = (uploadedBytes - lastBytes) / dt;
      smoothedSpeed = smoothedSpeed === 0
        ? instantSpeed
        : smoothedSpeed * 0.7 + instantSpeed * 0.3;
      lastBytes = uploadedBytes;
      lastTime = now;
    }

    if (smoothedSpeed > 0) {
      const remaining = (totalBytes - uploadedBytes) / smoothedSpeed;
      right.textContent = formatBytes(smoothedSpeed) + '/s  ·  ' + formatTime(remaining);
    } else {
      right.textContent = '';
    }
  }

  function done() {
    fill.style.width = '100%';
    fill.classList.add('upload-progress-fill--done');
    left.textContent = formatBytes(totalBytes) + ' uploaded';
    right.textContent = '';
  }

  function error() {
    fill.classList.add('upload-progress-fill--error');
    right.textContent = 'Upload failed';
  }

  return {
    show:   () => { containerEl.classList.remove('hidden'); },
    hide:   () => { containerEl.classList.add('hidden'); },
    update,
    done,
    error,
  };
}

function formatTime(seconds) {
  if (!isFinite(seconds) || seconds < 0) return '';
  if (seconds < 60)  return Math.ceil(seconds) + 's';
  if (seconds < 3600) return Math.ceil(seconds / 60) + 'm';
  return (seconds / 3600).toFixed(1) + 'h';
}

export function showImageModal(src) {
  const { overlay, img } = ensureImageModal();
  img.src = src;
  overlay.classList.remove('hidden');
}
