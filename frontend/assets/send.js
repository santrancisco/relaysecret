// send.js — controller for the root / send+receive page.
//
// Two jobs:
//   1. ENCRYPT: message or file -> AES-GCM -> PUT presigned URL -> share link
//   2. DECRYPT: when ?obj=...&region=...#tempkey is present, fetch, decrypt
//               and offer download.

import { encryptBlob, decryptBlob, randomTempKey, createChunkedEncryptContext, decryptChunked, detectFormat, RSv2_HEADER_LEN } from './crypto.js';
import {
  getUploadPresign, getDownloadPresign, getMultipartPresign, deleteObject, ApiError,
} from './api.js';
import {
  $, formatBytes, setStatus, getQueryParams, getFragment,
  safeFilename, copyToClipboard, b64url, readFileBytes,
  createProgressFlow, createUploadProgressBar, streamDecryptedDownload, showImageModal,
} from './ui.js';

// Lazy progress flow widgets for the encrypt / decrypt paths.
let _encFlow = null;
let _decFlow = null;
function encFlow() {
  if (_encFlow) return _encFlow;
  _encFlow = createProgressFlow($('encProgress'), [
    'Read message / file bytes',
    'Derive AES key (PBKDF2-SHA256, 600 000 iters)',
    'Encrypt with AES-GCM-256 in your browser',
    'Request a short-lived R2 upload URL',
    'Upload ciphertext directly to R2',
    'Build share URL (key stays in #fragment)',
  ]);
  return _encFlow;
}
function decFlow() {
  if (_decFlow) return _decFlow;
  _decFlow = createProgressFlow($('decProgress'), [
    'Request a short-lived R2 download URL',
    'Download ciphertext from R2',
    'Derive AES key (PBKDF2-SHA256, 600 000 iters)',
    'Verify auth tag & decrypt (AES-GCM-256)',
  ]);
  return _decFlow;
}

const MSG_FILENAME = 'messageinbrowser.txt';

// Files larger than CHUNK_THRESHOLD use RSv2 chunked multipart upload.
const CHUNK_THRESHOLD = 500 * 1024 * 1024; // 500 MB
const CHUNK_SIZE      = 128 * 1024 * 1024;  // 128 MB

const state = {
  mode: 'message',     // 'message' | 'file' | 'decrypt'
  file: null,          // File object when in file mode
  tempKey: '',         // 32-char hex fragment (sender side)
  // decrypt-side state:
  objKey: null,
  region: 'us',
  meta: null,          // {objsize, objname, deleteondownload}
  plaintext: null,     // Uint8Array
  origFilename: '',
};

// ---------------------------------------------------------------- tabs
function showTab(which) {
  state.mode = which;
  $('tabMsg').classList.toggle('active', which === 'message');
  $('tabFile').classList.toggle('active', which === 'file');
  $('tabDec').classList.toggle('active', which === 'decrypt');
  $('paneMsg').classList.toggle('hidden',    which !== 'message');
  $('paneFile').classList.toggle('hidden',   which !== 'file');
  $('paneDec').classList.toggle('hidden',    which !== 'decrypt');
  $('encOptions').classList.toggle('hidden', which === 'decrypt');
  $('paneResult').classList.add('hidden');
  updateEncryptButton();
}
$('tabMsg').onclick  = () => showTab('message');
$('tabFile').onclick = () => showTab('file');
$('tabDec').onclick  = () => showTab('decrypt');

// ---------------------------------------------------------------- enc button enable logic
function updateEncryptButton() {
  const btn = $('btnEncrypt');
  if (state.mode === 'message') {
    btn.disabled = $('msgInput').value.trim().length === 0;
  } else if (state.mode === 'file') {
    btn.disabled = state.file === null;
  } else {
    btn.disabled = true;
  }
}
$('msgInput').addEventListener('input', updateEncryptButton);

// ---------------------------------------------------------------- dropzone
const dz = $('dropzone');
$('dzPick').onclick = (e) => { e.preventDefault(); $('fileInput').click(); };
$('fileInput').onchange = (e) => { if (e.target.files[0]) setFile(e.target.files[0]); };
dz.addEventListener('dragover', (e) => {
  if (dz.classList.contains('locked') || dz.classList.contains('done')) return;
  e.preventDefault();
  dz.classList.add('over');
});
dz.addEventListener('dragleave', () => dz.classList.remove('over'));
dz.addEventListener('drop', (e) => {
  e.preventDefault();
  dz.classList.remove('over');
  if (!dz.classList.contains('locked') && !dz.classList.contains('done')) {
    if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
  }
});

function setFile(f) {
  state.file = f;
  $('dzFileInfo').textContent = f.name + '  (' + formatBytes(f.size) + ')';
  dz.classList.remove('done');
  dz.classList.add('filled');
  $('dzIdleContent').classList.remove('hidden');
  $('dzDoneContent').classList.add('hidden');
  $('btnUploadAnother').classList.add('hidden');
  updateEncryptButton();
}

function lockDropzone() {
  dz.classList.add('locked');
  $('btnEncrypt').disabled = true;
}

function unlockDropzone() {
  dz.classList.remove('locked');
  updateEncryptButton();
}

function showDropzoneDone(filename) {
  dz.classList.remove('locked', 'filled', 'over');
  dz.classList.add('done');
  $('dzIdleContent').classList.add('hidden');
  $('dzDoneContent').classList.remove('hidden');
  $('dzDoneName').textContent = filename;
  $('btnUploadAnother').classList.remove('hidden');
  $('btnEncrypt').disabled = true;
}

function resetDropzone() {
  state.file = null;
  dz.classList.remove('locked', 'filled', 'done', 'over');
  $('dzIdleContent').classList.remove('hidden');
  $('dzDoneContent').classList.add('hidden');
  $('dzFileInfo').textContent = '';
  $('btnUploadAnother').classList.add('hidden');
  $('fileInput').value = '';
  updateEncryptButton();
}

$('btnUploadAnother').onclick = () => {
  resetDropzone();
  // Hide the progress widgets and status from the previous upload.
  $('encProgress').classList.add('hidden');
  $('uploadBar').classList.add('hidden');
  setStatus($('encStatus'), '');
  // Keep the share URL visible so the user can still copy it.
};

// ---------------------------------------------------------------- encrypt flow
$('btnEncrypt').onclick = async () => {
  const isFile = state.mode === 'file';
  const isChunked = isFile && state.file && state.file.size > CHUNK_THRESHOLD;
  const flow = encFlow();
  flow.show();
  flow.reset();
  let currentStep = 0;
  let uploadBar = null;
  let downloadBar = null;
  try {
    document.body.classList.add('busy');

    state.tempKey = randomTempKey();
    const pass = ($('passInput').value || '').trim();
    const region = $('regionSelect').value;
    const expire = $('expireSelect').value;
    const dod = $('dodInput').checked;

    // Lock the dropzone and button for the duration of the upload.
    if (isFile) lockDropzone();

    if (isChunked) {
      // ---- RSv2 chunked multipart path ----
      const file = state.file;
      const filename = safeFilename(file.name) || 'file.bin';
      const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

      currentStep = 0;
      flow.start(0);
      setStatus($('encStatus'), 'Initiating multipart upload…');
      const mp = await getMultipartPresign({
        region, expire, filename, chunks: totalChunks, deleteOnDownload: dod,
      });
      flow.done(0);

      currentStep = 1;
      flow.start(1);
      const ctx = await createChunkedEncryptContext(pass, state.tempKey, CHUNK_SIZE, file.size);
      flow.done(1);

      currentStep = 2;
      flow.start(2);

      // --- Encrypt all parts sequentially (crypto context is stateful / ordered) ---
      //
      // Part 1 carries the 48-byte RSv2 header prepended to the chunk record.
      // To satisfy R2's requirement that all non-trailing parts have equal wire
      // size, we reduce part 1's plaintext slice by RSv2_HEADER_LEN bytes so that:
      //   part 1 wire = header(48) + lenPrefix(4) + enc(CHUNK_SIZE - 48 + 16 tag)
      //   part N wire =             lenPrefix(4) + enc(CHUNK_SIZE      + 16 tag)
      // Both equal CHUNK_SIZE + 4 + 16 bytes on the wire.
      setStatus($('encStatus'), 'Encrypting…');
      const bodies = [];
      let chunkOffset = 0;
      for (let i = 0; i < mp.partUrls.length; i++) {
        const effectiveChunkSize = (i === 0) ? CHUNK_SIZE - RSv2_HEADER_LEN : CHUNK_SIZE;
        const end = Math.min(chunkOffset + effectiveChunkSize, file.size);
        const plainChunk = new Uint8Array(await file.slice(chunkOffset, end).arrayBuffer());
        const record = await ctx.encryptChunk(plainChunk, i);
        let body = record;
        if (i === 0) {
          body = new Uint8Array(ctx.header.length + record.length);
          body.set(ctx.header, 0);
          body.set(record, ctx.header.length);
        }
        bodies.push({ index: i, partNumber: mp.partUrls[i].partNumber, url: mp.partUrls[i].url, body, plainSize: plainChunk.length });
        chunkOffset = end;
      }

      // --- Upload parts with bounded concurrency (max 3 in-flight) ---
      const CONCURRENCY = 3;
      uploadBar = createUploadProgressBar($('uploadBar'), file.size);
      uploadBar.show();
      const bar = uploadBar;
      setStatus($('encStatus'), 'Uploading…');

      const partETags = new Array(bodies.length);
      let uploadedBytes = 0;
      let partsComplete = 0;

      async function uploadPart(part) {
        const putRes = await fetch(part.url, { method: 'PUT', body: part.body });
        if (!putRes.ok) throw new Error('Part ' + part.partNumber + ' failed: HTTP ' + putRes.status);
        partETags[part.index] = { partNumber: part.partNumber, etag: putRes.headers.get('ETag') || '' };
        uploadedBytes += part.plainSize;
        partsComplete++;
        bar.update(uploadedBytes, partsComplete, bodies.length);
      }

      // Semaphore: keep up to CONCURRENCY uploads running at once.
      const inFlight = new Set();
      for (let i = 0; i < bodies.length; i++) {
        const p = uploadPart(bodies[i]);
        inFlight.add(p);
        p.finally(() => inFlight.delete(p));
        if (inFlight.size >= CONCURRENCY) {
          await Promise.race(inFlight);
        }
      }
      // Wait for all remaining in-flight uploads.
      await Promise.all(inFlight);

      bar.done();

      // Complete multipart upload — S3/R2 requires XML body with part ETags.
      const partsXml = partETags
        .map(p => `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${p.etag}</ETag></Part>`)
        .join('');
      const completeBody = `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUpload>${partsXml}</CompleteMultipartUpload>`;
      const completeRes = await fetch(mp.completeUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/xml' },
        body: completeBody,
      });
      if (!completeRes.ok) throw new Error('Complete multipart failed: HTTP ' + completeRes.status);
      flow.done(2);

      currentStep = 3;
      flow.start(3);
      showShareUrl(mp.region || region, mp.key, state.tempKey);
      flow.done(3);
      setStatus($('encStatus'), 'Encrypted end-to-end and uploaded.', 'ok');
      showDropzoneDone(safeFilename(file.name) || 'file.bin');

    } else {
      // ---- RSv1 single-shot path (messages + small files) ----
      flow.start(0);
      setStatus($('encStatus'), 'Reading input…');
      let plaintext, filename;
      if (state.mode === 'message') {
        plaintext = new TextEncoder().encode($('msgInput').value);
        filename = MSG_FILENAME;
      } else {
        if (!state.file) return;
        plaintext = await readFileBytes(state.file);
        filename = safeFilename(state.file.name) || 'file.bin';
      }
      if (plaintext.length === 0) throw new Error('Nothing to encrypt.');
      flow.done(0);

      currentStep = 1;
      flow.start(1);
      await new Promise((r) => setTimeout(r, 16));
      flow.done(1);

      currentStep = 2;
      flow.start(2);
      setStatus($('encStatus'), 'Encrypting with AES-GCM-256…');
      const blob = await encryptBlob(plaintext, pass, state.tempKey);
      flow.done(2);

      currentStep = 3;
      flow.start(3);
      setStatus($('encStatus'), 'Requesting upload URL…');
      const presign = await getUploadPresign({
        region, expire, filename, deleteOnDownload: dod,
      });
      flow.done(3);

      currentStep = 4;
      flow.start(4);
      setStatus($('encStatus'), 'Uploading ciphertext (' + formatBytes(blob.length) + ')…');
      const putRes = await fetch(presign.url, {
        method: 'PUT', headers: presign.requiredHeaders, body: blob,
      });
      if (!putRes.ok) throw new Error('Upload failed: HTTP ' + putRes.status);
      flow.done(4);

      currentStep = 5;
      flow.start(5);
      showShareUrl(presign.region || region, presign.key, state.tempKey);
      flow.done(5);
      setStatus($('encStatus'), 'Encrypted end-to-end and uploaded.', 'ok');
      if (isFile) showDropzoneDone(filename);
    }
  } catch (err) {
    console.error(err);
    flow.error(currentStep);
    if (uploadBar) uploadBar.error();
    if (downloadBar) downloadBar.error();
    if (isFile) unlockDropzone();
    setStatus($('encStatus'), err.message || 'Encryption failed.', 'err');
  } finally {
    document.body.classList.remove('busy');
  }
};

function showShareUrl(region, key, tempKey) {
  const origin = window.location.origin;
  const url = origin + '/?obj=' + encodeURIComponent(key) +
              '&region=' + encodeURIComponent(region) + '#' + tempKey;
  const block = $('shareUrlBlock');
  // Build coloured copy without innerHTML injection of user data (key/region
  // are server-provided, tempKey is locally generated — both safe).
  block.textContent = '';
  block.append(
    origin + '/?obj=',
    mkSpan(key, 'obj'),
    '&region=' + region + '#',
    mkSpan(tempKey, 'frag'),
  );
  renderQrCode(url);
  $('paneResult').classList.remove('hidden');
  $('btnCopyUrl').onclick = async () => {
    const ok = await copyToClipboard(url);
    setStatus($('encStatus'), ok ? 'URL copied to clipboard.' : 'Copy failed — select manually.', ok ? 'ok' : 'warn');
  };
  $('btnNewSend').onclick = () => {
    $('paneResult').classList.add('hidden');
    $('msgInput').value = '';
    resetDropzone();
    $('encProgress').classList.add('hidden');
    $('uploadBar').classList.add('hidden');
    setStatus($('encStatus'), '');
  };
}
function renderQrCode(url) {
  const host = $('shareQr');
  if (!host) return;
  host.textContent = '';
  if (typeof window.qrcode !== 'function') return;
  // Try increasing type numbers until the data fits. Type 0 = auto-detect
  // is not supported by this lib, so iterate manually. Error correction
  // level 'L' keeps capacity high enough for long share URLs.
  let qr = null;
  for (let type = 4; type <= 40; type++) {
    try {
      const candidate = window.qrcode(type, 'L');
      candidate.addData(url);
      candidate.make();
      qr = candidate;
      break;
    } catch (_) { /* too small, try next */ }
  }
  if (!qr) return;
  // Build the SVG as DOM nodes (not innerHTML) — the page's CSP enforces
  // Trusted Types for script sinks, which blocks innerHTML assignments.
  const SVG = 'http://www.w3.org/2000/svg';
  const count = qr.getModuleCount();
  const cell = 1;
  const margin = 2;
  const size = count * cell + margin * 2;
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('xmlns', SVG);
  svg.setAttribute('viewBox', '0 0 ' + size + ' ' + size);
  svg.setAttribute('preserveAspectRatio', 'xMinYMin meet');
  svg.setAttribute('shape-rendering', 'crispEdges');
  const bg = document.createElementNS(SVG, 'rect');
  bg.setAttribute('width', '100%');
  bg.setAttribute('height', '100%');
  bg.setAttribute('fill', 'white');
  svg.append(bg);
  let d = '';
  for (let r = 0; r < count; r++) {
    for (let c = 0; c < count; c++) {
      if (qr.isDark(r, c)) {
        const x = c * cell + margin;
        const y = r * cell + margin;
        d += 'M' + x + ',' + y + 'h' + cell + 'v' + cell + 'h-' + cell + 'z';
      }
    }
  }
  const path = document.createElementNS(SVG, 'path');
  path.setAttribute('d', d);
  path.setAttribute('fill', 'black');
  svg.append(path);
  host.append(svg);
}

function mkSpan(text, cls) {
  const s = document.createElement('span');
  s.className = cls;
  s.textContent = text;
  return s;
}

// ---------------------------------------------------------------- decrypt flow
async function initDecryptFromUrl() {
  const q = getQueryParams();
  if (!q.obj) return false;
  state.objKey = q.obj;
  state.region = q.region || 'us';
  showTab('decrypt');
  $('btnDecrypt').disabled = false;
  setStatus($('decStatus'), 'Fetching metadata…');
  try {
    state.meta = await getDownloadPresign({ region: state.region, key: state.objKey });
    state.origFilename = safeFilename(state.meta.objname || 'file.bin');
    $('decMeta').textContent =
      'File: ' + state.origFilename + ' · ' + formatBytes(state.meta.objsize) +
      ' · region ' + state.region.toUpperCase() +
      (state.meta.deleteondownload ? ' · delete-on-download' : '');
    setStatus($('decStatus'), 'Ready. Enter password (if any) and click Decrypt.');
  } catch (err) {
    const msg = err instanceof ApiError && err.status === 404
      ? 'File no longer exists or has expired.'
      : (err.message || 'Failed to load metadata.');
    setStatus($('decStatus'), msg, 'err');
    $('btnDecrypt').disabled = true;
  }
  return true;
}

$('btnDecrypt').onclick = async () => {
  if (!state.meta) return;
  const flow = decFlow();
  flow.show();
  flow.reset();
  let currentStep = 0;
  let downloadBar = null;
  try {
    document.body.classList.add('busy');
    state.plaintext = null;
    state._blobUrl = null;
    flow.done(0); // metadata already fetched

    const frag = (getFragment() || '').trim();
    const pass = ($('decPassInput').value || '').trim();
    const presignedUrl = state.meta.url;

    // Fetch the first 48 bytes to detect RSv1 vs RSv2.
    currentStep = 1;
    flow.start(1);
    setStatus($('decStatus'), 'Detecting format…');
    const headRes = await fetch(presignedUrl, { headers: { Range: 'bytes=0-47' } });
    if (!headRes.ok) throw new Error('Header fetch failed: HTTP ' + headRes.status);
    const headerBytes = new Uint8Array(await headRes.arrayBuffer());
    const format = detectFormat(headerBytes);

    if (format === 'v2') {
      // ---- RSv2 chunked decrypt — stream directly to disk ----
      setStatus($('decStatus'), 'Downloading & decrypting…');

      // Parse chunkSize and totalSize from the RSv2 header for the progress bar.
      const dv = new DataView(headerBytes.buffer);
      const chunkSize = dv.getUint32(8, true);
      const totalSize = dv.getUint32(16, true) * 0x100000000 + dv.getUint32(12, true);
      const totalChunks = chunkSize > 0 ? Math.ceil(totalSize / chunkSize) : 1;

      downloadBar = createUploadProgressBar($('downloadBar'), totalSize, { partLabel: 'Chunk' });
      downloadBar.show();

      const fetchRange = async (start, end) => {
        const r = await fetch(presignedUrl, {
          headers: { Range: `bytes=${start}-${end - 1}` },
        });
        if (!r.ok) throw new Error('Range fetch failed: HTTP ' + r.status);
        return new Uint8Array(await r.arrayBuffer());
      };

      // Stream chunks directly to disk — no full-file buffer in JS memory.
      let totalDecrypted = 0;
      let chunksDone = 0;
      const chunkGen = decryptChunked(headerBytes, pass, frag, fetchRange);
      const { blobUrl, usedPicker } = await streamDecryptedDownload(
        state.origFilename,
        chunkGen,
        (chunk) => {
          totalDecrypted += chunk.length;
          chunksDone++;
          downloadBar.update(totalDecrypted, chunksDone, totalChunks);
        },
      );
      downloadBar.done();
      flow.done(1);
      currentStep = 2;
      flow.start(2); flow.done(2); // KDF was inside decryptChunked
      currentStep = 3;
      flow.start(3); flow.done(3); // auth verified per-chunk

      // If the File System Access picker was used the file is already saved —
      // skip showDecrypted() and just show a confirmation.
      if (usedPicker) {
        $('decResult').classList.remove('hidden');
        setStatus($('decStatus'), 'Decrypted and saved.', 'ok');
        if (state.meta.deleteondownload) {
          deleteObject({ region: state.region, key: state.objKey }).catch(() => {});
        }
        return;
      }

      // Fallback: blob URL — trigger the browser save dialog via a hidden click.
      state.plaintext = null; // not in memory; use blobUrl directly
      state._blobUrl = blobUrl;
    } else {
      // ---- RSv1 single-shot decrypt ----
      setStatus($('decStatus'), 'Downloading ciphertext…');
      const res = await fetch(presignedUrl);
      if (!res.ok) throw new Error('Download failed: HTTP ' + res.status);
      const blob = new Uint8Array(await res.arrayBuffer());
      flow.done(1);

      currentStep = 2;
      flow.start(2);
      await new Promise((r) => setTimeout(r, 16));
      flow.done(2);

      currentStep = 3;
      flow.start(3);
      setStatus($('decStatus'), 'Verifying & decrypting…');
      state.plaintext = await decryptBlob(blob, pass, frag);
      flow.done(3);
    }

    await showDecrypted();
    setStatus($('decStatus'), 'Decrypted.', 'ok');

    if (state.meta.deleteondownload) {
      deleteObject({ region: state.region, key: state.objKey }).catch(() => {});
    }
  } catch (err) {
    console.error(err);
    flow.error(currentStep);
    if (downloadBar) downloadBar.error();
    setStatus($('decStatus'), 'Decrypt failed — wrong password, tampered data, or expired link.', 'err');
  } finally {
    document.body.classList.remove('busy');
  }
};

async function showDecrypted() {
  const plain = state.plaintext;       // null for streamed RSv2 downloads
  const blobUrl = state._blobUrl;      // set for fallback RSv2 path
  const filename = state.origFilename;
  const isMessage = filename === MSG_FILENAME;
  $('decResult').classList.remove('hidden');

  if (plain !== null) {
    // RSv1 / small file path — plaintext is in memory.
    if (isMessage) {
      const text = new TextDecoder().decode(plain);
      const ta = $('decMsgOut');
      ta.value = text;
      ta.classList.remove('hidden');
    }

    const url = URL.createObjectURL(new Blob([plain], { type: 'application/octet-stream' }));
    const a = $('decDownload');
    a.href = url;
    a.download = filename;
    a.classList.remove('hidden');

    // Inline preview for common image types. Click to enlarge.
    const ext = filename.split('.').pop().toLowerCase();
    if (['png', 'jpg', 'jpeg', 'gif', 'webp'].includes(ext)) {
      const img = $('decImg');
      img.src = url;
      img.classList.remove('hidden');
      img.onclick = () => showImageModal(url);
    }
  } else if (blobUrl) {
    // RSv2 fallback path — blob URL from ReadableStream, no copy in JS memory.
    const a = $('decDownload');
    a.href = blobUrl;
    a.download = filename;
    a.classList.remove('hidden');
    // Auto-trigger the save dialog immediately — no need for user to click.
    a.click();
  }

  if (!state.meta.deleteondownload) {
    const btn = $('btnDelete');
    btn.classList.remove('hidden');
    btn.onclick = async () => {
      try {
        await deleteObject({ region: state.region, key: state.objKey });
        setStatus($('decStatus'), 'Deleted from server.', 'ok');
        btn.disabled = true;
      } catch (e) {
        setStatus($('decStatus'), 'Delete failed.', 'err');
      }
    };
  }
}

// ---------------------------------------------------------------- boot
(async function main() {
  const isDecrypt = await initDecryptFromUrl();
  if (!isDecrypt) showTab('message');
})();
