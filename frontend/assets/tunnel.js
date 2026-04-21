// tunnel.js — controller for /tunnel/. Room mode.
//
// URL format: /tunnel/?tunnelid=<16hex>#<tempkey>
//   - tempkey = sha256(userRoomName) hex (64 chars, stays in fragment)
//   - tunnelid = first 16 chars of sha256(tempkey) — a public handle the
//     Worker uses to scope R2 keys. The room name itself is never sent.
//
// If the URL has no tunnelid we prompt for a room name and redirect.

import { encryptBlob, decryptBlob, sha256Hex, createChunkedEncryptContext, decryptChunked, detectFormat, RSv2_HEADER_LEN } from './crypto.js';
import {
  getTunnelUploadPresign, getDownloadPresign, getMultipartPresign, listTunnel, deleteObject,
} from './api.js';
import {
  $, formatBytes, setStatus, getQueryParams, getFragment,
  safeFilename, readFileBytes, createProgressFlow, createUploadProgressBar,
  streamDecryptedDownload, showImageModal,
} from './ui.js';

const REGION = 'us'; // Tunnels are pinned to us for now (matches backend default).
const CHUNK_THRESHOLD = 500 * 1024 * 1024; // 500 MB
const CHUNK_SIZE      = 128 * 1024 * 1024;  // 128 MB

const state = {
  tunnelId: '',
  file: null,
  ready: false, // true once we have a valid tunnelid + tempkey
};

// Read the tunnel temp key FRESH from the URL fragment at every action.
// Relying on a cached `state.tempKey` was causing a symmetry bug where the
// encrypt side and decrypt side could end up with different values (stale
// state, autofill on an old field, back/forward navigation, etc.).
function currentTempKey() {
  return (getFragment() || '').trim();
}

// Read+normalize a password field's value. Trim handles iOS keyboard
// autofill which can insert a leading/trailing space.
function readPass(id) {
  const el = $(id);
  return el ? (el.value || '').trim() : '';
}

// Lazily create the encrypt / decrypt progress flow widgets.
let _encFlow = null;
let _decFlow = null;
function encFlow() {
  if (_encFlow) return _encFlow;
  _encFlow = createProgressFlow($('encProgress'), [
    'Read the file from disk',
    'Derive AES key (PBKDF2-SHA256, 600 000 iters)',
    'Encrypt with AES-GCM-256 in your browser',
    'Request a short-lived R2 upload URL',
    'Upload ciphertext directly to R2',
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

// ---------------------------------------------------------------- bootstrap / room creation
async function boot() {
  const q = getQueryParams();
  const tempKey = currentTempKey();
  if (!q.tunnelid || !tempKey) {
    await createRoom();
    return;
  }
  state.tunnelId = q.tunnelid;
  state.ready = true;
  $('tunnelInfo').textContent = 'Tunnel id: ' + state.tunnelId + ' · region ' + REGION.toUpperCase();
  await refreshList();
}

function disableTunnelActions() {
  state.ready = false;
  $('btnUpload').disabled = true;
  $('btnRefresh').disabled = true;
}

async function createRoom() {
  const raw = window.prompt('Enter tunnel name (min 8 characters)');
  if (raw === null) {
    disableTunnelActions();
    setStatus($('tunnelInfo'), 'No tunnel selected. Switch to Send or Clipboard, or reload to try again.', 'err');
    return;
  }
  const name = raw.trim();
  if (name.length < 8) {
    disableTunnelActions();
    setStatus($('tunnelInfo'), 'Tunnel name must be at least 8 characters. Reload to try again.', 'err');
    return;
  }
  const tempKey = await sha256Hex(name);
  const idFull  = await sha256Hex(tempKey);
  const tunnel  = idFull.slice(0, 16);
  // Reload with the derived id + fragment. The room name never leaves the browser.
  window.location.href = window.location.pathname + '?tunnelid=' + tunnel + '#' + tempKey;
}

// ---------------------------------------------------------------- list
async function refreshList() {
  setStatus($('listStatus'), 'Loading files…');
  try {
    const files = await listTunnel({ region: REGION, tunnel: state.tunnelId });
    renderList(files || []);
    setStatus($('listStatus'), files.length + ' file(s)');
  } catch (err) {
    setStatus($('listStatus'), 'Failed to list: ' + (err.message || err), 'err');
  }
}

function renderList(files) {
  const tbody = $('fileListBody');
  tbody.textContent = '';
  if (files.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 3;
    td.className = 'muted';
    td.textContent = 'No files yet.';
    tr.append(td);
    tbody.append(tr);
    return;
  }
  for (const f of files) {
    const tr = document.createElement('tr');
    const tdName = document.createElement('td');
    tdName.className = 'name';
    tdName.textContent = safeFilename(f.objname) || '(unnamed)';
    const tdSize = document.createElement('td');
    tdSize.textContent = formatBytes(f.objsize);
    const tdActs = document.createElement('td');
    tdActs.className = 'actions';

    const btnDec = document.createElement('button');
    btnDec.textContent = 'Decrypt';
    btnDec.onclick = () => decryptOne(f);
    const btnDel = document.createElement('button');
    btnDel.textContent = 'Delete';
    btnDel.onclick = () => deleteOne(f);

    tdActs.append(btnDec, btnDel);
    tr.append(tdName, tdSize, tdActs);
    tbody.append(tr);
  }
}

$('btnRefresh').onclick = refreshList;

// ---------------------------------------------------------------- upload
const dz = $('dropzone');
$('dzPick').onclick = (e) => { e.preventDefault(); $('fileInput').click(); };
$('fileInput').onchange = (e) => { if (e.target.files[0]) setFile(e.target.files[0]); };
dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('over'); });
dz.addEventListener('dragleave', () => dz.classList.remove('over'));
dz.addEventListener('drop', (e) => {
  e.preventDefault();
  dz.classList.remove('over');
  if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
});

function setFile(f) {
  state.file = f;
  $('dzFileInfo').textContent = f.name + '  (' + formatBytes(f.size) + ')';
  $('filenameInput').value = f.name;
  dz.classList.add('filled');
  $('btnUpload').disabled = !state.ready;
}

$('btnUpload').onclick = async () => {
  if (!state.file) return;
  const isChunked = state.file.size > CHUNK_THRESHOLD;
  const flow = encFlow();
  flow.show();
  flow.reset();
  let currentStep = 0;
  let uploadBar = null;
  try {
    document.body.classList.add('busy');
    setStatus($('uploadStatus'), 'Starting…');

    const filename = safeFilename($('filenameInput').value || state.file.name) || 'file.bin';
    const tempKey = currentTempKey();
    const pass = readPass('encPassInput');

    if (isChunked) {
      // ---- RSv2 chunked multipart path ----
      const file = state.file;
      const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

      currentStep = 0;
      flow.start(0);
      setStatus($('uploadStatus'), 'Initiating multipart upload…');
      const mp = await getMultipartPresign({
        region: REGION, filename, chunks: totalChunks,
        deleteOnDownload: $('dodInput').checked, tunnel: state.tunnelId,
      });
      flow.done(0);

      currentStep = 1;
      flow.start(1);
      const ctx = await createChunkedEncryptContext(pass, tempKey, CHUNK_SIZE, file.size);
      flow.done(1);

      currentStep = 2;
      flow.start(2);

      // --- Encrypt all parts sequentially (crypto context is stateful / ordered) ---
      // Part 1 carries the RSv2 header — reduce its plaintext by RSv2_HEADER_LEN
      // bytes so all non-trailing parts have equal wire size (R2 requirement).
      setStatus($('uploadStatus'), 'Encrypting…');
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
      setStatus($('uploadStatus'), 'Uploading…');

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

      const inFlight = new Set();
      for (let i = 0; i < bodies.length; i++) {
        const p = uploadPart(bodies[i]);
        inFlight.add(p);
        p.finally(() => inFlight.delete(p));
        if (inFlight.size >= CONCURRENCY) {
          await Promise.race(inFlight);
        }
      }
      await Promise.all(inFlight);

      bar.done();
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

      setStatus($('uploadStatus'), 'Uploaded and encrypted end-to-end.', 'ok');
    } else {
      // ---- RSv1 single-shot path ----
      flow.start(0);
      const plain = await readFileBytes(state.file);
      flow.done(0);

      currentStep = 1;
      flow.start(1);
      await new Promise((r) => setTimeout(r, 16));
      flow.done(1);

      flow.start(2);
      const blob = await encryptBlob(plain, pass, tempKey);
      flow.done(2);

      currentStep = 3;
      flow.start(3);
      setStatus($('uploadStatus'), 'Requesting upload URL…');
      const p = await getTunnelUploadPresign({
        region: REGION, tunnel: state.tunnelId, filename,
        deleteOnDownload: $('dodInput').checked,
      });
      flow.done(3);

      currentStep = 4;
      flow.start(4);
      setStatus($('uploadStatus'), 'Uploading ' + formatBytes(blob.length) + '…');
      const res = await fetch(p.url, { method: 'PUT', headers: p.requiredHeaders, body: blob });
      if (!res.ok) throw new Error('Upload HTTP ' + res.status);
      flow.done(4);

      setStatus($('uploadStatus'), 'Uploaded and encrypted end-to-end.', 'ok');
    }

    state.file = null;
    $('dzFileInfo').textContent = '';
    dz.classList.remove('filled');
    $('btnUpload').disabled = true;
    await refreshList();
  } catch (err) {
    console.error(err);
    flow.error(currentStep);
    if (uploadBar) uploadBar.error();
    setStatus($('uploadStatus'), err.message || 'Upload failed.', 'err');
  } finally {
    document.body.classList.remove('busy');
  }
};

// ---------------------------------------------------------------- decrypt one
async function decryptOne(f) {
  const card = $('decCard');
  const status = $('decStatus');
  const ta = $('decMsgOut');
  const img = $('decImg');
  const a = $('decDownload');
  card.classList.remove('hidden');
  ta.classList.add('hidden'); img.classList.add('hidden'); a.classList.add('hidden');

  const flow = decFlow();
  flow.show();
  flow.reset();
  let currentStep = 0;
  let downloadBar = null;

  try {
    document.body.classList.add('busy');

    flow.start(0);
    setStatus(status, 'Fetching download URL…');
    const meta = await getDownloadPresign({ region: REGION, key: f.key });
    flow.done(0);

    currentStep = 1;
    flow.start(1);

    // Capture pass + tempkey ONCE — matches the encrypt side exactly.
    const tempKey = currentTempKey();
    const pass = readPass('decPassInput');

    // Detect format via first 48 bytes.
    setStatus(status, 'Detecting format…');
    const headRes = await fetch(meta.url, { headers: { Range: 'bytes=0-47' } });
    if (!headRes.ok) throw new Error('Header fetch failed: HTTP ' + headRes.status);
    const headerBytes = new Uint8Array(await headRes.arrayBuffer());
    const format = detectFormat(headerBytes);

    const name = safeFilename(meta.objname || f.objname) || 'file.bin';
    let plain = null;

    if (format === 'v2') {
      // ---- RSv2 chunked decrypt — stream directly to disk ----
      setStatus(status, 'Downloading & decrypting…');

      const dv = new DataView(headerBytes.buffer);
      const chunkSize = dv.getUint32(8, true);
      const totalSize = dv.getUint32(16, true) * 0x100000000 + dv.getUint32(12, true);
      const totalChunks = chunkSize > 0 ? Math.ceil(totalSize / chunkSize) : 1;

      downloadBar = createUploadProgressBar($('downloadBar'), totalSize, { partLabel: 'Chunk' });
      downloadBar.show();

      const fetchRange = async (start, end) => {
        const r = await fetch(meta.url, {
          headers: { Range: `bytes=${start}-${end - 1}` },
        });
        if (!r.ok) throw new Error('Range fetch failed: HTTP ' + r.status);
        return new Uint8Array(await r.arrayBuffer());
      };

      let totalDecrypted = 0;
      let chunksDone = 0;
      const chunkGen = decryptChunked(headerBytes, pass, tempKey, fetchRange);
      const { blobUrl, usedPicker } = await streamDecryptedDownload(
        name,
        chunkGen,
        (chunk) => {
          totalDecrypted += chunk.length;
          chunksDone++;
          downloadBar.update(totalDecrypted, chunksDone, totalChunks);
        },
      );
      downloadBar.done();
      flow.done(1);
      currentStep = 2; flow.start(2); flow.done(2);
      currentStep = 3; flow.start(3); flow.done(3);

      if (usedPicker) {
        setStatus(status, 'Decrypted and saved: ' + name, 'ok');
      } else {
        a.href = blobUrl; a.download = name; a.classList.remove('hidden');
        a.click(); // auto-trigger save dialog
        setStatus(status, 'Decrypted: ' + name, 'ok');
      }
    } else {
      // ---- RSv1 single-shot decrypt (small files only) ----
      setStatus(status, 'Downloading ciphertext…');
      const res = await fetch(meta.url);
      if (!res.ok) throw new Error('Download HTTP ' + res.status);
      const cipher = new Uint8Array(await res.arrayBuffer());
      flow.done(1);

      currentStep = 2;
      flow.start(2);
      await new Promise((r) => setTimeout(r, 16));
      flow.done(2);

      currentStep = 3;
      flow.start(3);
      setStatus(status, 'Verifying & decrypting…');
      plain = await decryptBlob(cipher, pass, tempKey);
      flow.done(3);

      const url = URL.createObjectURL(new Blob([plain], { type: 'application/octet-stream' }));
      a.href = url; a.download = name; a.classList.remove('hidden');

      const ext = name.split('.').pop().toLowerCase();
      if (['png', 'jpg', 'jpeg', 'gif', 'webp'].includes(ext)) {
        img.src = url;
        img.classList.remove('hidden');
        img.onclick = () => showImageModal(url);
      } else if (name.endsWith('.txt') || ext === 'txt') {
        ta.value = new TextDecoder().decode(plain);
        ta.classList.remove('hidden');
      }

      setStatus(status, 'Decrypted: ' + name, 'ok');
    }

    if (meta.deleteondownload) {
      deleteObject({ region: REGION, key: f.key }).then(refreshList).catch(() => {});
    }
  } catch (err) {
    console.error(err);
    flow.error(currentStep);
    if (downloadBar) downloadBar.error();
    const isCrypto = err && /decrypt|OperationError|tag/i.test(String(err && err.message || err));
    setStatus(
      status,
      isCrypto
        ? 'Decrypt failed — wrong password, or the uploader used a password you need to type in.'
        : (err.message || 'Decrypt failed.'),
      'err'
    );
  } finally {
    document.body.classList.remove('busy');
  }
}

async function deleteOne(f) {
  try {
    await deleteObject({ region: REGION, key: f.key });
    setStatus($('listStatus'), 'Deleted.', 'ok');
    await refreshList();
  } catch (err) {
    setStatus($('listStatus'), 'Delete failed.', 'err');
  }
}

boot();
