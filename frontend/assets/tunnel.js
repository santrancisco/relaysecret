// tunnel.js — controller for /tunnel/. Room mode.
//
// URL format: /tunnel/?tunnelid=<16hex>#<tempkey>
//   - tempkey = sha256(userRoomName) hex (64 chars, stays in fragment)
//   - tunnelid = first 16 chars of sha256(tempkey) — a public handle the
//     Worker uses to scope R2 keys. The room name itself is never sent.
//
// If the URL has no tunnelid we prompt for a room name and redirect.

import { encryptBlob, decryptBlob, sha256Hex } from './crypto.js';
import {
  getTunnelUploadPresign, getDownloadPresign, listTunnel, deleteObject,
} from './api.js';
import {
  $, formatBytes, setStatus, getQueryParams, getFragment,
  safeFilename, readFileBytes, createProgressFlow, showImageModal,
} from './ui.js';

const REGION = 'us'; // Tunnels are pinned to us for now (matches backend default).

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
  const flow = encFlow();
  flow.show();
  flow.reset();
  let currentStep = 0;
  try {
    document.body.classList.add('busy');
    setStatus($('uploadStatus'), 'Starting…');

    flow.start(0);
    const plain = await readFileBytes(state.file);
    const filename = safeFilename($('filenameInput').value || state.file.name) || 'file.bin';
    flow.done(0);

    // Capture tempKey + password ONCE at action time, so anything that
    // happens to the input fields after this point can't mess up the
    // symmetry with the decrypt side.
    const tempKey = currentTempKey();
    const pass = readPass('encPassInput');

    currentStep = 1;
    flow.start(1); // Derive + encrypt happen together inside encryptBlob;
                   // we split them visually by flipping done(1) + start(2)
                   // right before the AES call.
    // Microtask yield so the browser paints the "active" spinner before
    // PBKDF2 blocks the main thread for ~0.8s.
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
    state.file = null;
    $('dzFileInfo').textContent = '';
    dz.classList.remove('filled');
    $('btnUpload').disabled = true;
    await refreshList();
  } catch (err) {
    console.error(err);
    flow.error(currentStep);
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

  try {
    document.body.classList.add('busy');

    flow.start(0);
    setStatus(status, 'Fetching download URL…');
    const meta = await getDownloadPresign({ region: REGION, key: f.key });
    flow.done(0);

    currentStep = 1;
    flow.start(1);
    setStatus(status, 'Downloading ciphertext…');
    const res = await fetch(meta.url);
    if (!res.ok) throw new Error('Download HTTP ' + res.status);
    const cipher = new Uint8Array(await res.arrayBuffer());
    flow.done(1);

    // Capture pass + tempkey ONCE — matches the encrypt side exactly.
    const tempKey = currentTempKey();
    const pass = readPass('decPassInput');

    currentStep = 2;
    flow.start(2);
    await new Promise((r) => setTimeout(r, 16));
    flow.done(2);

    currentStep = 3;
    flow.start(3);
    setStatus(status, 'Verifying & decrypting…');
    const plain = await decryptBlob(cipher, pass, tempKey);
    flow.done(3);

    const name = safeFilename(meta.objname || f.objname) || 'file.bin';
    const blobUrl = URL.createObjectURL(new Blob([plain], { type: 'application/octet-stream' }));
    a.href = blobUrl; a.download = name; a.classList.remove('hidden');

    const ext = name.split('.').pop().toLowerCase();
    if (['png', 'jpg', 'jpeg', 'gif', 'webp'].includes(ext)) {
      img.src = blobUrl;
      img.classList.remove('hidden');
      img.onclick = () => showImageModal(blobUrl);
    } else if (name.endsWith('.txt') || ext === 'txt') {
      ta.value = new TextDecoder().decode(plain);
      ta.classList.remove('hidden');
    }

    setStatus(status, 'Decrypted: ' + name, 'ok');

    if (meta.deleteondownload) {
      deleteObject({ region: REGION, key: f.key }).then(refreshList).catch(() => {});
    }
  } catch (err) {
    console.error(err);
    flow.error(currentStep);
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
