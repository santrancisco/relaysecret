// tunnel.js — controller for /tunnel/. Room mode.
//
// URL format: /tunnel/?tunnelid=<16hex>#<tempkey>
//   - tempkey = sha256(userRoomName) hex (64 chars, stays in fragment)
//   - tunnelid = first 16 chars of sha256(tempkey) — a public handle the
//     Worker uses to scope R2 keys. The room name itself is never sent.
//
// If the URL has no tunnelid we prompt for a room name and redirect.

import { encryptBlob, decryptBlob, sha1Hex, sha256Hex } from './crypto.js';
import {
  getTunnelUploadPresign, getDownloadPresign, listTunnel, deleteObject, checkSha1,
} from './api.js';
import {
  $, formatBytes, setStatus, getQueryParams, getFragment,
  safeFilename, readFileBytes,
} from './ui.js';

const REGION = 'us'; // Tunnels are pinned to us for now (matches backend default).

const state = {
  tunnelId: '',
  tempKey: '',
  file: null,
};

// ---------------------------------------------------------------- bootstrap / room creation
async function boot() {
  const q = getQueryParams();
  state.tempKey = getFragment();
  if (!q.tunnelid || !state.tempKey) {
    await createRoom();
    return;
  }
  state.tunnelId = q.tunnelid;
  $('tunnelInfo').textContent = 'Tunnel id: ' + state.tunnelId + ' · region ' + REGION.toUpperCase();
  await refreshList();
}

async function createRoom() {
  let name = '';
  while (name.length < 8) {
    name = window.prompt('Enter tunnel name (min 8 characters)') || '';
    if (name === null) return;
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
  $('btnUpload').disabled = false;
}

$('btnUpload').onclick = async () => {
  if (!state.file) return;
  try {
    document.body.classList.add('busy');
    setStatus($('uploadStatus'), 'Reading file…');
    const plain = await readFileBytes(state.file);
    const filename = safeFilename($('filenameInput').value || state.file.name) || 'file.bin';

    setStatus($('uploadStatus'), 'Encrypting…');
    const blob = await encryptBlob(plain, $('passInput').value, state.tempKey);

    setStatus($('uploadStatus'), 'Requesting upload URL…');
    const p = await getTunnelUploadPresign({
      region: REGION, tunnel: state.tunnelId, filename,
      deleteOnDownload: $('dodInput').checked,
    });

    setStatus($('uploadStatus'), 'Uploading ' + formatBytes(blob.length) + '…');
    const res = await fetch(p.url, { method: 'PUT', headers: p.requiredHeaders, body: blob });
    if (!res.ok) throw new Error('Upload HTTP ' + res.status);

    setStatus($('uploadStatus'), 'Uploaded.', 'ok');
    state.file = null;
    $('dzFileInfo').textContent = '';
    dz.classList.remove('filled');
    $('btnUpload').disabled = true;
    await refreshList();
  } catch (err) {
    console.error(err);
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
  try {
    document.body.classList.add('busy');
    setStatus(status, 'Fetching download URL…');
    const meta = await getDownloadPresign({ region: REGION, key: f.key });
    setStatus(status, 'Downloading ciphertext…');
    const res = await fetch(meta.url);
    if (!res.ok) throw new Error('Download HTTP ' + res.status);
    const cipher = new Uint8Array(await res.arrayBuffer());

    setStatus(status, 'Decrypting…');
    const plain = await decryptBlob(cipher, $('passInput').value, state.tempKey);

    const name = safeFilename(meta.objname || f.objname) || 'file.bin';
    const blobUrl = URL.createObjectURL(new Blob([plain], { type: 'application/octet-stream' }));
    a.href = blobUrl; a.download = name; a.classList.remove('hidden');

    const ext = name.split('.').pop().toLowerCase();
    if (['png', 'jpg', 'jpeg', 'gif', 'webp'].includes(ext)) {
      img.src = blobUrl; img.classList.remove('hidden');
    } else if (name.endsWith('.txt') || ext === 'txt') {
      ta.value = new TextDecoder().decode(plain);
      ta.classList.remove('hidden');
    }

    setStatus(status, 'Decrypted: ' + name, 'ok');

    // Background VT check
    sha1Hex(plain).then(checkSha1).then((vt) => {
      if (vt && vt.detect) {
        setStatus(status,
          'WARNING: VirusTotal flagged this file (' + vt.positives + '/' + vt.total + ')',
          'err');
      }
    }).catch(() => {});

    if (meta.deleteondownload) {
      deleteObject({ region: REGION, key: f.key }).then(refreshList).catch(() => {});
    }
  } catch (err) {
    console.error(err);
    setStatus(status, 'Decrypt failed — wrong password or tampered data.', 'err');
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
