// send.js — controller for the root / send+receive page.
//
// Two jobs:
//   1. ENCRYPT: message or file -> AES-GCM -> PUT presigned URL -> share link
//   2. DECRYPT: when ?obj=...&region=...#tempkey is present, fetch, decrypt
//               and offer download.

import { encryptBlob, decryptBlob, randomTempKey } from './crypto.js';
import {
  getUploadPresign, getDownloadPresign, deleteObject, ApiError,
} from './api.js';
import {
  $, formatBytes, setStatus, getQueryParams, getFragment,
  safeFilename, copyToClipboard, b64url, readFileBytes,
  createProgressFlow, showImageModal,
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
  updateEncryptButton();
}

// ---------------------------------------------------------------- encrypt flow
$('btnEncrypt').onclick = async () => {
  const flow = encFlow();
  flow.show();
  flow.reset();
  let currentStep = 0;
  try {
    document.body.classList.add('busy');

    flow.start(0);
    setStatus($('encStatus'), 'Reading input…');
    let plaintext, filename;
    if (state.mode === 'message') {
      plaintext = new TextEncoder().encode($('msgInput').value);
      filename = MSG_FILENAME;
    } else {
      if (!state.file) return;
      plaintext = await readFileBytes(state.file);
      filename = safeFilename($('filenameInput').value || state.file.name) || 'file.bin';
    }
    if (plaintext.length === 0) throw new Error('Nothing to encrypt.');
    flow.done(0);

    state.tempKey = randomTempKey();
    const pass = ($('passInput').value || '').trim();

    currentStep = 1;
    flow.start(1);
    await new Promise((r) => setTimeout(r, 16)); // let spinner paint
    flow.done(1);

    currentStep = 2;
    flow.start(2);
    setStatus($('encStatus'), 'Encrypting with AES-GCM-256…');
    const blob = await encryptBlob(plaintext, pass, state.tempKey);
    flow.done(2);

    currentStep = 3;
    flow.start(3);
    setStatus($('encStatus'), 'Requesting upload URL…');
    const region = $('regionSelect').value;
    const expire = $('expireSelect').value;
    const dod    = $('dodInput').checked;
    const presign = await getUploadPresign({
      region, expire, filename, deleteOnDownload: dod,
    });
    flow.done(3);

    currentStep = 4;
    flow.start(4);
    setStatus($('encStatus'), 'Uploading ciphertext (' + formatBytes(blob.length) + ')…');
    const putRes = await fetch(presign.url, {
      method: 'PUT',
      headers: presign.requiredHeaders,
      body: blob,
    });
    if (!putRes.ok) throw new Error('Upload failed: HTTP ' + putRes.status);
    flow.done(4);

    currentStep = 5;
    flow.start(5);
    showShareUrl(presign.region || region, presign.key, state.tempKey);
    flow.done(5);

    setStatus($('encStatus'), 'Encrypted end-to-end and uploaded.', 'ok');
  } catch (err) {
    console.error(err);
    flow.error(currentStep);
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
  $('paneResult').classList.remove('hidden');
  $('btnCopyUrl').onclick = async () => {
    const ok = await copyToClipboard(url);
    setStatus($('encStatus'), ok ? 'URL copied to clipboard.' : 'Copy failed — select manually.', ok ? 'ok' : 'warn');
  };
  $('btnNewSend').onclick = () => {
    $('paneResult').classList.add('hidden');
    $('msgInput').value = '';
    state.file = null;
    $('dzFileInfo').textContent = '';
    dz.classList.remove('filled');
    setStatus($('encStatus'), '');
  };
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
  try {
    document.body.classList.add('busy');

    // Metadata was already fetched during initDecryptFromUrl; mark step 0
    // as done up-front since we have the presigned GET URL already.
    flow.done(0);

    currentStep = 1;
    flow.start(1);
    setStatus($('decStatus'), 'Downloading ciphertext…');
    const res = await fetch(state.meta.url);
    if (!res.ok) throw new Error('Download failed: HTTP ' + res.status);
    const blob = new Uint8Array(await res.arrayBuffer());
    flow.done(1);

    const frag = (getFragment() || '').trim();
    const pass = ($('decPassInput').value || '').trim();

    currentStep = 2;
    flow.start(2);
    await new Promise((r) => setTimeout(r, 16));
    flow.done(2);

    currentStep = 3;
    flow.start(3);
    setStatus($('decStatus'), 'Verifying & decrypting…');
    const plain = await decryptBlob(blob, pass, frag);
    state.plaintext = plain;
    flow.done(3);

    await showDecrypted();
    setStatus($('decStatus'), 'Decrypted.', 'ok');

    if (state.meta.deleteondownload) {
      deleteObject({ region: state.region, key: state.objKey }).catch(() => {});
    }
  } catch (err) {
    console.error(err);
    flow.error(currentStep);
    setStatus($('decStatus'), 'Decrypt failed — wrong password, tampered data, or expired link.', 'err');
  } finally {
    document.body.classList.remove('busy');
  }
};

async function showDecrypted() {
  const plain = state.plaintext;
  const filename = state.origFilename;
  const isMessage = filename === MSG_FILENAME;
  $('decResult').classList.remove('hidden');

  if (isMessage) {
    const text = new TextDecoder().decode(plain);
    const ta = $('decMsgOut');
    ta.value = text;
    ta.classList.remove('hidden');
  }

  // Offer a download regardless. URL.createObjectURL streams the Blob.
  const blobUrl = URL.createObjectURL(new Blob([plain], { type: 'application/octet-stream' }));
  const a = $('decDownload');
  a.href = blobUrl;
  a.download = filename;
  a.classList.remove('hidden');

  // Inline preview for common image types. Click to enlarge.
  const ext = filename.split('.').pop().toLowerCase();
  if (['png', 'jpg', 'jpeg', 'gif', 'webp'].includes(ext)) {
    const img = $('decImg');
    img.src = blobUrl;
    img.classList.remove('hidden');
    img.onclick = () => showImageModal(blobUrl);
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
