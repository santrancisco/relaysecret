// clipboard.js — controller for /clipboard/.
//
// Tunnel id is derived the same way as the tunnel room page:
//   tempKey   = sha256(userName) hex            (stays in URL fragment)
//   clipId    = first 16 chars of sha256(tempKey)  (query param)
//
// Transport is hex strings via the Worker /clipboard/:id KV endpoints.

import { encryptBlob, decryptBlob, sha256Hex } from './crypto.js';
import { clipboardGet, clipboardPut, ApiError } from './api.js';
import {
  $, setStatus, getQueryParams, getFragment, bytesToHex, hexToBytes,
} from './ui.js';

const state = { clipId: '', tempKey: '' };

async function boot() {
  const q = getQueryParams();
  state.tempKey = getFragment();
  if (!q.clipboardid || !state.tempKey) {
    let name = '';
    while (name.length < 8) {
      name = window.prompt('Enter clipboard id (min 8 characters)') || '';
      if (name === null) return;
    }
    const tempKey = await sha256Hex(name);
    const full    = await sha256Hex(tempKey);
    const id      = full.slice(0, 16);
    window.location.href = window.location.pathname + '?clipboardid=' + id + '#' + tempKey;
    return;
  }
  state.clipId = q.clipboardid;
  $('clipInfo').textContent = 'Clipboard id: ' + state.clipId;
}

$('btnUpdate').onclick = async () => {
  try {
    document.body.classList.add('busy');
    setStatus($('status'), 'Reading local clipboard…');
    const text = await navigator.clipboard.readText();
    if (!text) { setStatus($('status'), 'Nothing to upload.', 'warn'); return; }

    setStatus($('status'), 'Encrypting…');
    const plain = new TextEncoder().encode(text);
    const blob = await encryptBlob(plain, $('passInput').value, state.tempKey);

    setStatus($('status'), 'Uploading…');
    await clipboardPut(state.clipId, bytesToHex(blob));
    setStatus($('status'), 'Clipboard updated.', 'ok');
  } catch (err) {
    console.error(err);
    setStatus($('status'), 'Update failed: ' + (err.message || err), 'err');
  } finally {
    document.body.classList.remove('busy');
  }
};

$('btnGet').onclick = async () => {
  try {
    document.body.classList.add('busy');
    setStatus($('status'), 'Fetching…');
    let payload;
    try {
      payload = await clipboardGet(state.clipId);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setStatus($('status'), 'No clipboard data yet.', 'warn');
        return;
      }
      throw err;
    }
    if (!payload || !payload.data) {
      setStatus($('status'), 'Empty clipboard.', 'warn');
      return;
    }
    setStatus($('status'), 'Decrypting…');
    const cipher = hexToBytes(payload.data);
    const plain  = await decryptBlob(cipher, $('passInput').value, state.tempKey);
    const text   = new TextDecoder().decode(plain);

    await navigator.clipboard.writeText(text);
    setStatus($('status'), 'Copied to local clipboard (' + text.length + ' chars).', 'ok');
  } catch (err) {
    console.error(err);
    setStatus($('status'), 'Get failed — wrong password or tampered data.', 'err');
  } finally {
    document.body.classList.remove('busy');
  }
};

boot();
