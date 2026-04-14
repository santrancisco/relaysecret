// GET /tunnel/list — list all objects in a tunnel. Uses the R2 binding,
// not SigV4, because we never hand this list to the browser over S3 — we
// build our own JSON shape from customMetadata.

import { jsonResponse, errorResponse } from '../util/json.js';
import { resolveRegion } from '../util/regions.js';
import { tunnelHash } from '../util/keys.js';

function b64urlDecode(s) {
  if (!s) return '';
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch {
    return '';
  }
}

export async function tunnelList(url, request, env) {
  const q = url.searchParams;
  const region = resolveRegion(q.get('region'), env);

  const tunnel = q.get('tunnel') || '';
  if (!/^[A-Za-z0-9]+$/.test(tunnel) || tunnel.length < 1 || tunnel.length > 64) {
    return errorResponse('invalid tunnel name', 'BAD_INPUT', 400, env, request);
  }
  if (!region.binding) {
    return errorResponse('region unavailable', 'NO_BINDING', 500, env, request);
  }

  const tHash = await tunnelHash(tunnel);
  const prefix = `1day/${tHash}/`;

  const listed = await region.binding.list({ prefix, include: ['customMetadata'] });
  const out = [];
  for (const obj of listed.objects || []) {
    const meta = obj.customMetadata || {};
    out.push({
      key: obj.key,
      objsize: obj.size,
      objname: b64urlDecode(meta.filename || '') || 'unknown-file-name',
      deleteondownload: (meta.deleteondownload || 'false') === 'true',
    });
  }
  // Return a bare array per docs/API.md. Previously wrapped in an object,
  // which broke the frontend's `for (const f of files)` iteration.
  return jsonResponse(out, 200, env, request);
}
