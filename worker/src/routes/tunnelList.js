// GET /tunnel/list — list all objects in a tunnel. Uses the R2 binding,
// not SigV4, because we never hand this list to the browser over S3 — we
// build our own JSON shape from customMetadata.

import { jsonResponse, errorResponse } from '../util/json.js';
import { resolveRegion } from '../util/regions.js';
import { tunnelHash } from '../util/keys.js';

// Hard cap on objects returned per tunnel list. A tunnel with more than this
// many files is not usable in a browser anyway, and iterating past this would
// mean unbounded Worker CPU time if someone floods the tunnel with objects.
const MAX_LIST_OBJECTS = 200;

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

  // Paginate through all R2 objects under the tunnel prefix. R2 list() returns
  // at most 1000 objects per call and sets `truncated = true` when more exist.
  // We collect up to MAX_LIST_OBJECTS total to bound Worker CPU time and
  // prevent a trivially flooded tunnel from stalling legitimate users.
  const out = [];
  let cursor;
  let truncated = false;

  do {
    const opts = { prefix, include: ['customMetadata'], limit: 1000 };
    if (cursor) opts.cursor = cursor;

    const page = await region.binding.list(opts);

    for (const obj of page.objects || []) {
      if (out.length >= MAX_LIST_OBJECTS) {
        truncated = true;
        break;
      }
      const meta = obj.customMetadata || {};
      out.push({
        key: obj.key,
        objsize: obj.size,
        objname: b64urlDecode(meta.filename || '') || 'unknown-file-name',
        deleteondownload: (meta.deleteondownload || 'false') === 'true',
      });
    }

    if (page.truncated && out.length < MAX_LIST_OBJECTS) {
      cursor = page.cursor;
    } else {
      truncated = truncated || page.truncated;
      break;
    }
  } while (true);

  // Return a bare array per docs/API.md. Include a `truncated` flag so the
  // frontend can warn users when the list has been capped.
  return jsonResponse({ objects: out, truncated: !!truncated }, 200, env, request);
}
