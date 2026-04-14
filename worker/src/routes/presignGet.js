// GET /presign/get — mint a GET URL + echo object metadata.
// We HEAD the object via the R2 binding (no SigV4 needed) so we can return
// filename/size to the client without forcing it to decode custom metadata
// from a HEAD request against R2 directly.

import { jsonResponse, errorResponse } from '../util/json.js';
import { resolveRegion } from '../util/regions.js';
import { presignR2 } from '../util/sigv4.js';
import { KEY_REGEX } from '../util/keys.js';

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

export async function presignGet(url, request, env) {
  const q = url.searchParams;
  const region = resolveRegion(q.get('region'), env);

  const key = q.get('key') || '';
  if (!KEY_REGEX.test(key)) {
    return errorResponse('invalid key', 'BAD_INPUT', 400, env, request);
  }

  if (!region.binding) {
    return errorResponse('region unavailable', 'NO_BINDING', 500, env, request);
  }

  const head = await region.binding.head(key);
  if (!head) {
    return errorResponse('not found', 'NOT_FOUND', 404, env, request);
  }

  const meta = head.customMetadata || {};
  const objname = b64urlDecode(meta.filename || '') || 'unknown-file-name';
  const deleteondownload = (meta.deleteondownload || 'false') === 'true';

  const { url: presigned } = await presignR2({
    method: 'GET',
    accountId: env.R2_ACCOUNT_ID,
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
    bucket: region.bucketName,
    key,
    region: 'auto',
    expiresIn: 900,
    signedHeaders: {},
  });

  return jsonResponse(
    {
      url: presigned,
      key,
      objsize: head.size,
      objname,
      deleteondownload,
    },
    200,
    env,
    request
  );
}
