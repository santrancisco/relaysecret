// GET /presign/tunnel-put — mint a SigV4 presigned PUT URL for a tunnel (room) send.
// Expiry is always 1 day; room membership is implicit to the tunnel name.

import { jsonResponse, errorResponse } from '../util/json.js';
import { resolveRegion } from '../util/regions.js';
import { presignR2 } from '../util/sigv4.js';
import {
  makeTunnelKey,
  tunnelHash,
  sanitizeFilename,
  b64urlEncode,
} from '../util/keys.js';
import { checkHmacGate } from '../util/hmacGate.js';

export async function presignTunnelPut(url, request, env) {
  const q = url.searchParams;

  // HMAC gate — same gate as presignPut. All upload-initiating routes must be
  // gated consistently; skipping this check here would allow operators who set
  // HMAC_SECRET to be bypassed by hitting the tunnel-put endpoint instead.
  const passed = await checkHmacGate(env, q.get('exp'));
  if (!passed) {
    return errorResponse('hmac gate failed', 'HMAC_GATE', 403, env, request);
  }

  const region = resolveRegion(q.get('region'), env);

  const tunnel = q.get('tunnel') || '';
  if (!/^[A-Za-z0-9]+$/.test(tunnel) || tunnel.length < 1 || tunnel.length > 64) {
    return errorResponse('invalid tunnel name', 'BAD_INPUT', 400, env, request);
  }

  const rawName = q.get('filename') || '';
  if (!rawName) return errorResponse('filename required', 'BAD_INPUT', 400, env, request);
  const cleanName = sanitizeFilename(rawName);
  if (!cleanName) return errorResponse('filename invalid', 'BAD_INPUT', 400, env, request);

  const deleteOnDownload =
    (q.get('deleteOnDownload') || 'false').toLowerCase() === 'true';

  const tHash = await tunnelHash(tunnel);
  const key = await makeTunnelKey(tHash, env.SEED || '');

  const metaFilename = b64urlEncode(cleanName);
  const metaDelete = deleteOnDownload ? 'true' : 'false';

  const { url: presigned, signedHeaders } = await presignR2({
    method: 'PUT',
    accountId: env.R2_ACCOUNT_ID,
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
    bucket: region.bucketName,
    key,
    region: 'auto',
    expiresIn: 900,
    signedHeaders: {
      'content-type': 'application/octet-stream',
      'x-amz-meta-filename': metaFilename,
      'x-amz-meta-deleteondownload': metaDelete,
    },
  });

  return jsonResponse(
    {
      url: presigned,
      key,
      region: region.region,
      tunnelHash: tHash,
      requiredHeaders: signedHeaders,
    },
    200,
    env,
    request
  );
}
