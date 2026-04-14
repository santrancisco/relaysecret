// GET /presign/put — mint a SigV4 presigned PUT URL for a single-recipient send.

import { jsonResponse, errorResponse } from '../util/json.js';
import { resolveRegion } from '../util/regions.js';
import { presignR2 } from '../util/sigv4.js';
import { makeSendKey, sanitizeFilename, b64urlEncode } from '../util/keys.js';
import { checkHmacGate } from '../util/hmacGate.js';

const ALLOWED_EXPIRE = new Set([1, 2, 3, 4, 5, 10]);

export async function presignPut(url, request, env) {
  const q = url.searchParams;

  // HMAC gate: only this route is gated, matching lambda.py.
  const passed = await checkHmacGate(env, q.get('exp'));
  if (!passed) {
    return errorResponse('hmac gate failed', 'HMAC_GATE', 403, env, request);
  }

  const region = resolveRegion(q.get('region'), env);

  let expire = parseInt(q.get('expire') || '1', 10);
  if (!ALLOWED_EXPIRE.has(expire)) expire = 1;

  const rawName = q.get('filename') || '';
  if (!rawName) {
    return errorResponse('filename required', 'BAD_INPUT', 400, env, request);
  }
  const cleanName = sanitizeFilename(rawName);
  if (!cleanName) {
    return errorResponse('filename invalid', 'BAD_INPUT', 400, env, request);
  }

  const deleteOnDownload = (q.get('deleteOnDownload') || 'false').toLowerCase() === 'true';

  const key = await makeSendKey(expire, env.SEED || '');

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
      requiredHeaders: signedHeaders,
    },
    200,
    env,
    request
  );
}
