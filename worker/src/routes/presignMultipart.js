// POST /presign/multipart-init — mint an S3 multipart upload with presigned part URLs.
//
// Flow:
//   1. Browser calls this Worker route with chunk count + file metadata.
//   2. Worker calls CreateMultipartUpload on R2 (server-side, gets uploadId).
//   3. Worker generates N presigned PUT URLs (one per part) + complete/abort URLs.
//   4. Browser uploads each encrypted chunk directly to R2 via the part URLs.
//   5. Browser calls the complete URL to finalise.
//
// The Worker never sees file bytes — only the uploadId metadata round-trips.

import { jsonResponse, errorResponse } from '../util/json.js';
import { resolveRegion } from '../util/regions.js';
import { presignR2, signS3Request } from '../util/sigv4.js';
import { makeSendKey, makeTunnelKey, tunnelHash, sanitizeFilename, b64urlEncode } from '../util/keys.js';
import { checkHmacGate } from '../util/hmacGate.js';

const ALLOWED_EXPIRE = new Set([1, 2, 3, 4, 5, 10]);
// 500 parts × 128 MB = 64 GB — far beyond any practical browser upload.
// The S3/R2 hard limit is 10 000, but allowing that many in a single
// unauthenticated request would let anyone trigger ~60 000 WebCrypto ops +
// a real CreateMultipartUpload R2 call per request, making this a cheap DoS.
const MAX_PARTS = 500;

async function createMultipartUpload(env, region, key, metaHeaders) {
  const { amzDate, authorization } = await signS3Request({
    method: 'POST',
    accountId: env.R2_ACCOUNT_ID,
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
    bucket: region.bucketName,
    key,
    queryParams: { uploads: '' },
    headers: {
      'content-type': 'application/octet-stream',
      ...metaHeaders,
    },
  });

  const host = `${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  const res = await fetch(
    `https://${host}/${region.bucketName}/${key}?uploads=`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
        'x-amz-date': amzDate,
        Authorization: authorization,
        ...metaHeaders,
      },
    }
  );

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`CreateMultipartUpload failed: ${res.status} ${body}`);
  }

  // R2 returns XML: <UploadId>...</UploadId>
  const xml = await res.text();
  const match = xml.match(/<UploadId>([^<]+)<\/UploadId>/);
  if (!match) throw new Error('No UploadId in CreateMultipartUpload response');
  return match[1];
}

export async function presignMultipartInit(url, request, env) {
  const q = url.searchParams;

  // HMAC gate — same gate as presignPut / presignTunnelPut. All upload-initiating
  // routes must be gated consistently so that setting HMAC_SECRET actually works.
  const passed = await checkHmacGate(env, q.get('exp'));
  if (!passed) {
    return errorResponse('hmac gate failed', 'HMAC_GATE', 403, env, request);
  }

  const region = resolveRegion(q.get('region'), env);

  // chunk count
  let chunks = parseInt(q.get('chunks') || '0', 10);
  if (chunks < 1 || chunks > MAX_PARTS) {
    return errorResponse('chunks must be 1..500', 'BAD_INPUT', 400, env, request);
  }

  // filename
  const rawName = q.get('filename') || '';
  if (!rawName) return errorResponse('filename required', 'BAD_INPUT', 400, env, request);
  const cleanName = sanitizeFilename(rawName);
  if (!cleanName) return errorResponse('filename invalid', 'BAD_INPUT', 400, env, request);

  // expiry
  let expire = parseInt(q.get('expire') || '1', 10);
  if (!ALLOWED_EXPIRE.has(expire)) expire = 1;

  const deleteOnDownload = (q.get('deleteOnDownload') || 'false').toLowerCase() === 'true';
  const isTunnel = q.has('tunnel');
  const tunnel = (q.get('tunnel') || '').trim();

  if (isTunnel && (!/^[A-Za-z0-9]+$/.test(tunnel) || tunnel.length < 1 || tunnel.length > 64)) {
    return errorResponse('invalid tunnel name', 'BAD_INPUT', 400, env, request);
  }

  // Generate the object key
  let key;
  if (isTunnel) {
    const tHash = await tunnelHash(tunnel);
    key = await makeTunnelKey(tHash, env.SEED || '');
  } else {
    key = await makeSendKey(expire, env.SEED || '');
  }

  const metaFilename = b64urlEncode(cleanName);
  const metaDelete = deleteOnDownload ? 'true' : 'false';
  const metaHeaders = {
    'x-amz-meta-filename': metaFilename,
    'x-amz-meta-deleteondownload': metaDelete,
  };

  // Step 1: Create multipart upload on R2
  let uploadId;
  try {
    uploadId = await createMultipartUpload(env, region, key, metaHeaders);
  } catch (err) {
    return errorResponse(err.message, 'S3_ERROR', 502, env, request);
  }

  // Step 2: Generate presigned URLs for each part + complete + abort
  const s3Creds = {
    accountId: env.R2_ACCOUNT_ID,
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
    bucket: region.bucketName,
    key,
    region: 'auto',
    expiresIn: 3600,
  };

  const partUrls = [];
  for (let i = 1; i <= chunks; i++) {
    const { url: partUrl } = await presignR2({
      ...s3Creds,
      method: 'PUT',
      queryExtras: { partNumber: String(i), uploadId },
    });
    partUrls.push({ partNumber: i, url: partUrl });
  }

  const { url: completeUrl } = await presignR2({
    ...s3Creds,
    method: 'POST',
    queryExtras: { uploadId },
    signedHeaders: { 'content-type': 'application/xml' },
  });

  const { url: abortUrl } = await presignR2({
    ...s3Creds,
    method: 'DELETE',
    queryExtras: { uploadId },
  });

  return jsonResponse(
    {
      key,
      uploadId,
      region: region.region,
      partUrls,
      completeUrl,
      abortUrl,
      requiredHeaders: {
        'content-type': 'application/octet-stream',
        ...metaHeaders,
      },
    },
    200,
    env,
    request
  );
}
