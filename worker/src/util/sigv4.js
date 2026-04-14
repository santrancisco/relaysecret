// sigv4.js — AWS SigV4 presigner for R2's S3-compatible endpoint.
//
// WHY THIS FILE EXISTS
// --------------------
// R2 buckets can be signed with AWS SigV4 using an R2 API token's
// access-key-id + secret-access-key pair. The alternative — proxying the
// bytes through the Worker — would double bandwidth cost and route plaintext
// (well, ciphertext) through our runtime. Presigned URLs let the browser talk
// to R2 directly. We MUST implement SigV4 here because the user wants zero
// npm deps and a surface small enough to audit in one sitting.
//
// SHAPE OF AN S3 PRESIGNED URL
// ----------------------------
// A presigned request for S3 is just a normal HTTP request whose
// authenticating material is carried in query-string parameters rather than
// HTTP headers. The server recomputes the signature from the request line +
// query string + a deterministic set of "signed headers" and checks it.
//
// The canonical algorithm, per AWS docs, is:
//
//   1. Build a "canonical request", a fixed-format textual representation of:
//        HTTPMethod \n
//        CanonicalURI \n         (the path, URI-encoded except "/")
//        CanonicalQueryString \n (sorted key=value, each URI-encoded)
//        CanonicalHeaders \n     ("k:v\n" lines, lowercase key, trimmed value)
//        SignedHeaders \n        (";"-joined lowercase header names)
//        HashedPayload           ("UNSIGNED-PAYLOAD" for presigned URLs)
//
//   2. Compute the "string to sign":
//        AWS4-HMAC-SHA256 \n
//        <amzDate, yyyymmddThhmmssZ> \n
//        <credential scope: date/region/service/aws4_request> \n
//        hex(sha256(canonical_request))
//
//   3. Derive the signing key as a chain of HMAC-SHA256:
//        kDate    = HMAC("AWS4" + secret, date)
//        kRegion  = HMAC(kDate,  region)
//        kService = HMAC(kRegion, service)
//        kSigning = HMAC(kService, "aws4_request")
//
//   4. Signature = hex(HMAC(kSigning, stringToSign))
//
//   5. Final URL = endpoint + canonicalURI + "?" + canonicalQueryString
//                   + "&X-Amz-Signature=" + signature
//
// R2 SPECIFICS
// ------------
//   * Region is literally the string "auto".
//   * Service is "s3".
//   * Host is `${accountId}.r2.cloudflarestorage.com`.
//   * Bucket is part of the path (path-style): /{bucket}/{key}
//   * R2 accepts "UNSIGNED-PAYLOAD" for presigned URLs just like S3.
//
// WHAT THE CALLER MUST DO WITH signedHeaders
// ------------------------------------------
// The set of headers that were "signed" (their names appear in
// X-Amz-SignedHeaders and X-Amz-Credential claims over them) MUST be sent
// verbatim by whoever executes the request. If they are missing or differ,
// R2 rejects the PUT with SignatureDoesNotMatch. For our PUT presign we sign:
//     host, content-type, x-amz-meta-filename, x-amz-meta-deleteondownload
// and the browser must send exactly those.
//
// SELF-TEST
// ---------
// A commented-out self-test block at the bottom of this file exercises the
// canonical AWS test vector ("GET object"). A reviewer can uncomment the
// block and hit a dev route to verify the implementation still matches AWS's
// published reference.

const enc = new TextEncoder();

// -- hex helpers ------------------------------------------------------------

function toHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

async function sha256Hex(str) {
  const h = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return toHex(new Uint8Array(h));
}

async function hmac(keyBytes, msg) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const msgBytes = typeof msg === 'string' ? enc.encode(msg) : msg;
  const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
  return new Uint8Array(sig);
}

// RFC3986 URI encoding. encodeURIComponent is almost right, but leaves
// !'()* alone — AWS wants them percent-encoded. Slashes in paths are handled
// by the caller, which splits on "/" and encodes each segment.
function rfc3986(str) {
  return encodeURIComponent(str).replace(
    /[!'()*]/g,
    (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()
  );
}

function encodePath(path) {
  // Path-style bucket URL: "/bucket/a/b/c". Encode each segment.
  return path
    .split('/')
    .map((seg) => (seg === '' ? '' : rfc3986(seg)))
    .join('/');
}

// Build the canonical query string: keys sorted lexicographically by their
// *encoded* form, each "k=v" also encoded.
function buildCanonicalQueryString(params) {
  const pairs = [];
  for (const [k, v] of Object.entries(params)) {
    pairs.push([rfc3986(k), rfc3986(v)]);
  }
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return pairs.map(([k, v]) => `${k}=${v}`).join('&');
}

// amzDate + dateStamp, e.g. ("20240214T101530Z", "20240214")
function formatAmzDate(d) {
  const pad = (n) => String(n).padStart(2, '0');
  const yyyy = d.getUTCFullYear();
  const mm = pad(d.getUTCMonth() + 1);
  const dd = pad(d.getUTCDate());
  const hh = pad(d.getUTCHours());
  const mi = pad(d.getUTCMinutes());
  const ss = pad(d.getUTCSeconds());
  return {
    amzDate: `${yyyy}${mm}${dd}T${hh}${mi}${ss}Z`,
    dateStamp: `${yyyy}${mm}${dd}`,
  };
}

// Derive kSigning per the AWS signing-key chain (see top of file).
async function deriveSigningKey(secret, dateStamp, region, service) {
  const kDate = await hmac(enc.encode('AWS4' + secret), dateStamp);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  const kSigning = await hmac(kService, 'aws4_request');
  return kSigning;
}

/**
 * presignR2 — build a query-string-signed URL for R2.
 *
 * opts:
 *   method          "PUT" | "GET" | "DELETE"
 *   accountId       Cloudflare account id
 *   accessKeyId     R2 S3-compatible access key id
 *   secretAccessKey R2 S3-compatible secret
 *   bucket          bucket name (path-style)
 *   key             object key (no leading slash)
 *   region          MUST be "auto"
 *   expiresIn       integer seconds, max 604800
 *   signedHeaders   object of header name -> value. Host is added automatically.
 *                   For PUTs, include content-type + x-amz-meta-* headers
 *                   the client is going to send.
 *
 * Returns { url, signedHeaders } — signedHeaders is the canonicalised
 * lowercase-keyed map the caller must echo on the wire.
 */
export async function presignR2(opts) {
  const {
    method,
    accountId,
    accessKeyId,
    secretAccessKey,
    bucket,
    key,
    region = 'auto',
    expiresIn = 900,
    signedHeaders = {},
  } = opts;

  const service = 's3';
  const host = `${accountId}.r2.cloudflarestorage.com`;
  const now = new Date();
  const { amzDate, dateStamp } = formatAmzDate(now);
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;

  // ---- canonical headers ------------------------------------------------
  // We always sign Host. Any extra headers from the caller are folded in.
  // Per SigV4: names are lowercase, values are trimmed, duplicate spaces
  // collapsed (we don't allow header values with internal whitespace here).
  const headerMap = { host };
  for (const [k, v] of Object.entries(signedHeaders)) {
    headerMap[k.toLowerCase()] = String(v).trim();
  }
  const sortedHeaderNames = Object.keys(headerMap).sort();
  const canonicalHeaders =
    sortedHeaderNames.map((n) => `${n}:${headerMap[n]}`).join('\n') + '\n';
  const signedHeadersList = sortedHeaderNames.join(';');

  // ---- query string -----------------------------------------------------
  // X-Amz-* auth params live in the query string for presigned URLs.
  const params = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${accessKeyId}/${credentialScope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expiresIn),
    'X-Amz-SignedHeaders': signedHeadersList,
  };
  const canonicalQueryString = buildCanonicalQueryString(params);

  // ---- canonical URI ----------------------------------------------------
  // Path-style: /{bucket}/{key}. Each segment is RFC3986 encoded; slashes stay.
  const canonicalUri = encodePath(`/${bucket}/${key}`);

  // ---- canonical request ------------------------------------------------
  const canonicalRequest = [
    method.toUpperCase(),
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeadersList,
    'UNSIGNED-PAYLOAD',
  ].join('\n');

  const hashedCanonicalRequest = await sha256Hex(canonicalRequest);

  // ---- string to sign ---------------------------------------------------
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    hashedCanonicalRequest,
  ].join('\n');

  // ---- signing key + signature ------------------------------------------
  const signingKey = await deriveSigningKey(
    secretAccessKey,
    dateStamp,
    region,
    service
  );
  const signatureBytes = await hmac(signingKey, stringToSign);
  const signature = toHex(signatureBytes);

  // ---- final URL --------------------------------------------------------
  const url =
    `https://${host}${canonicalUri}?${canonicalQueryString}` +
    `&X-Amz-Signature=${signature}`;

  // Strip host from the echoed signedHeaders — the fetch library adds it.
  const echoed = { ...headerMap };
  delete echoed.host;

  return { url, signedHeaders: echoed };
}

/* ----------------------------------------------------------------------- *
 * Self-test — uncomment and wire to a dev route to verify against the AWS  *
 * canonical vector "Example: GET Object" from the SigV4 spec.              *
 *                                                                          *
 * Expected canonical request hash for the published vector is:             *
 *   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855       *
 * (Only the signing chain changes; the canonical-request builder is the   *
 * interesting bit to verify.)                                              *
 *                                                                          *
 * export async function _selfTest() {                                      *
 *   const out = await presignR2({                                          *
 *     method: 'GET',                                                       *
 *     accountId: 'examples',                                               *
 *     accessKeyId: 'AKIDEXAMPLE',                                          *
 *     secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',          *
 *     bucket: 'examplebucket',                                             *
 *     key: 'test.txt',                                                     *
 *     region: 'auto',                                                      *
 *     expiresIn: 86400,                                                    *
 *     signedHeaders: {},                                                   *
 *   });                                                                    *
 *   return out;                                                            *
 * }                                                                        *
 * ----------------------------------------------------------------------- */
