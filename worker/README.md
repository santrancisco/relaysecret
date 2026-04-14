# RelaySecret Worker

The RelaySecret backend, rewritten for Cloudflare Workers + R2 + KV.

The Worker never sees plaintext. All encryption happens in the browser with
WebCrypto. The Worker's only jobs are:

1. Mint short-lived **SigV4 presigned R2 URLs** so the browser can PUT/GET
   ciphertext directly against R2's S3 endpoint.
2. Proxy VirusTotal SHA-1 lookups so the API key stays server-side.
3. Store and fetch encrypted clipboard blobs in KV.

Zero npm dependencies. Plain ES modules. `wrangler` is the only tool you need.

## Layout

```
src/
  index.js                  router + CORS + referer gate
  routes/
    presignPut.js           GET  /presign/put
    presignTunnelPut.js     GET  /presign/tunnel-put
    presignGet.js           GET  /presign/get
    tunnelList.js           GET  /tunnel/list
    deleteObj.js            DELETE /obj
    sha1.js                 GET  /sha1/:hash
    clipboard.js            GET/POST /clipboard/:id
  util/
    sigv4.js                AWS SigV4 presigner (audit surface)
    hmacGate.js             optional time-bound HMAC validator
    cors.js                 CORS + referer gate helpers
    json.js                 jsonResponse / errorResponse
    keys.js                 object-key generator + filename helpers
    regions.js              region -> binding / bucket / endpoint
```

## SigV4 in one paragraph

`util/sigv4.js` implements the AWS SigV4 query-string presigning algorithm on
top of WebCrypto. It builds a canonical request (method, URI, query, headers,
`UNSIGNED-PAYLOAD`), wraps that in a "string to sign", derives a signing key
by chaining HMAC-SHA256 over `AWS4+secret -> date -> region -> service ->
aws4_request`, and signs the string to sign. The signature is appended to the
URL as `X-Amz-Signature`. R2 expects region `auto` and service `s3`; we use
path-style URLs (`/{bucket}/{key}`) against
`<accountId>.r2.cloudflarestorage.com`. Every step is commented inline. Start
reading at `presignR2()`.

## Prerequisites

- Node 18+
- `wrangler` v3+ (`npm i -g wrangler`)
- A Cloudflare account with R2 enabled and an R2 API token

## Buckets

Create three R2 buckets with location hints matching `docs/API.md`:

```
wrangler r2 bucket create relaysecret-us   --location wnam
wrangler r2 bucket create relaysecret-eu   --location eeur
wrangler r2 bucket create relaysecret-apac --location apac
```

Apply lifecycle rules so that objects under `1day/`, `2day/`, ..., `10day/`
auto-expire after the matching number of days. These can be created from the
R2 dashboard or via `wrangler r2 bucket lifecycle set`.

## KV

```
wrangler kv namespace create CLIPBOARD_KV
```

Copy the printed `id` into `wrangler.toml`.

## Config

Copy `wrangler.toml.example` to `wrangler.toml` and fill in:

- `R2_ACCOUNT_ID` — Cloudflare account id
- `FRONTEND_ORIGIN` — e.g. `https://www.relaysecret.com`, or `devmode`
- `SEED` — long random string used to salt object keys

Then set the secrets (values never appear in the file):

```
wrangler secret put R2_ACCESS_KEY_ID
wrangler secret put R2_SECRET_ACCESS_KEY
wrangler secret put VT_API_KEY        # or literal "none"
wrangler secret put HMAC_SECRET       # or literal "none"
```

## Run locally

```
wrangler dev
```

Pass `FRONTEND_ORIGIN=devmode` in `[vars]` (or via `--var`) to disable the
origin gate and get wildcard CORS.

## Manual smoke tests

Replace `BASE` with `http://127.0.0.1:8787` for dev, or the deployed URL.

Presign a PUT:
```
curl "$BASE/presign/put?region=us&expire=1&filename=hello.bin&deleteOnDownload=true"
```

Upload ciphertext using the returned URL — send the exact `requiredHeaders`:
```
curl -X PUT --data-binary @ciphertext.bin \
  -H 'content-type: application/octet-stream' \
  -H 'x-amz-meta-filename: aGVsbG8uYmlu' \
  -H 'x-amz-meta-deleteondownload: true' \
  "$PRESIGNED_URL"
```

Presign a GET:
```
curl "$BASE/presign/get?region=us&key=1day/<hex>"
```

Download via the presigned URL:
```
curl -o got.bin "$PRESIGNED_GET_URL"
```

Delete:
```
curl -X DELETE "$BASE/obj?region=us&key=1day/<hex>"
```

Tunnel upload + list:
```
curl "$BASE/presign/tunnel-put?region=us&tunnel=myroom&filename=a.bin&deleteOnDownload=false"
curl "$BASE/tunnel/list?region=us&tunnel=myroom"
```

VirusTotal lookup (requires `VT_API_KEY != none`):
```
curl "$BASE/sha1/3395856ce81f2b7382dee72602f798b642f14140"
```

Clipboard round-trip:
```
curl -X POST -H 'content-type: application/json' \
  -d '{"data":"deadbeef"}' "$BASE/clipboard/abc12345"
curl "$BASE/clipboard/abc12345"
```

## Deploy

```
wrangler deploy
```

Then uncomment the `routes` block in `wrangler.toml` to attach the
`api.relaysecret.com` custom domain.

## Audit order

If you have an hour and want to read every line, this is the order I'd read it in:

1. `src/index.js` — the whole router.
2. `src/util/cors.js` + `src/util/json.js` — shared response plumbing.
3. `src/util/keys.js` + `src/util/regions.js` — ID generation + bucket routing.
4. `src/util/sigv4.js` — the crypto surface. Comments walk you through every
   step of the SigV4 algorithm.
5. `src/util/hmacGate.js` — optional time-bound HMAC gate.
6. `src/routes/*.js` — each route is small and boring; read them in any order.
