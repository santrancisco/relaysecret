# RelaySecret Worker API Contract

All endpoints live on the Worker (deployed at e.g. `https://api.relaysecret.com`). Pages frontend is served from `https://www.relaysecret.com`.

The Worker **never sees plaintext**. All encryption and decryption is done in the browser with WebCrypto. The Worker's only jobs are:
1. Mint short-lived **SigV4 presigned R2 URLs** so the client can PUT/GET/DELETE encrypted blobs directly against R2's S3-compatible endpoint.
2. Proxy VirusTotal SHA-1 lookups (so the API key stays server-side).
3. Store and fetch encrypted clipboard blobs in KV.

## R2 key layout (unchanged from the AWS version)

```
{n}day/{64-hex}                        # single-recipient send
{n}day/{tunnelHash}/{64-hex}           # room / tunnel mode (n is always 1)
```

`n ∈ {1,2,3,4,5,10}` — used by R2 lifecycle rules to auto-expire objects by prefix.
`tunnelHash` = first 16 chars of SHA-256(tunnelName) — avoids leaking room names into R2 listings.
`64-hex` = SHA-256 of (seed + timestamp + 256 crypto-random bits). Collision-free.

## Regions

Three R2 buckets, one per jurisdiction, selected by `?region=` query param:

| Param | R2 bucket binding | R2 location hint |
|-------|-------------------|------------------|
| `us`  | `R2_US`           | `wnam` (Western North America) |
| `eu`  | `R2_EU`           | `eeur` (Eastern Europe) |
| `apac`| `R2_APAC`         | `apac` (Asia-Pacific) |

Default region is `us` if `region` is missing or unknown.

## Endpoints

### `GET /presign/put?region=X&expire=N&filename=F&deleteOnDownload=B`
Returns a SigV4 presigned R2 PUT URL plus the object key.

- `region`: one of `us|eu|apac`
- `expire`: one of `1|2|3|4|5|10` (days, maps to lifecycle prefix)
- `filename`: plaintext filename (kept in object metadata, never in the URL)
- `deleteOnDownload`: `true|false`

Response:
```json
{
  "url": "https://<account>.r2.cloudflarestorage.com/<bucket>/1day/<hex>?X-Amz-...",
  "key": "1day/<hex>",
  "region": "us",
  "requiredHeaders": {
    "x-amz-meta-filename": "<b64url(filename)>",
    "x-amz-meta-deleteondownload": "true",
    "content-type": "application/octet-stream"
  }
}
```

Client must PUT the ciphertext with **exactly** those headers. Max body 2 GB, enforced client-side.

### `GET /presign/tunnel-put?region=X&tunnel=NAME&filename=F&deleteOnDownload=B`
Same as `/presign/put` but key is scoped under `1day/<tunnelHash>/...`. Always 1-day expiry.

### `GET /presign/get?region=X&key=KEY`
Returns a short-lived (1h) presigned R2 GET URL + file metadata.

Response:
```json
{
  "url": "https://...?X-Amz-...",
  "key": "1day/<hex>",
  "objsize": 12345,
  "objname": "photo.png",
  "deleteondownload": false
}
```

### `GET /tunnel/list?region=X&tunnel=NAME`
Lists objects under `1day/<tunnelHash>/`. Returns an array of `{key, objsize, objname, deleteondownload}`. Uses R2 binding `list()` server-side — no presigning needed.

### `DELETE /obj?region=X&key=KEY`
Deletes the object via R2 binding. Simpler than presigning a DELETE.

### `GET /sha1/:hash`
Proxies VirusTotal `file/report` for the given SHA-1. API key stays in Worker secret. Returns `{sha1, positives, total, vtlink, detect, error}`.

### `POST /clipboard/:id` — body `{"data": "<hex>"}`
Stores ciphertext in KV under the given clipboard id with a TTL of 1 day.

### `GET /clipboard/:id`
Returns `{"data": "<hex>"}` or 404.

### `OPTIONS /*`
CORS preflight. `Access-Control-Allow-Origin` is pinned to the configured frontend origin (e.g. `https://www.relaysecret.com`) in prod, `*` in dev.

## Error shape

```json
{ "error": "human readable", "code": "SHORT_CODE" }
```

Status codes: `400` bad input, `403` referer/origin mismatch, `404` not found, `500` internal.

## Referer check

In prod, the Worker rejects any request whose `Origin` or `Referer` does not start with the configured frontend URL, matching the original Lambda's behaviour. Dev mode disables this.

## Secrets / bindings (wrangler.toml)

Bindings:
- `R2_US`, `R2_EU`, `R2_APAC` — R2 bucket bindings
- `CLIPBOARD_KV` — KV namespace

Secrets (via `wrangler secret put`):
- `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` — R2 S3-compatible credentials (used only for SigV4 presigning)
- `R2_ACCOUNT_ID` — Cloudflare account id (used to build the R2 S3 endpoint URL)
- `VT_API_KEY` — VirusTotal API key (or `"none"` to disable)
- `HMAC_SECRET` — optional time-bound HMAC gate (`"none"` to disable)
- `FRONTEND_ORIGIN` — e.g. `https://www.relaysecret.com`, or a comma-separated list `https://www.relaysecret.com,https://relaysecret.com` to allow multiple origins (or `"devmode"` to disable the gate)
- `SEED` — random string used to salt object-key generation
