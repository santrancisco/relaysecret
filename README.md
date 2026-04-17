## Why another file sharing app?

Several reasons:

- Firefox Send was taken down and the walkthrough to deploy it is too complicated.
- Magic Wormhole is great but needs a client app installed.
- Some solutions look amazing but send plaintext to the server — all encryption happens server-side.
- Many solutions are well written but complex: WebSockets, WebRTC, tons of dependencies that make auditing impossible and leave you exposed to supply chain attacks on every rebuild.
- Other issues: third-party tracking cookies, too much backend code that may be prone to attacks.

What RelaySecret aims for:
- **Extremely simple backend** — a single Cloudflare Worker that mints presigned URLs. No application logic that touches your data.
- **No server-side plaintext** — file upload/download goes directly between browser and R2 via presigned URLs. The Worker never sees file bytes.
- **Zero dependencies** — all cryptography uses the standard Web Crypto API. No npm packages, no bundler, no build step.
- **No WebSockets, no WebRTC** — no real-time refresh. There's a button to refresh the file list in room mode.

## How it works

Visit [https://www.relaysecret.com/](https://www.relaysecret.com/) to try it out.

The architecture is Cloudflare Workers + R2 + Pages. Three regional R2 buckets (US, EU, APAC) store ciphertext. The Worker has two jobs:

1. **Mint short-lived SigV4 presigned URLs** so the browser can PUT/GET/delete ciphertext directly against R2. The Worker never proxies bytes.
2. **Proxy VirusTotal SHA-1 lookups** so the API key stays server-side.

A KV namespace stores encrypted clipboard blobs.

### Upload file

1. Browser requests a presigned PUT URL from the Worker (with filename, expiry, region).
2. Browser encrypts the file client-side with AES-GCM-256 using WebCrypto.
3. Browser uploads ciphertext directly to R2 via the presigned URL.
4. Browser builds a share URL: `https://{server}/{object-key}#{key-material}`

### Retrieve file

1. User visits the share URL. The `#key-material` never leaves the browser (not sent in Referer, not logged server-side).
2. Browser requests a presigned GET URL from the Worker.
3. Browser downloads ciphertext directly from R2.
4. Browser decrypts using the key-material (and optional user password).

### Delete / Expire

- Object keys follow the format `{expiry-days}/{hex-id}`. R2 lifecycle rules auto-expire objects by prefix (1-day, 2-day, ..., 10-day).
- Objects tagged with `deleteOnDownload` are deleted automatically after the first download.
- Users can always delete files manually.

### Room mode

Visit [https://www.relaysecret.com/tunnel](https://www.relaysecret.com/tunnel).

Create a "room" by entering a room name (min 8 characters). Others who enter the same room name see the same file list and can share/decrypt files. All files in a room expire after 1 day.

The room name is hashed with SHA-256 to derive the key material. The room name itself is never sent to the server — only the first 16 hex chars of its hash are used as the tunnel ID. Users can add an optional password for extra protection.

## Large file support

Files under 500 MB use the **RSv1** format: the entire file is encrypted in one shot with AES-GCM-256, uploaded via a single presigned PUT URL.

Files over 500 MB use the **RSv2** chunked format:
- The file is split into 128 MB chunks. Each chunk is independently AES-GCM encrypted with a unique IV (derived by XOR-ing the chunk index into a random base nonce).
- Chunks are uploaded via S3 multipart presigned URLs directly to R2 — still no bytes through the Worker.
- On download, the browser detects the format from the first 48 bytes and decrypts each chunk using HTTP Range requests.
- Peak browser memory is ~260 MB regardless of total file size (128 MB plaintext + 128 MB ciphertext + overhead).

## Cryptography

All cryptography uses the **Web Crypto API**. No external libraries.

| Primitive | Usage |
|-----------|-------|
| **AES-GCM-256** | File/message encryption. Per-chunk auth tags in RSv2. |
| **PBKDF2-HMAC-SHA256** | Key derivation from password + temp key. 600,000 iterations, 16-byte random salt. |
| **HMAC-SHA256** | AWS SigV4 presigning, optional upload gate. |
| **SHA-256** | Object key generation, room name derivation, VirusTotal lookups. |

The encryption key is derived as: `PBKDF2-HMAC-SHA256(password + tempKey, salt, 600000) -> 256 bits`. The temp key (128-bit random for single-recipient, SHA-256 of room name for tunnels) is the primary entropy source; the optional password is layered on top.

### Post-quantum note

The application uses **symmetric cryptography only** — no RSA, ECDH, ECDSA, or any asymmetric primitives. AES-256 and HMAC-SHA256 are considered quantum-resistant: Grover's algorithm halves the effective key space, but AES-256 retains 128-bit post-quantum security which is well beyond practical attacks.

The transport layer (HTTPS) relies on Cloudflare's TLS termination. Cloudflare has been deploying hybrid post-quantum key agreement (X25519 + ML-KEM/Kyber) across their network. This is the only point where asymmetric cryptography enters the threat model, and it is outside the application's control.

## Deploy your own

See [deploy/README.md](deploy/README.md) for the full one-shot deploy script. It provisions R2 buckets, KV namespace, the Worker, Pages, and DNS — all against your own Cloudflare account.

Quick start:
```bash
cp deploy/config.example.env deploy/config.env
# fill in your Cloudflare API token + domain
./deploy/deploy.sh --yes
```

Requirements: `wrangler`, `curl`, `jq`, `openssl`.

## License

This project is licensed under the GPL-3.0 open source license.
