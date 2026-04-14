# RelaySecret frontend

A zero-framework, zero-dependency static site for Cloudflare Pages. Plain HTML,
plain CSS, plain ES modules. All crypto done in the browser with WebCrypto.

## Layout

```
frontend/
├── index.html              # send / receive (encrypt message or file, then decrypt)
├── tunnel/index.html       # room mode — shared file list, 1-day expiry
├── clipboard/index.html    # encrypted shared clipboard (KV backed)
├── assets/
│   ├── tokens.css          # design tokens (verbatim from docs/DESIGN_TOKENS.css)
│   ├── app.css             # page-specific layout on top of tokens
│   ├── config.js           # window.CONFIG.workerUrl — change per environment
│   ├── crypto.js           # AES-GCM-256 + PBKDF2 600k + RSv1 blob format
│   ├── api.js              # fetch wrappers for every Worker route
│   ├── ui.js               # DOM helpers, byte formatter, status lines
│   ├── send.js             # index.html controller
│   ├── tunnel.js           # tunnel controller
│   ├── clipboard.js        # clipboard controller
│   └── favicon.svg         # RS mark in brand red
├── _headers                # Cloudflare Pages — CSP, X-Frame-Options, etc.
├── _redirects              # clean URLs
└── README.md
```

## Run locally

```bash
cd frontend
python3 -m http.server 8888
# open http://localhost:8888
```

WebCrypto requires a "secure context", but `localhost` is considered secure by
all major browsers, so plain http://localhost works.

### Point at a local Worker

Edit `assets/config.js`:

```js
window.CONFIG = { workerUrl: 'http://localhost:8787' };
```

Then start the Worker with `wrangler dev` in the worker project. Make sure the
Worker is in dev mode (permissive CORS + no Referer check) — see the Worker
README.

### Point at production

```js
window.CONFIG = { workerUrl: 'https://api.relaysecret.com' };
```

**And** update `_headers` so the CSP `connect-src` allows that origin. The
placeholder `<WORKER_ORIGIN_PLACEHOLDER>` in `_headers` should be replaced at
deploy time (the deploy script does this — keep it literal in the repo).

## The RSv1 blob format

Every ciphertext we produce has this layout:

```
 offset  size  field
 ------  ----  --------------------------------------
 0       8     magic     "RSv1" + 4x NUL
 8       16    salt      PBKDF2 salt
 24      12    iv        AES-GCM nonce
 36      N     ct||tag   AES-GCM(ciphertext + 16-byte tag)
```

- Cipher: **AES-GCM-256** (authenticated, tamper-evident).
- KDF: **PBKDF2-HMAC-SHA256, 600 000 iterations** (OWASP 2023 / NIST SP 800-132).
- Passphrase = `userPassword || tempKey`. `tempKey` is 128 bits of random hex
  kept in the URL fragment (`#...`), which browsers never send to servers.
- Salt and IV are both random per-message, stored inside the blob.

This is **not** compatible with the archived AWS site's `Salted__` + AES-CBC
format. Clean launch — no migration needed.

## File size ceiling

WebCrypto's `subtle.encrypt` needs the whole plaintext in memory. We cap files
at **2 GB** in the UI; actual ceiling depends on how much RAM the browser will
hand out to a tab. Uploads use `fetch(url, { body: Uint8Array })`, which
streams to the network.

## CSP contract

`_headers` pins:

```
default-src 'self';
script-src  'self';
style-src   'self';
connect-src 'self' <WORKER_ORIGIN>;
img-src     'self' data: blob:;
font-src    'self';
frame-ancestors 'none';
base-uri 'none';
```

`blob:` is required for the "Save decrypted file" link (createObjectURL). No
inline scripts, no inline styles, no third-party origins. If you add a new
Worker endpoint on a new host, update `connect-src` too.

## Audit order for a reviewer

Read in this order:

1. `assets/crypto.js` — correctness-critical. ~100 lines. Verify constants,
   blob layout, and key derivation match this README.
2. `assets/api.js` — all server I/O funnels through here.
3. `assets/config.js` + `_headers` — confirm CSP pins connect-src to only the
   one Worker origin.
4. `assets/send.js` — encrypt and decrypt flows; the share URL format.
5. `assets/tunnel.js` — room bootstrap (sha256 derivation) and list/upload/decrypt.
6. `assets/clipboard.js` — KV transport + hex encoding.
7. `assets/ui.js`, `assets/app.css`, `assets/tokens.css` — UI plumbing.
8. `index.html`, `tunnel/index.html`, `clipboard/index.html` — markup only,
   all logic is in the JS modules.
