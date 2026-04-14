# Archived AWS Implementation

This folder contains the original AWS-based implementation of RelaySecret (Lambda + API Gateway + S3, with a separate Cloudflare Worker for the clipboard feature). It is kept for historical reference and is not maintained.

The project has been migrated to a Cloudflare-native stack (Workers + R2 + Pages + KV). See the top-level `README.md` for the current architecture and deployment instructions.

## What's in here

- `backend/code/lambda.py` — original Python Lambda handling presigned S3 URLs, VirusTotal lookups, tunnel (room) mode.
- `backend/terraform/` — Terraform module deploying Lambda, API Gateway and 3 regional S3 buckets (us-east-1, eu-central-1, ap-southeast-2) with prefix-based lifecycle rules.
- `backend/clipboardworker/` — original minimal Cloudflare Worker + KV used for the clipboard feature (now folded into the unified worker).
- `frontend/` — original static frontend (index, tunnel, clipboard). Zero-framework, all crypto via WebCrypto (AES-CBC + PBKDF2-SHA256 @ 10k iters).

## Why it was replaced

- Consolidate infra on a single provider (Cloudflare).
- R2 egress is free → cheaper for a file-sharing service.
- Single Worker is simpler to audit than Lambda + API Gateway + 3× S3 buckets + CORS policies.
- Upgrade crypto to AES-GCM (authenticated) + PBKDF2 @ 600 000 iters (OWASP 2023 / NIST SP 800-132).
- Raise the file size cap from 200 MB to 2 GB via direct-to-R2 presigned PUTs.
