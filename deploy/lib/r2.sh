#!/usr/bin/env bash
# lib/r2.sh — R2 bucket + lifecycle + API token helpers
set -euo pipefail

# shellcheck source=./cf_api.sh
source "$(dirname "${BASH_SOURCE[0]}")/cf_api.sh"

# r2_bucket_exists NAME -> returns 0 if bucket exists
r2_bucket_exists() {
  local name="$1"
  local resp
  if resp="$(cf_api_try GET "/accounts/${CF_ACCOUNT_ID}/r2/buckets/${name}")"; then
    return 0
  fi
  return 1
}

# r2_create_bucket NAME LOCATION_HINT
# LOCATION_HINT is one of: wnam, enam, weur, eeur, apac, oc
r2_create_bucket() {
  local name="$1"
  local hint="$2"

  if r2_bucket_exists "$name"; then
    echo "  - bucket '${name}' already exists, skipping"
    return 0
  fi

  echo "  - creating bucket '${name}' (locationHint=${hint})"
  cf_api POST "/accounts/${CF_ACCOUNT_ID}/r2/buckets" \
    "$(jq -cn --arg n "$name" --arg h "$hint" '{name:$n, locationHint:$h}')" \
    >/dev/null
}

# r2_apply_cors NAME FRONTEND_ORIGIN
# Applies a CORS rule allowing the frontend to PUT encrypted blobs directly
# to R2 (with x-amz-meta-* custom headers, which trigger a preflight) and to
# GET + read the response body.
#
# Without this, browser uploads fail at CORS preflight and downloads fail at
# response-body read. Without CORS, the whole presigned-URL model is useless.
#
# API shape: Cloudflare's R2 REST endpoint wants `{ "rules": [...] }`, with
# each rule using the S3-style camelCase keys (allowed / exposeHeaders /
# maxAgeSeconds). This is NOT the same as the S3 XML CORS PutBucketCors body.
r2_apply_cors() {
  local name="$1"
  local origin="$2"

  echo "  - applying CORS policy to '${name}' (origin=${origin})"
  local body
  body="$(jq -cn --arg origin "$origin" '{
    rules: [
      {
        allowed: {
          origins:  [$origin],
          methods:  ["GET","PUT","HEAD"],
          headers:  ["content-type","x-amz-meta-filename","x-amz-meta-deleteondownload"]
        },
        exposeHeaders: ["etag","content-length","content-type"],
        maxAgeSeconds: 3600
      }
    ]
  }')"
  cf_api PUT "/accounts/${CF_ACCOUNT_ID}/r2/buckets/${name}/cors" "$body" >/dev/null
}

# r2_apply_lifecycle NAME LIFECYCLE_JSON_FILE
r2_apply_lifecycle() {
  local name="$1"
  local file="$2"

  if [[ ! -f "$file" ]]; then
    echo "[r2] lifecycle file not found: $file" >&2
    exit 1
  fi

  echo "  - applying lifecycle rules to '${name}'"
  local body
  body="$(cat "$file")"
  cf_api PUT "/accounts/${CF_ACCOUNT_ID}/r2/buckets/${name}/lifecycle" "$body" >/dev/null
}

# r2_create_api_token BUCKETS_CSV
# Creates an R2-scoped API token with "Object Read & Write" on the listed buckets.
# Prints "ACCESS_KEY_ID SECRET_ACCESS_KEY" on stdout on success.
#
# NOTE: Cloudflare only shows the secret once — caller must capture it.
r2_create_api_token() {
  local buckets_csv="$1"
  local bucket_json
  bucket_json="$(echo "$buckets_csv" | tr ',' '\n' | jq -R . | jq -cs 'map({name:.})')"

  local body
  body="$(jq -cn \
    --arg name "relaysecret-worker-$(date +%s)" \
    --argjson buckets "$bucket_json" \
    '{
      name: $name,
      policies: [
        {
          effect: "allow",
          permission_groups: [
            { id: "2efd5506f9c8494dacb1fa10a3e7d5b6" }
          ],
          resources: ({} + ($buckets | map({("com.cloudflare.api.account.r2.bucket." + .name): "*"}) | add))
        }
      ]
    }')"

  local result
  result="$(cf_api POST "/accounts/${CF_ACCOUNT_ID}/r2/tokens" "$body")"
  local access secret
  access="$(echo "$result" | jq -r '.accessKeyId // .access_key_id // empty')"
  secret="$(echo "$result" | jq -r '.secretAccessKey // .secret_access_key // empty')"
  if [[ -z "$access" || -z "$secret" ]]; then
    echo "[r2] failed to parse access/secret from R2 token response" >&2
    echo "$result" >&2
    exit 1
  fi
  echo "${access} ${secret}"
}

# r2_empty_bucket NAME — deletes every object via wrangler
r2_empty_bucket() {
  local name="$1"
  if ! r2_bucket_exists "$name"; then
    return 0
  fi
  echo "  - emptying bucket '${name}' via wrangler r2 object delete"
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "[dry-run] wrangler r2 bucket list + delete objects in $name"
    return 0
  fi
  # wrangler has no recursive delete; iterate via r2 API listing.
  local cursor="" page objs key
  while :; do
    if [[ -n "$cursor" ]]; then
      page="$(cf_api GET "/accounts/${CF_ACCOUNT_ID}/r2/buckets/${name}/objects?per_page=1000&cursor=${cursor}" || echo '{}')"
    else
      page="$(cf_api GET "/accounts/${CF_ACCOUNT_ID}/r2/buckets/${name}/objects?per_page=1000" || echo '{}')"
    fi
    objs="$(echo "$page" | jq -r '.[]?.key // empty' 2>/dev/null || true)"
    [[ -z "$objs" ]] && break
    while IFS= read -r key; do
      [[ -z "$key" ]] && continue
      cf_api DELETE "/accounts/${CF_ACCOUNT_ID}/r2/buckets/${name}/objects/${key}" >/dev/null || true
    done <<< "$objs"
    cursor="$(echo "$page" | jq -r '.cursor // empty' 2>/dev/null || true)"
    [[ -z "$cursor" ]] && break
  done
}

# r2_delete_bucket NAME
r2_delete_bucket() {
  local name="$1"
  if ! r2_bucket_exists "$name"; then
    echo "  - bucket '${name}' does not exist, skipping"
    return 0
  fi
  echo "  - deleting bucket '${name}'"
  cf_api DELETE "/accounts/${CF_ACCOUNT_ID}/r2/buckets/${name}" >/dev/null
}
