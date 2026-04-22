#!/usr/bin/env bash
# lib/worker.sh — publish Worker + set secrets + bind custom domain
set -euo pipefail

# shellcheck source=./cf_api.sh
source "$(dirname "${BASH_SOURCE[0]}")/cf_api.sh"

# worker_render_wrangler_toml SRC DST
# Substitutes placeholders in wrangler.toml.example to produce wrangler.toml.
# Placeholders (all must be set as env vars before calling):
#   __CLOUDFLARE_ACCOUNT_ID__
#   __WORKER_NAME__
#   __KV_NAMESPACE_ID__
#   __R2_BUCKET_US__  __R2_BUCKET_EU__  __R2_BUCKET_APAC__
#   __API_HOST__
worker_render_wrangler_toml() {
  local src="$1"
  local dst="$2"
  if [[ ! -f "$src" ]]; then
    echo "[worker] wrangler template missing: $src" >&2
    exit 1
  fi

  local content
  content="$(cat "$src")"
  content="${content//__CLOUDFLARE_ACCOUNT_ID__/${CLOUDFLARE_ACCOUNT_ID}}"
  content="${content//__WORKER_NAME__/${WORKER_NAME}}"
  content="${content//__KV_NAMESPACE_ID__/${KV_NAMESPACE_ID}}"
  content="${content//__R2_BUCKET_US__/${R2_BUCKET_US}}"
  content="${content//__R2_BUCKET_EU__/${R2_BUCKET_EU}}"
  content="${content//__R2_BUCKET_APAC__/${R2_BUCKET_APAC}}"
  content="${content//__API_HOST__/${API_HOST}}"

  printf '%s\n' "$content" > "$dst"
  echo "  - wrote ${dst}"
}

# _wrangler_run WORKER_DIR -- ARGS...
_wrangler_run() {
  local dir="$1"; shift
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "[dry-run] (cd ${dir} && wrangler $*)"
    return 0
  fi
  (cd "$dir" && wrangler "$@")
}

# worker_deploy WORKER_DIR
worker_deploy() {
  local dir="$1"
  echo "  - wrangler deploy (from ${dir})"
  _wrangler_run "$dir" deploy
}

# worker_put_secret WORKER_DIR NAME VALUE
worker_put_secret() {
  local dir="$1"
  local name="$2"
  local value="$3"
  echo "  - wrangler secret put ${name}"
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "[dry-run] printf '***' | (cd ${dir} && wrangler secret put ${name})"
    return 0
  fi
  # shellcheck disable=SC2031
  (cd "$dir" && printf '%s' "$value" | wrangler secret put "$name")
}

# worker_delete_secret WORKER_DIR NAME
worker_delete_secret() {
  local dir="$1"
  local name="$2"
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "[dry-run] (cd ${dir} && wrangler secret delete ${name} --force)"
    return 0
  fi
  (cd "$dir" && wrangler secret delete "$name" --force) || true
}

# worker_bind_domain API_HOST WORKER_NAME ZONE_ID
# Creates a Worker custom domain via the Cloudflare API (idempotent).
worker_bind_domain() {
  local host="$1"
  local name="$2"
  local zone="$3"

  # Look up existing domains
  local existing
  existing="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/domains" || echo '[]')"
  local found
  found="$(echo "$existing" | jq -r --arg h "$host" --arg n "$name" \
    '.[]? | select(.hostname==$h and .service==$n) | .id' | head -n1)"
  if [[ -n "$found" && "$found" != "null" ]]; then
    echo "  - custom domain '${host}' already bound to worker '${name}'"
    return 0
  fi

  echo "  - binding custom domain '${host}' to worker '${name}'"
  # override_existing_dns_record=true tells Cloudflare to atomically replace
  # any pre-existing A/CNAME at $host (e.g. leftover from a previous AWS
  # deployment) with the Worker's managed record. Without this flag the
  # API 409s with code 100117.
  local body
  body="$(jq -cn \
    --arg zone "$zone" \
    --arg host "$host" \
    --arg svc "$name" \
    --arg env "production" \
    '{
      zone_id: $zone,
      hostname: $host,
      service: $svc,
      environment: $env,
      override_existing_dns_record: true
    }')"
  cf_api PUT "/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/domains" "$body" >/dev/null
}

# worker_unpublish WORKER_NAME
worker_unpublish() {
  local name="$1"
  echo "  - deleting worker script '${name}'"
  cf_api_try DELETE "/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${name}?force=true" >/dev/null || true
}
