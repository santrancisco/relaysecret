#!/usr/bin/env bash
# lib/dns.sh — zone lookup + idempotent DNS record upsert
set -euo pipefail

# shellcheck source=./cf_api.sh
source "$(dirname "${BASH_SOURCE[0]}")/cf_api.sh"

# dns_lookup_zone_id DOMAIN -> prints zone id
dns_lookup_zone_id() {
  local domain="$1"
  local resp
  resp="$(cf_api GET "/zones?name=${domain}&status=active")"
  local id
  id="$(echo "$resp" | jq -r '.[0].id // empty')"
  if [[ -z "$id" ]]; then
    echo "[dns] zone not found for domain '${domain}'. Add it to your Cloudflare account first." >&2
    exit 1
  fi
  printf '%s' "$id"
}

# dns_find_record ZONE_ID NAME TYPE -> prints record id or empty
dns_find_record() {
  local zone="$1" name="$2" type="$3"
  local resp
  resp="$(cf_api GET "/zones/${zone}/dns_records?type=${type}&name=${name}")"
  echo "$resp" | jq -r '.[0].id // empty'
}

# dns_upsert_record ZONE_ID NAME TYPE CONTENT PROXIED(true|false)
dns_upsert_record() {
  local zone="$1" name="$2" type="$3" content="$4" proxied="$5"

  local existing_id
  existing_id="$(dns_find_record "$zone" "$name" "$type" || true)"

  local body
  body="$(jq -cn \
    --arg name "$name" \
    --arg type "$type" \
    --arg content "$content" \
    --argjson proxied "$proxied" \
    '{type:$type, name:$name, content:$content, ttl:1, proxied:$proxied}')"

  if [[ -n "$existing_id" ]]; then
    echo "  - updating DNS ${type} ${name} -> ${content} (proxied=${proxied})"
    cf_api PUT "/zones/${zone}/dns_records/${existing_id}" "$body" >/dev/null
  else
    echo "  - creating DNS ${type} ${name} -> ${content} (proxied=${proxied})"
    cf_api POST "/zones/${zone}/dns_records" "$body" >/dev/null
  fi
}

# dns_delete_record ZONE_ID NAME TYPE
dns_delete_record() {
  local zone="$1" name="$2" type="$3"
  local id
  id="$(dns_find_record "$zone" "$name" "$type" || true)"
  [[ -z "$id" ]] && return 0
  echo "  - deleting DNS ${type} ${name}"
  cf_api DELETE "/zones/${zone}/dns_records/${id}" >/dev/null
}
