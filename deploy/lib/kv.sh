#!/usr/bin/env bash
# lib/kv.sh — Workers KV namespace helpers
set -euo pipefail

# shellcheck source=./cf_api.sh
source "$(dirname "${BASH_SOURCE[0]}")/cf_api.sh"

# kv_find_namespace_id TITLE
# Prints namespace id if a namespace with that title already exists, else empty.
kv_find_namespace_id() {
  local title="$1"
  local resp
  resp="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/storage/kv/namespaces?per_page=100")" || return 0
  echo "$resp" | jq -r --arg t "$title" '.[] | select(.title == $t) | .id' | head -n1
}

# kv_create_namespace TITLE -> prints namespace id (stdout)
kv_create_namespace() {
  local title="$1"
  local id
  id="$(kv_find_namespace_id "$title" || true)"
  if [[ -n "$id" && "$id" != "null" ]]; then
    echo "  - KV namespace '${title}' already exists (id=${id})" >&2
    printf '%s' "$id"
    return 0
  fi

  echo "  - creating KV namespace '${title}'" >&2
  local body result
  body="$(jq -cn --arg t "$title" '{title:$t}')"
  result="$(cf_api POST "/accounts/${CLOUDFLARE_ACCOUNT_ID}/storage/kv/namespaces" "$body")"
  id="$(echo "$result" | jq -r '.id')"
  if [[ -z "$id" || "$id" == "null" ]]; then
    echo "[kv] failed to parse namespace id from create response" >&2
    echo "$result" >&2
    exit 1
  fi
  printf '%s' "$id"
}

# kv_delete_namespace TITLE
kv_delete_namespace() {
  local title="$1"
  local id
  id="$(kv_find_namespace_id "$title" || true)"
  if [[ -z "$id" || "$id" == "null" ]]; then
    echo "  - KV namespace '${title}' does not exist, skipping"
    return 0
  fi
  echo "  - deleting KV namespace '${title}' (id=${id})"
  cf_api DELETE "/accounts/${CLOUDFLARE_ACCOUNT_ID}/storage/kv/namespaces/${id}" >/dev/null
}
