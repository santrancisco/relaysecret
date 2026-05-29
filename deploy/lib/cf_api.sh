#!/usr/bin/env bash
# lib/cf_api.sh — thin curl wrapper around api.cloudflare.com/client/v4
#
# Exposes:
#   cf_api METHOD PATH [JSON_BODY]       -> prints `.result` on success
#   cf_api_raw METHOD PATH [JSON_BODY]   -> prints full response JSON
#
# Honours:
#   CLOUDFLARE_API_TOKEN   — bearer token (required)
#   DRY_RUN                — if "1", prints the call and returns a stub success
#
# Fails hard on any non-success response (exit 1) after printing .errors.

set -euo pipefail

CF_API_BASE="https://api.cloudflare.com/client/v4"

_cf_require_token() {
  if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
    echo "[cf_api] CLOUDFLARE_API_TOKEN is not set" >&2
    exit 1
  fi
}

cf_api_raw() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  _cf_require_token

  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "[dry-run] cf_api ${method} ${path} ${body:+<body ${#body} bytes>}" >&2
    # Fake a successful, empty result envelope so callers that `jq` it don't explode.
    printf '{"success":true,"errors":[],"messages":[],"result":{}}'
    return 0
  fi

  local tmp
  tmp="$(mktemp)"
  local http_code
  if [[ -n "$body" ]]; then
    http_code="$(curl -sS -o "$tmp" -w '%{http_code}' \
      -X "$method" \
      -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
      -H "Content-Type: application/json" \
      --data "$body" \
      "${CF_API_BASE}${path}")"
  else
    http_code="$(curl -sS -o "$tmp" -w '%{http_code}' \
      -X "$method" \
      -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
      "${CF_API_BASE}${path}")"
  fi

  local resp
  resp="$(cat "$tmp")"
  rm -f "$tmp"

  # Some endpoints return non-JSON on hard failure; guard jq.
  if ! echo "$resp" | jq -e . >/dev/null 2>&1; then
    echo "[cf_api] ${method} ${path} failed (http ${http_code}), non-JSON response:" >&2
    echo "$resp" >&2
    exit 1
  fi

  local success
  success="$(echo "$resp" | jq -r '.success // false')"
  if [[ "$success" != "true" ]]; then
    echo "[cf_api] ${method} ${path} failed (http ${http_code}):" >&2
    echo "$resp" | jq '.errors // .' >&2
    exit 1
  fi

  echo "$resp"
}

cf_api() {
  cf_api_raw "$@" | jq -c '.result'
}

# Like cf_api but does NOT exit on failure — returns the raw response
# and a non-zero exit code. Used for "might-not-exist" probes.
cf_api_try() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  _cf_require_token

  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "[dry-run] cf_api_try ${method} ${path}" >&2
    printf '{"success":true,"errors":[],"result":{}}'
    return 0
  fi

  local resp
  if [[ -n "$body" ]]; then
    resp="$(curl -sS \
      -X "$method" \
      -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
      -H "Content-Type: application/json" \
      --data "$body" \
      "${CF_API_BASE}${path}")"
  else
    resp="$(curl -sS \
      -X "$method" \
      -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
      "${CF_API_BASE}${path}")"
  fi
  echo "$resp"
  local success
  success="$(echo "$resp" | jq -r '.success // false' 2>/dev/null || echo false)"
  [[ "$success" == "true" ]]
}
