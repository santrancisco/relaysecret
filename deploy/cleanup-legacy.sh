#!/usr/bin/env bash
# deploy/cleanup-legacy.sh — remove legacy Cloudflare artifacts left over
# from the AWS-era clipboard worker (script name "tunnel") that shadow the
# new RelaySecret worker at api.relaysecret.com.
#
# Deletes:
#   1. Any Worker Route whose script is "tunnel"
#   2. Any Worker Route whose pattern matches $API_HOST/*
#   3. The "tunnel" worker script itself
#
# Idempotent — safe to re-run. Prints what it does.
#
# Usage:
#   ./deploy/cleanup-legacy.sh              # interactive
#   ./deploy/cleanup-legacy.sh --yes        # non-interactive
#   ./deploy/cleanup-legacy.sh --dry-run    # list only, make no changes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.env"

YES=0
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --yes)     YES=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help)
      sed -n '1,25p' "$0"
      exit 0
      ;;
    *) echo "unknown flag: $arg" >&2; exit 1 ;;
  esac
done

banner() { echo; echo "== $*"; }
info()   { echo "   $*"; }
warn()   { echo "!! $*" >&2; }
die()    { echo "!! $*" >&2; exit 1; }

confirm() {
  [[ "$YES" -eq 1 ]] && return 0
  read -r -p "${1} [y/N] " ans
  [[ "${ans:-}" =~ ^[Yy]$ ]]
}

[[ -f "$CONFIG_FILE" ]] || die "missing ${CONFIG_FILE}"
# shellcheck disable=SC1090
set -a; source "$CONFIG_FILE"; set +a

for v in CF_API_TOKEN CF_ACCOUNT_ID DOMAIN API_HOST; do
  [[ -n "${!v:-}" ]] || die "config.env missing required var: $v"
done

for bin in curl jq; do
  command -v "$bin" >/dev/null || die "missing required binary: $bin"
done

API="https://api.cloudflare.com/client/v4"
AUTH=(-H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json")

# Resolve zone id if not set
if [[ -z "${CF_ZONE_ID:-}" ]]; then
  info "looking up zone id for ${DOMAIN}..."
  CF_ZONE_ID="$(curl -sS "${AUTH[@]}" "${API}/zones?name=${DOMAIN}&status=active" \
    | jq -r '.result[0].id // empty')"
  [[ -n "$CF_ZONE_ID" ]] || die "could not resolve zone id for ${DOMAIN}"
fi
info "zone id: ${CF_ZONE_ID}"

# --- 1. Find stale worker routes --------------------------------------------
banner "Scanning Worker Routes on zone ${DOMAIN}"
routes_json="$(curl -sS "${AUTH[@]}" "${API}/zones/${CF_ZONE_ID}/workers/routes")"
success="$(echo "$routes_json" | jq -r '.success')"
[[ "$success" == "true" ]] || { echo "$routes_json" | jq .; die "failed to list routes"; }

# Select routes that either (a) point at the legacy 'tunnel' script, or
# (b) target our API_HOST pattern but belong to anything other than our
# new worker name. Second condition catches a wider range of leftovers.
mapfile -t stale_routes < <(
  echo "$routes_json" | jq -r --arg host "$API_HOST" --arg new "${WORKER_NAME:-relaysecret}" \
    '.result[]?
     | select(.script == "tunnel"
              or (.pattern | test($host) and .script != $new))
     | [.id, .pattern, .script] | @tsv'
)

if [[ "${#stale_routes[@]}" -eq 0 ]]; then
  info "no stale routes found — nothing to do here"
else
  echo "Stale routes that will be deleted:"
  for r in "${stale_routes[@]}"; do
    IFS=$'\t' read -r id pattern script <<<"$r"
    echo "  - ${id}  pattern=${pattern}  script=${script}"
  done
  confirm "Delete these routes?" || die "aborted"
  for r in "${stale_routes[@]}"; do
    IFS=$'\t' read -r id _pattern _script <<<"$r"
    if [[ "$DRY_RUN" -eq 1 ]]; then
      info "[dry-run] DELETE /zones/${CF_ZONE_ID}/workers/routes/${id}"
    else
      resp="$(curl -sS -X DELETE "${AUTH[@]}" \
        "${API}/zones/${CF_ZONE_ID}/workers/routes/${id}")"
      if [[ "$(echo "$resp" | jq -r '.success')" == "true" ]]; then
        info "deleted route ${id}"
      else
        warn "failed to delete route ${id}: $(echo "$resp" | jq -c '.errors')"
      fi
    fi
  done
fi

# --- 2. Delete the legacy 'tunnel' worker script ----------------------------
banner "Checking for legacy worker script 'tunnel'"
probe="$(curl -sS "${AUTH[@]}" \
  "${API}/accounts/${CF_ACCOUNT_ID}/workers/scripts/tunnel" \
  -o /dev/null -w '%{http_code}')"

if [[ "$probe" == "200" ]]; then
  echo "Legacy worker 'tunnel' exists in account ${CF_ACCOUNT_ID}."
  confirm "Delete worker 'tunnel'?" || { info "leaving 'tunnel' in place"; }
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "[dry-run] DELETE /accounts/${CF_ACCOUNT_ID}/workers/scripts/tunnel?force=true"
  else
    resp="$(curl -sS -X DELETE "${AUTH[@]}" \
      "${API}/accounts/${CF_ACCOUNT_ID}/workers/scripts/tunnel?force=true")"
    if [[ "$(echo "$resp" | jq -r '.success')" == "true" ]]; then
      info "deleted worker 'tunnel'"
    else
      warn "failed to delete worker 'tunnel': $(echo "$resp" | jq -c '.errors')"
    fi
  fi
else
  info "no legacy worker 'tunnel' found (HTTP ${probe})"
fi

# --- 3. Verify --------------------------------------------------------------
banner "Verifying api.relaysecret.com now hits the new worker"
if [[ "$DRY_RUN" -eq 1 ]]; then
  info "[dry-run] would curl https://${API_HOST}/"
else
  body="$(curl -sS "https://${API_HOST}/" || true)"
  if [[ "$body" == *'"code":"NOT_FOUND"'* ]]; then
    info "OK — new worker is answering at ${API_HOST}:"
    echo "       ${body}"
  else
    warn "unexpected response from ${API_HOST}/:"
    echo "   ${body}"
    warn "give DNS 30-60s to propagate, or inspect with: curl -v https://${API_HOST}/"
  fi
fi

banner "Cleanup complete."
