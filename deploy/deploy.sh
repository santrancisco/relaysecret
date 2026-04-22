#!/usr/bin/env bash
# deploy/deploy.sh — one-shot RelaySecret deploy to Cloudflare.
# See deploy/README.md for prereqs and token permissions.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKER_DIR="${REPO_ROOT}/worker"
FRONTEND_DIR="${REPO_ROOT}/frontend"
CONFIG_FILE="${SCRIPT_DIR}/config.env"
LIFECYCLE_FILE="${SCRIPT_DIR}/lifecycle.json"

YES=0
DRY_RUN=0
TEARDOWN=0
ONLY=""
SKIP=""

usage() {
  cat <<'EOF'
RelaySecret deploy — provisions / updates the whole Cloudflare stack
(R2 buckets, KV namespace, Worker, Pages site) from deploy/config.env.

USAGE
  ./deploy/deploy.sh [flags]

FLAGS
  --yes              Skip interactive confirmations. Required for non-TTY runs
                     (CI, pipes). Teardown still asks for it twice.
  --dry-run          Print every Cloudflare API call and wrangler invocation
                     without touching the network or mutating state.
  --teardown         DESTROY everything this script created: Pages project,
                     Worker, KV namespace, R2 buckets (emptied first), and
                     DNS records for FRONTEND_HOST / API_HOST. Irreversible.
  --only=STEPS       Run ONLY the listed steps (comma-separated). Preflight
                     always runs. Mutually exclusive with --skip.
  --skip=STEPS       Run everything EXCEPT the listed steps (comma-separated).
  -h, --help         Show this help and exit.

STEPS (for --only / --skip)
  r2       Create the three regional R2 buckets, apply lifecycle + CORS.
  kv       Create the clipboard KV namespace. Exports KV_NAMESPACE_ID for
           the worker step. If you skip kv, set KV_NAMESPACE_ID in config.env.
  worker   Render wrangler.toml, deploy the Worker, push secrets, bind the
           API_HOST custom domain. Requires R2 credentials in config.env.
  pages    Build the frontend (with placeholder substitution) and deploy
           the Pages project, attach FRONTEND_HOST + apex domain.
  smoke    Hit the API and frontend over HTTPS to verify the deploy.

EXAMPLES
  # First-time deploy, non-interactive
  ./deploy/deploy.sh --yes

  # Push only the frontend (fastest iteration loop for HTML/CSS/JS changes)
  ./deploy/deploy.sh --only=pages --yes

  # Re-deploy the worker after editing worker/ source
  ./deploy/deploy.sh --only=worker --yes

  # Frontend + worker together, skip infra and smoke test
  ./deploy/deploy.sh --only=worker,pages --yes

  # Everything except the smoke test
  ./deploy/deploy.sh --skip=smoke --yes

  # See exactly what a full run would do, no side effects
  ./deploy/deploy.sh --dry-run --yes

  # Burn it all down
  ./deploy/deploy.sh --teardown --yes

NOTES
  * Preflight (config + binary checks, token verify, zone lookup) always runs.
  * --only and --skip cannot be combined; --only wins if both are given.
  * For tiny one-off changes you can also bypass this script entirely:
      (cd worker && wrangler deploy)
      wrangler pages deploy frontend --project-name="$PAGES_PROJECT"
EOF
}

for arg in "$@"; do
  case "$arg" in
    --yes)      YES=1 ;;
    --dry-run)  DRY_RUN=1 ;;
    --teardown) TEARDOWN=1 ;;
    --only=*)   ONLY="${arg#--only=}" ;;
    --skip=*)   SKIP="${arg#--skip=}" ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown flag: $arg" >&2
      echo "run '$0 --help' for usage" >&2
      exit 1
      ;;
  esac
done
export DRY_RUN

# step_enabled NAME — returns 0 if the step should run given --only / --skip.
# Steps: r2, kv, worker, pages, smoke. Preflight always runs.
step_enabled() {
  local name="$1"
  if [[ -n "$ONLY" ]]; then
    [[ ",${ONLY}," == *",${name},"* ]]
    return $?
  fi
  if [[ -n "$SKIP" ]]; then
    [[ ",${SKIP}," == *",${name},"* ]] && return 1
  fi
  return 0
}

# ---------- pretty output ----------
banner() {
  echo
  echo "============================================================"
  echo "== $*"
  echo "============================================================"
}
info()  { echo "   $*"; }
warn()  { echo "!! $*" >&2; }
die()   { echo "!! $*" >&2; exit 1; }

confirm() {
  local prompt="$1"
  if [[ "$YES" -eq 1 ]]; then
    return 0
  fi
  if [[ ! -t 0 ]]; then
    die "refusing to run destructive action without --yes in non-interactive mode"
  fi
  read -r -p "${prompt} [y/N] " ans
  [[ "${ans:-}" =~ ^[Yy]$ ]]
}

# ---------- load libs ----------
# shellcheck source=lib/cf_api.sh
source "${SCRIPT_DIR}/lib/cf_api.sh"
# shellcheck source=lib/r2.sh
source "${SCRIPT_DIR}/lib/r2.sh"
# shellcheck source=lib/kv.sh
source "${SCRIPT_DIR}/lib/kv.sh"
# shellcheck source=lib/worker.sh
source "${SCRIPT_DIR}/lib/worker.sh"
# shellcheck source=lib/pages.sh
source "${SCRIPT_DIR}/lib/pages.sh"
# shellcheck source=lib/dns.sh
source "${SCRIPT_DIR}/lib/dns.sh"

# ---------- load config ----------
if [[ ! -f "$CONFIG_FILE" ]]; then
  die "missing ${CONFIG_FILE}. Copy ${SCRIPT_DIR}/config.example.env to ${CONFIG_FILE} and fill it in."
fi
# shellcheck disable=SC1090
set -a; source "$CONFIG_FILE"; set +a

# defaults
: "${VT_API_KEY:=none}"
: "${HMAC_SECRET:=none}"
: "${PAGES_PROJECT:=relaysecret}"
: "${WORKER_NAME:=relaysecret}"
: "${R2_BUCKET_US:=relaysecret-us}"
: "${R2_BUCKET_EU:=relaysecret-eu}"
: "${R2_BUCKET_APAC:=relaysecret-apac}"
: "${CLOUDFLARE_ZONE_ID:=}"

# ---------- validate ----------
banner "Preflight"

for v in CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID DOMAIN FRONTEND_HOST API_HOST; do
  if [[ -z "${!v:-}" ]]; then
    die "config.env is missing required variable: ${v}"
  fi
done

for bin in curl jq openssl wrangler; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    die "required binary not found in PATH: ${bin}"
  fi
done
info "wrangler: $(wrangler --version 2>/dev/null | head -n1)"

if [[ -z "${SEED}" ]]; then
  SEED="$(openssl rand -hex 32)"
  info "generated SEED (length=${#SEED})"
fi

# verify token
info "verifying CLOUDFLARE_API_TOKEN..."
info "  token length : ${#CLOUDFLARE_API_TOKEN}"
info "  token prefix : ${CLOUDFLARE_API_TOKEN:0:6}... (first 6 chars)"
if [[ "$DRY_RUN" -eq 1 ]]; then
  info "[dry-run] skipping token verify"
else
  info "  calling GET ${CF_API_BASE:-https://api.cloudflare.com/client/v4}/user/tokens/verify"
  raw_verify_resp=""
  verify_http_code=""
  {
    tmp_verify="$(mktemp)"
    verify_http_code="$(curl -sS -o "$tmp_verify" -w '%{http_code}' \
      -X GET \
      -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
      "https://api.cloudflare.com/client/v4/user/tokens/verify")"
    raw_verify_resp="$(cat "$tmp_verify")"
    rm -f "$tmp_verify"
  }
  info "  HTTP status  : ${verify_http_code}"
  info "  raw response : ${raw_verify_resp}"
  # Attempt to parse; fall back gracefully if non-JSON
  if ! echo "$raw_verify_resp" | jq -e . >/dev/null 2>&1; then
    die "CLOUDFLARE_API_TOKEN verify failed: non-JSON response (HTTP ${verify_http_code}): ${raw_verify_resp}"
  fi
  verify_success="$(echo "$raw_verify_resp" | jq -r '.success // false')"
  verify_errors="$(echo "$raw_verify_resp" | jq -c '.errors // []')"
  verify_result="$(echo "$raw_verify_resp" | jq -c '.result // {}')"
  info "  success      : ${verify_success}"
  info "  errors       : ${verify_errors}"
  info "  result       : ${verify_result}"
  if [[ "$verify_success" != "true" ]]; then
    die "CLOUDFLARE_API_TOKEN verify failed (HTTP ${verify_http_code}): errors=${verify_errors}"
  fi
  status="$(echo "$raw_verify_resp" | jq -r '.result.status // empty')"
  info "  token status : ${status}"
  if [[ "$status" != "active" ]]; then
    die "CLOUDFLARE_API_TOKEN is not active (status='${status}'). Check the token in the Cloudflare dashboard: https://dash.cloudflare.com/profile/api-tokens"
  fi
  info "token is active"
fi

# resolve zone id
if [[ -z "$CLOUDFLARE_ZONE_ID" ]]; then
  info "looking up zone id for ${DOMAIN}..."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    CLOUDFLARE_ZONE_ID="00000000000000000000000000000000"
    info "[dry-run] using stub zone id"
  else
    CLOUDFLARE_ZONE_ID="$(dns_lookup_zone_id "$DOMAIN")"
  fi
fi
info "zone id: ${CLOUDFLARE_ZONE_ID}"

export CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID CLOUDFLARE_ZONE_ID DOMAIN FRONTEND_HOST API_HOST \
       VT_API_KEY HMAC_SECRET SEED PAGES_PROJECT WORKER_NAME \
       R2_BUCKET_US R2_BUCKET_EU R2_BUCKET_APAC

# ---------- TEARDOWN path ----------
if [[ "$TEARDOWN" -eq 1 ]]; then
  banner "TEARDOWN — this will DELETE everything RelaySecret-related in this account"
  warn "Pages project:  ${PAGES_PROJECT}"
  warn "Worker:         ${WORKER_NAME}"
  warn "KV namespace:   relaysecret-clipboard"
  warn "R2 buckets:     ${R2_BUCKET_US}, ${R2_BUCKET_EU}, ${R2_BUCKET_APAC} (and all objects)"
  warn "DNS records:    ${FRONTEND_HOST}, ${API_HOST}"
  confirm "Proceed with teardown?" || die "aborted"
  confirm "Really really proceed? This is irreversible." || die "aborted"

  banner "[teardown] DNS"
  dns_delete_record "$CLOUDFLARE_ZONE_ID" "$FRONTEND_HOST" CNAME || true
  dns_delete_record "$CLOUDFLARE_ZONE_ID" "$DOMAIN"        CNAME || true
  dns_delete_record "$CLOUDFLARE_ZONE_ID" "$API_HOST"      AAAA  || true

  banner "[teardown] Pages"
  pages_detach_domain "$PAGES_PROJECT" "$FRONTEND_HOST" || true
  pages_detach_domain "$PAGES_PROJECT" "$DOMAIN" || true
  pages_delete_project "$PAGES_PROJECT" || true

  banner "[teardown] Worker"
  worker_unpublish "$WORKER_NAME" || true

  banner "[teardown] KV"
  kv_delete_namespace "relaysecret-clipboard" || true

  banner "[teardown] R2"
  for b in "$R2_BUCKET_US" "$R2_BUCKET_EU" "$R2_BUCKET_APAC"; do
    r2_empty_bucket "$b" || true
    r2_delete_bucket "$b" || true
  done

  banner "Teardown complete."
  exit 0
fi

# ---------- confirm before mutating ----------
if [[ "$DRY_RUN" -ne 1 ]]; then
  confirm "About to deploy RelaySecret to ${DOMAIN} (frontend=${FRONTEND_HOST}, api=${API_HOST}). Continue?" \
    || die "aborted"
fi

# FRONTEND_ORIGIN is needed by multiple steps (R2 CORS and worker secrets).
# Include the apex domain alongside FRONTEND_HOST so both are accepted by the
# worker's referer gate (comma-separated list, first entry is the canonical one).
if [[ "${FRONTEND_HOST}" == www.* ]]; then
  _apex_origin="https://${FRONTEND_HOST#www.}"
  FRONTEND_ORIGIN="https://${FRONTEND_HOST},${_apex_origin}"
else
  FRONTEND_ORIGIN="https://${FRONTEND_HOST}"
fi
unset _apex_origin

# ---------- R2 ----------
if step_enabled r2; then
  banner "R2 buckets"
  r2_create_bucket "$R2_BUCKET_US"   wnam
  r2_create_bucket "$R2_BUCKET_EU"   eeur
  r2_create_bucket "$R2_BUCKET_APAC" apac
  r2_apply_lifecycle "$R2_BUCKET_US"   "$LIFECYCLE_FILE"
  r2_apply_lifecycle "$R2_BUCKET_EU"   "$LIFECYCLE_FILE"
  r2_apply_lifecycle "$R2_BUCKET_APAC" "$LIFECYCLE_FILE"

  # CORS — required so the browser can PUT/GET directly against R2 with
  # x-amz-meta-* custom headers. Without this the whole presign model is dead.
  r2_apply_cors "$R2_BUCKET_US"   "$FRONTEND_ORIGIN"
  r2_apply_cors "$R2_BUCKET_EU"   "$FRONTEND_ORIGIN"
  r2_apply_cors "$R2_BUCKET_APAC" "$FRONTEND_ORIGIN"
else
  info "skipping R2 step (per --only/--skip)"
fi

# ---------- KV ----------
if step_enabled kv; then
  banner "KV namespace"
  KV_NAMESPACE_ID="$(kv_create_namespace "relaysecret-clipboard")"
  info "KV namespace id: ${KV_NAMESPACE_ID}"
  export KV_NAMESPACE_ID
else
  info "skipping KV step (per --only/--skip)"
fi

# ---------- Worker (wrangler.toml + deploy + secrets + domain) ----------
if step_enabled worker; then
  # R2 credentials check — only required for the worker step, since that's
  # where they get piped into `wrangler secret put`.
  banner "R2 credentials for the Worker"
  if [[ "$DRY_RUN" -eq 1 && -z "${R2_ACCESS_KEY_ID:-}" ]]; then
    R2_ACCESS_KEY_ID="DRYRUNACCESSKEY"
    R2_SECRET_ACCESS_KEY="DRYRUNSECRETKEY"
    info "[dry-run] using stub R2 credentials"
  elif [[ -n "${R2_ACCESS_KEY_ID:-}" && -n "${R2_SECRET_ACCESS_KEY:-}" ]]; then
    info "using R2_ACCESS_KEY_ID / R2_SECRET_ACCESS_KEY from config.env"
  else
    cat <<EOF >&2

!! R2_ACCESS_KEY_ID / R2_SECRET_ACCESS_KEY are missing from deploy/config.env.
!! Create them in the dashboard:
!!   https://dash.cloudflare.com/?to=/:account/r2/api-tokens
!! and paste into config.env, then re-run.
EOF
    die "R2 credentials required"
  fi

  # wrangler.toml render requires KV_NAMESPACE_ID. If KV step was skipped,
  # the user must supply it via config.env.
  if [[ -z "${KV_NAMESPACE_ID:-}" ]]; then
    die "KV_NAMESPACE_ID is empty — run the 'kv' step too, or set it in config.env"
  fi

  banner "Worker: wrangler.toml"
  WRANGLER_TEMPLATE="${WORKER_DIR}/wrangler.toml.example"
  WRANGLER_OUT="${WORKER_DIR}/wrangler.toml"
  if [[ ! -f "$WRANGLER_TEMPLATE" ]]; then
    die "missing ${WRANGLER_TEMPLATE}"
  fi
  worker_render_wrangler_toml "$WRANGLER_TEMPLATE" "$WRANGLER_OUT"

  banner "Worker: deploy"
  worker_deploy "$WORKER_DIR"

  banner "Worker: secrets"
  worker_put_secret "$WORKER_DIR" R2_ACCESS_KEY_ID     "$R2_ACCESS_KEY_ID"
  worker_put_secret "$WORKER_DIR" R2_SECRET_ACCESS_KEY "$R2_SECRET_ACCESS_KEY"
  worker_put_secret "$WORKER_DIR" R2_ACCOUNT_ID        "$CLOUDFLARE_ACCOUNT_ID"
  worker_put_secret "$WORKER_DIR" VT_API_KEY           "$VT_API_KEY"
  worker_put_secret "$WORKER_DIR" HMAC_SECRET          "$HMAC_SECRET"
  worker_put_secret "$WORKER_DIR" FRONTEND_ORIGIN      "$FRONTEND_ORIGIN"
  worker_put_secret "$WORKER_DIR" SEED                 "$SEED"

  banner "Worker: custom domain ${API_HOST}"
  worker_bind_domain "$API_HOST" "$WORKER_NAME" "$CLOUDFLARE_ZONE_ID"
else
  info "skipping Worker step (per --only/--skip)"
fi

# ---------- Pages step ----------
if ! step_enabled pages; then
  info "skipping Pages step (per --only/--skip)"
else

# ---------- Frontend build dir (never mutate the source tree) ----------
banner "Frontend: build"
BUILD_DIR="$(mktemp -d -t relaysecret-pages.XXXXXX)"
trap 'rm -rf "$BUILD_DIR"' EXIT
info "build dir: ${BUILD_DIR}"

if [[ "$DRY_RUN" -eq 1 ]]; then
  info "[dry-run] would cp -R ${FRONTEND_DIR}/ ${BUILD_DIR}/, substitute worker origin + HMAC exp token"
else
  # -a preserves timestamps and permissions. Trailing "/." copies contents.
  cp -a "${FRONTEND_DIR}/." "${BUILD_DIR}/"

  # Docs are not deployable assets and may contain the literal placeholder
  # as explanatory text. Drop them from the build dir so (a) Pages isn't
  # serving them and (b) the sanity-check grep below doesn't false-positive.
  rm -f "${BUILD_DIR}/README.md" "${BUILD_DIR}/README"

  HEADERS_FILE="${BUILD_DIR}/_headers"
  CONFIG_JS="${BUILD_DIR}/assets/config.js"

  if [[ -f "$HEADERS_FILE" ]]; then
    tmp="$(mktemp)"
    sed "s|<WORKER_ORIGIN_PLACEHOLDER>|https://${API_HOST}|g" "$HEADERS_FILE" > "$tmp"
    mv "$tmp" "$HEADERS_FILE"
    info "patched ${HEADERS_FILE}"
  else
    warn "missing ${HEADERS_FILE} — skipping CSP substitution"
  fi

  # Generate the HMAC upload token for the HMAC gate.
  # When HMAC_SECRET is "none" we embed an empty string — the Worker ignores it.
  # When set, we mint a token that expires 3 years from now so operators don't
  # need to redeploy just to refresh the token. Rotate by changing HMAC_SECRET
  # and redeploying both the worker (new secret) and pages (new token).
  #
  # Token format: "<unix_expiry>.<hex_hmac_sha256(secret, ascii_expiry)>"
  # This matches the format validated by worker/src/util/hmacGate.js.
  UPLOAD_EXP_VALUE=""
  if [[ "${HMAC_SECRET}" != "none" && -n "${HMAC_SECRET}" ]]; then
    EXP_TS=$(( $(date +%s) + 3 * 365 * 24 * 3600 ))
    EXP_HMAC="$(printf '%s' "${EXP_TS}" | \
      openssl dgst -sha256 -hmac "${HMAC_SECRET}" -hex | \
      awk '{print $NF}')"
    UPLOAD_EXP_VALUE="${EXP_TS}.${EXP_HMAC}"
    info "generated uploadExp token (expires $(date -d "@${EXP_TS}" '+%Y-%m-%d' 2>/dev/null || date -r "${EXP_TS}" '+%Y-%m-%d' 2>/dev/null || echo "unix:${EXP_TS}"))"
  else
    info "HMAC_SECRET is 'none' — uploadExp token will be empty (gate disabled)"
  fi

  if [[ -f "$CONFIG_JS" ]]; then
    tmp="$(mktemp)"
    sed -e "s|<WORKER_ORIGIN_PLACEHOLDER>|https://${API_HOST}|g" \
        -e "s|__API_HOST__|${API_HOST}|g" \
        -e "s|<UPLOAD_EXP_PLACEHOLDER>|${UPLOAD_EXP_VALUE}|g" \
        "$CONFIG_JS" > "$tmp"
    mv "$tmp" "$CONFIG_JS"
    info "patched ${CONFIG_JS}"
  else
    warn "missing ${CONFIG_JS} — skipping JS substitution"
  fi

  # Cache busting: Cloudflare Pages forces a 4h max-age on /assets/* and
  # ignores Cache-Control overrides for that path. Stamp every asset URL in
  # every HTML file with a per-deploy version query so phones that already
  # cached the old file are forced to refetch.
  BUILD_VERSION="$(date +%s)"
  python3 - "$BUILD_DIR" "$BUILD_VERSION" <<'PY'
import os, re, sys
build_dir, version = sys.argv[1], sys.argv[2]
pat = re.compile(r'(/assets/[A-Za-z0-9_./-]+\.(?:js|css|svg))')
for root, _, files in os.walk(build_dir):
    for name in files:
        if not name.endswith('.html'):
            continue
        p = os.path.join(root, name)
        with open(p, 'r', encoding='utf-8') as f:
            src = f.read()
        out = pat.sub(lambda m: m.group(1) + '?v=' + version, src)
        if out != src:
            with open(p, 'w', encoding='utf-8') as f:
                f.write(out)
PY
  info "stamped asset URLs with v=${BUILD_VERSION}"

  # Sanity check: the placeholder must not remain anywhere in the build.
  if grep -RIn '<WORKER_ORIGIN_PLACEHOLDER>' "$BUILD_DIR" >/dev/null 2>&1; then
    die "build sanity check failed: <WORKER_ORIGIN_PLACEHOLDER> still present in ${BUILD_DIR}"
  fi
  if grep -RIn '<UPLOAD_EXP_PLACEHOLDER>' "$BUILD_DIR" >/dev/null 2>&1; then
    die "build sanity check failed: <UPLOAD_EXP_PLACEHOLDER> still present in ${BUILD_DIR}"
  fi
fi

# ---------- Pages ----------
banner "Pages: project"
pages_create_project "$PAGES_PROJECT" main

banner "Pages: deploy ${BUILD_DIR}"
pages_deploy "$PAGES_PROJECT" "$BUILD_DIR"

banner "Pages: DNS records"
# Pages cannot activate a custom domain without a DNS record already in place.
# We upsert proxied CNAMEs pointing at the Pages project's default subdomain
# before attaching the domain, so verification succeeds on first run.
dns_upsert_record "$CLOUDFLARE_ZONE_ID" "$FRONTEND_HOST" CNAME "${PAGES_PROJECT}.pages.dev" true
dns_upsert_record "$CLOUDFLARE_ZONE_ID" "$DOMAIN"        CNAME "${PAGES_PROJECT}.pages.dev" true

banner "Pages: custom domains"
pages_attach_domain "$PAGES_PROJECT" "$FRONTEND_HOST"
pages_attach_domain "$PAGES_PROJECT" "$DOMAIN"

# Trigger re-verification in case the domains were previously stuck as pending.
info "triggering domain re-verification..."
pages_reverify_domain "$PAGES_PROJECT" "$FRONTEND_HOST"
pages_reverify_domain "$PAGES_PROJECT" "$DOMAIN"

fi  # <-- end of `if step_enabled pages`

# ---------- smoke test ----------
if ! step_enabled smoke; then
  info "skipping smoke test (per --only/--skip)"
elif [[ "$DRY_RUN" -eq 1 ]]; then
  banner "Smoke test"
  info "[dry-run] skipping smoke test"
else
  banner "Smoke test"
  info "GET https://${API_HOST}/sha1/0000000000000000000000000000000000000000"
  api_code="$(curl -sS -o /dev/null -w '%{http_code}' \
    "https://${API_HOST}/sha1/0000000000000000000000000000000000000000" || echo 000)"
  info "  -> HTTP ${api_code}"
  case "$api_code" in
    200|404) info "  OK" ;;
    000)     warn "  could not reach worker (DNS may still be propagating)" ;;
    5*)      warn "  worker returned ${api_code} — check 'wrangler tail'" ;;
    *)       info "  non-fatal: got ${api_code}" ;;
  esac

  info "HEAD https://${FRONTEND_HOST}"
  fe_headers="$(curl -sS -I "https://${FRONTEND_HOST}" || true)"
  fe_code="$(echo "$fe_headers" | awk 'NR==1 {print $2}')"
  info "  -> HTTP ${fe_code:-???}"
  if echo "$fe_headers" | grep -qi '^content-security-policy:'; then
    if echo "$fe_headers" | grep -i '^content-security-policy:' | grep -q "${API_HOST}"; then
      info "  CSP present and contains ${API_HOST}"
    else
      warn "  CSP present but does not mention ${API_HOST}"
    fi
  else
    warn "  no CSP header on frontend response (may still be propagating)"
  fi
fi

# ---------- summary ----------
banner "DONE"
cat <<EOF
RelaySecret is deployed.

  Frontend : https://${FRONTEND_HOST}
  Apex     : https://${DOMAIN}
  API      : https://${API_HOST}
  Worker   : ${WORKER_NAME}
  Pages    : ${PAGES_PROJECT}
  R2       : ${R2_BUCKET_US} / ${R2_BUCKET_EU} / ${R2_BUCKET_APAC}
  KV       : relaysecret-clipboard (id=${KV_NAMESPACE_ID:-<skipped>})

Rotate a secret:
  (cd worker && printf 'NEW_VALUE' | wrangler secret put VT_API_KEY)

Redeploy only the frontend:
  wrangler pages deploy frontend --project-name=${PAGES_PROJECT}

Redeploy only the worker:
  (cd worker && wrangler deploy)

Tear everything down (irreversible):
  ./deploy/deploy.sh --teardown --yes
EOF
