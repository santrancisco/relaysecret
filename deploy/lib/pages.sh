#!/usr/bin/env bash
# lib/pages.sh — Cloudflare Pages project + deploy + custom domain
set -euo pipefail

# shellcheck source=./cf_api.sh
source "$(dirname "${BASH_SOURCE[0]}")/cf_api.sh"

# pages_project_exists NAME -> 0 if exists
pages_project_exists() {
  local name="$1"
  cf_api_try GET "/accounts/${CF_ACCOUNT_ID}/pages/projects/${name}" >/dev/null
}

# pages_create_project NAME PRODUCTION_BRANCH
pages_create_project() {
  local name="$1"
  local branch="${2:-main}"

  if pages_project_exists "$name"; then
    echo "  - Pages project '${name}' already exists"
    return 0
  fi
  echo "  - creating Pages project '${name}'"
  local body
  body="$(jq -cn --arg n "$name" --arg b "$branch" \
    '{name:$n, production_branch:$b}')"
  cf_api POST "/accounts/${CF_ACCOUNT_ID}/pages/projects" "$body" >/dev/null
}

# pages_deploy PROJECT DIR
pages_deploy() {
  local project="$1"
  local dir="$2"
  echo "  - wrangler pages deploy ${dir} --project-name=${project}"
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "[dry-run] wrangler pages deploy ${dir} --project-name=${project} --branch=main --commit-dirty=true"
    return 0
  fi
  CLOUDFLARE_API_TOKEN="${CF_API_TOKEN}" CLOUDFLARE_ACCOUNT_ID="${CF_ACCOUNT_ID}" \
    wrangler pages deploy "$dir" \
      --project-name="$project" \
      --branch=main \
      --commit-dirty=true
}

# pages_attach_domain PROJECT HOST
pages_attach_domain() {
  local project="$1"
  local host="$2"

  local existing
  existing="$(cf_api GET "/accounts/${CF_ACCOUNT_ID}/pages/projects/${project}/domains" || echo '[]')"
  local match
  match="$(echo "$existing" | jq -r --arg h "$host" '.[]? | select(.name==$h) | .name' | head -n1)"
  if [[ -n "$match" ]]; then
    echo "  - domain '${host}' already attached to Pages project '${project}'"
    return 0
  fi

  echo "  - attaching '${host}' to Pages project '${project}'"
  local body
  body="$(jq -cn --arg h "$host" '{name:$h}')"
  cf_api POST "/accounts/${CF_ACCOUNT_ID}/pages/projects/${project}/domains" "$body" >/dev/null
}

# pages_detach_domain PROJECT HOST
pages_detach_domain() {
  local project="$1"
  local host="$2"
  cf_api_try DELETE "/accounts/${CF_ACCOUNT_ID}/pages/projects/${project}/domains/${host}" >/dev/null || true
}

# pages_delete_project NAME
pages_delete_project() {
  local name="$1"
  if ! pages_project_exists "$name"; then
    echo "  - Pages project '${name}' does not exist, skipping"
    return 0
  fi
  echo "  - deleting Pages project '${name}'"
  cf_api DELETE "/accounts/${CF_ACCOUNT_ID}/pages/projects/${name}" >/dev/null
}
