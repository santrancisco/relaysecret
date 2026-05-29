// Single source of truth for the Worker base URL and optional HMAC upload token.
//
// This file ships with literal placeholders that deploy/deploy.sh substitutes
// at deploy time in a build copy under /tmp — the committed file is never
// mutated in place.
//
// workerUrl: the Worker API origin.
// uploadExp: a time-bound HMAC token (format: "<unix_ts>.<hex>") used by the
//   Worker's HMAC gate (env.HMAC_SECRET). When HMAC_SECRET is "none" (the
//   default) this field is ignored by the Worker and the empty string is fine.
//   deploy.sh generates and embeds a fresh long-lived token automatically when
//   HMAC_SECRET is set. Rotate by re-running deploy.sh --only=pages,worker.
//
// For local dev: overwrite this file with:
//   window.CONFIG = { workerUrl: 'http://localhost:8787', uploadExp: '' };
// (api.js treats an empty/trailing-slash URL and an empty uploadExp safely.)
window.CONFIG = {
  workerUrl: '<WORKER_ORIGIN_PLACEHOLDER>',
  uploadExp: '<UPLOAD_EXP_PLACEHOLDER>',
};
