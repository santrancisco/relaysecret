// Single source of truth for the Worker base URL.
//
// This file ships with the literal placeholder `<WORKER_ORIGIN_PLACEHOLDER>`.
// deploy/deploy.sh substitutes it with `https://$API_HOST` at deploy time,
// in a build copy under /tmp — the committed file is never mutated in place.
//
// For local dev: overwrite this file with:
//   window.CONFIG = { workerUrl: 'http://localhost:8787' };
// (api.js treats an empty/trailing-slash URL safely.)
window.CONFIG = {
  workerUrl: '<WORKER_ORIGIN_PLACEHOLDER>',
};
