// regions.js — resolves a `?region=` query param to the concrete binding and
// bucket metadata. Anything unknown falls back to "us" per docs/API.md.
//
// NOTE: the bucket NAME is read from env so deployments can rename freely
// without touching code. Only the binding name is hard-coded per region.

const TABLE = {
  us:   { binding: 'R2_US',   envName: 'R2_US_BUCKET',   locationHint: 'wnam' },
  eu:   { binding: 'R2_EU',   envName: 'R2_EU_BUCKET',   locationHint: 'eeur' },
  apac: { binding: 'R2_APAC', envName: 'R2_APAC_BUCKET', locationHint: 'apac' },
};

export function resolveRegion(regionParam, env) {
  const key = (regionParam || 'us').toLowerCase();
  const row = TABLE[key] || TABLE.us;
  const realKey = TABLE[key] ? key : 'us';
  return {
    region: realKey,
    binding: env[row.binding],            // R2Bucket object
    bucketName: env[row.envName] || '',   // literal bucket name for presign URL
    locationHint: row.locationHint,
    endpoint: `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  };
}

export function isValidRegion(regionParam) {
  return Object.prototype.hasOwnProperty.call(TABLE, (regionParam || '').toLowerCase());
}
