// cors.js — CORS helpers. Origin is pinned to env.FRONTEND_ORIGIN in prod.
// If FRONTEND_ORIGIN === "devmode" we allow any origin (wildcard) for local dev.
//
// FRONTEND_ORIGIN may be a single origin ("https://www.example.com") or a
// comma-separated list of origins ("https://www.example.com,https://example.com").
// All listed origins are accepted by the referer gate; the first one is returned
// in Access-Control-Allow-Origin (browsers only send one origin per request, so
// we reflect the matching one for correctness).

function allowedOrigins(env) {
  if (!env.FRONTEND_ORIGIN || env.FRONTEND_ORIGIN === 'devmode') return null;
  return env.FRONTEND_ORIGIN.split(',').map(o => o.trim()).filter(Boolean);
}

export function allowOrigin(env, request) {
  const origins = allowedOrigins(env);
  if (!origins) return '*';
  // Reflect the request's own origin if it's in the allow-list.
  const reqOrigin = (request && request.headers.get('Origin')) || '';
  if (reqOrigin && origins.includes(reqOrigin)) return reqOrigin;
  // Fall back to the primary (first) allowed origin.
  return origins[0];
}

export function corsHeaders(env, request) {
  return {
    'Access-Control-Allow-Origin': allowOrigin(env, request),
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
    'Access-Control-Max-Age': '86400',
  };
}

// handlePreflight — respond to OPTIONS requests uniformly.
export function handlePreflight(request, env) {
  return new Response(null, { status: 204, headers: corsHeaders(env, request) });
}

// refererGate — mirrors lambda.py: in prod, reject anything whose Origin or
// Referer does not start with one of the allowed FRONTEND_ORIGIN values.
// Devmode disables the check.
// Returns null when the request is allowed, otherwise a 403 Response.
export function refererGate(request, env) {
  const origins = allowedOrigins(env);
  if (!origins) return null;
  const origin = request.headers.get('Origin') || '';
  const referer = request.headers.get('Referer') || '';
  const ok = origins.some(
    o => origin.startsWith(o) || referer.startsWith(o)
  );
  if (ok) return null;
  return new Response(
    JSON.stringify({ error: 'origin not allowed', code: 'FORBIDDEN' }),
    {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders(env, request),
      },
    }
  );
}
