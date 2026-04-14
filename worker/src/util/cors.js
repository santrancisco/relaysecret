// cors.js — CORS helpers. Origin is pinned to env.FRONTEND_ORIGIN in prod.
// If FRONTEND_ORIGIN === "devmode" we allow any origin (wildcard) for local dev.

export function allowOrigin(env) {
  if (!env.FRONTEND_ORIGIN || env.FRONTEND_ORIGIN === 'devmode') return '*';
  return env.FRONTEND_ORIGIN;
}

export function corsHeaders(env /*, request */) {
  return {
    'Access-Control-Allow-Origin': allowOrigin(env),
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
// Referer does not start with FRONTEND_ORIGIN. Devmode disables the check.
// Returns null when the request is allowed, otherwise a 403 Response.
export function refererGate(request, env) {
  if (!env.FRONTEND_ORIGIN || env.FRONTEND_ORIGIN === 'devmode') return null;
  const origin = request.headers.get('Origin') || '';
  const referer = request.headers.get('Referer') || '';
  const ok =
    origin.startsWith(env.FRONTEND_ORIGIN) ||
    referer.startsWith(env.FRONTEND_ORIGIN);
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
