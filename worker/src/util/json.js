// json.js — tiny response helpers. Every route returns JSON; keeping these
// centralised means CORS headers and error shape stay consistent.

import { corsHeaders } from './cors.js';

export function jsonResponse(body, status, env, request) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(env, request),
    },
  });
}

// errorResponse matches the contract in docs/API.md: { error, code } + status.
export function errorResponse(message, code, status, env, request) {
  return jsonResponse({ error: message, code }, status, env, request);
}
