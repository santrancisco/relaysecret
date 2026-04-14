// /clipboard/:id — KV-backed ciphertext clipboard. Ported from the old
// clipboard worker but with two cleanups:
//   * the "<hex>-<timestamp>" hack is removed. KV has native TTLs now.
//   * CORS is pinned to env.FRONTEND_ORIGIN via the shared helper.

import { jsonResponse, errorResponse } from '../util/json.js';

const ID_REGEX = /^[a-f0-9]{8,64}$/;

export async function clipboardGet(id, request, env) {
  if (!ID_REGEX.test(id)) {
    return errorResponse('bad id', 'BAD_INPUT', 400, env, request);
  }
  if (!env.CLIPBOARD_KV) {
    return errorResponse('kv unavailable', 'NO_KV', 500, env, request);
  }
  const data = await env.CLIPBOARD_KV.get(id);
  if (!data) return errorResponse('not found', 'NOT_FOUND', 404, env, request);
  return jsonResponse({ data }, 200, env, request);
}

export async function clipboardPost(id, request, env) {
  if (!ID_REGEX.test(id)) {
    return errorResponse('bad id', 'BAD_INPUT', 400, env, request);
  }
  if (!env.CLIPBOARD_KV) {
    return errorResponse('kv unavailable', 'NO_KV', 500, env, request);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('invalid json', 'BAD_INPUT', 400, env, request);
  }

  const data = body && body.data;
  if (typeof data !== 'string' || !/^[a-fA-F0-9]+$/.test(data)) {
    return errorResponse('data must be hex', 'BAD_INPUT', 400, env, request);
  }
  // 1 MB soft cap — KV can handle more but there's no reason to.
  if (data.length > 2 * 1024 * 1024) {
    return errorResponse('data too large', 'BAD_INPUT', 400, env, request);
  }

  await env.CLIPBOARD_KV.put(id, data, { expirationTtl: 86400 });
  return jsonResponse({ ok: true }, 200, env, request);
}
