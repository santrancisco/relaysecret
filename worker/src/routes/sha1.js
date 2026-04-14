// GET /sha1/:hash — VirusTotal file/report proxy.
// The API key lives in env.VT_API_KEY. If it's "none" we pretend the endpoint
// does not exist (matches lambda.py's checkvirus()).

import { jsonResponse, errorResponse } from '../util/json.js';

export async function sha1Route(hash, request, env) {
  if (!/^[a-fA-F0-9]{40}$/.test(hash)) {
    return errorResponse('invalid sha1', 'BAD_INPUT', 400, env, request);
  }
  if (!env.VT_API_KEY || env.VT_API_KEY === 'none') {
    return errorResponse('virustotal disabled', 'NOT_FOUND', 404, env, request);
  }

  const vtUrl =
    `https://www.virustotal.com/vtapi/v2/file/report?apikey=${encodeURIComponent(env.VT_API_KEY)}` +
    `&resource=${encodeURIComponent(hash)}`;

  try {
    const resp = await fetch(vtUrl, {
      headers: {
        'Accept-Encoding': 'identity',
        'User-Agent': 'gzip, virustotal-relaysecret 0.0.9',
      },
    });
    if (!resp.ok) {
      return errorResponse('vt upstream error', 'VT_UPSTREAM', 502, env, request);
    }
    const data = await resp.json();
    if (data.response_code !== 1) {
      return jsonResponse(
        {
          sha1: hash,
          positives: 0,
          total: 0,
          vtlink: `https://www.virustotal.com/gui/file/${hash}`,
          detect: false,
          error: false,
        },
        200,
        env,
        request
      );
    }
    return jsonResponse(
      {
        sha1: hash,
        positives: data.positives,
        total: data.total,
        vtlink: data.permalink,
        detect: data.positives > 0,
        error: false,
      },
      200,
      env,
      request
    );
  } catch (_e) {
    return errorResponse('vt fetch failed', 'VT_FETCH', 502, env, request);
  }
}
