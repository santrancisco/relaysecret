// GET /sha1/:hash — VirusTotal file/report proxy (v3 API).
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

  const vtUrl = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}`;

  try {
    const resp = await fetch(vtUrl, {
      headers: {
        'x-apikey': env.VT_API_KEY,
        'Accept': 'application/json',
      },
    });
    if (resp.status === 404) {
      // File not known to VirusTotal
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
    if (!resp.ok) {
      return errorResponse('vt upstream error', 'VT_UPSTREAM', 502, env, request);
    }
    const data = await resp.json();
    const stats = data.data.attributes.last_analysis_stats;
    const positives = stats.malicious + (stats.suspicious ?? 0);
    const total = Object.values(stats).reduce((sum, n) => sum + n, 0);
    // v3 file objects are keyed by SHA-256; use it for the GUI link if available
    const sha256 = data.data.id ?? hash;
    return jsonResponse(
      {
        sha1: hash,
        positives,
        total,
        vtlink: `https://www.virustotal.com/gui/file/${sha256}`,
        detect: positives > 0,
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
