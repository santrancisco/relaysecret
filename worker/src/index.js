// index.js — RelaySecret Worker entry point.
//
// The whole Worker is a plain ES module. No router dependency, no bundler —
// just a small switch on method + pathname so a human reviewer can follow
// every request end-to-end in one sitting.

import { handlePreflight, refererGate } from './util/cors.js';
import { errorResponse } from './util/json.js';

import { presignPut } from './routes/presignPut.js';
import { presignTunnelPut } from './routes/presignTunnelPut.js';
import { presignGet } from './routes/presignGet.js';
import { presignMultipartInit } from './routes/presignMultipart.js';
import { tunnelList } from './routes/tunnelList.js';
import { deleteObj } from './routes/deleteObj.js';
import { sha1Route } from './routes/sha1.js';
import { clipboardGet, clipboardPost } from './routes/clipboard.js';

export default {
  async fetch(request, env /*, ctx */) {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method.toUpperCase();

    // Preflight always short-circuits and carries CORS headers.
    if (method === 'OPTIONS') return handlePreflight(request, env);

    // Origin / Referer gate — mirrors lambda.py. Disabled in devmode.
    const blocked = refererGate(request, env);
    if (blocked) return blocked;

    try {
      // --- presign routes ------------------------------------------------
      if (method === 'GET' && pathname === '/presign/put') {
        return await presignPut(url, request, env);
      }
      if (method === 'GET' && pathname === '/presign/tunnel-put') {
        return await presignTunnelPut(url, request, env);
      }
      if (method === 'GET' && pathname === '/presign/get') {
        return await presignGet(url, request, env);
      }
      if (method === 'POST' && pathname === '/presign/multipart-init') {
        return await presignMultipartInit(url, request, env);
      }

      // --- tunnel + obj management --------------------------------------
      if (method === 'GET' && pathname === '/tunnel/list') {
        return await tunnelList(url, request, env);
      }
      if (method === 'DELETE' && pathname === '/obj') {
        return await deleteObj(url, request, env);
      }

      // --- sha1 / virustotal --------------------------------------------
      if (method === 'GET' && pathname.startsWith('/sha1/')) {
        const hash = pathname.slice('/sha1/'.length);
        return await sha1Route(hash, request, env);
      }

      // --- clipboard -----------------------------------------------------
      if (pathname.startsWith('/clipboard/')) {
        const id = pathname.slice('/clipboard/'.length);
        if (method === 'GET') return await clipboardGet(id, request, env);
        if (method === 'POST') return await clipboardPost(id, request, env);
      }

      return errorResponse('not found', 'NOT_FOUND', 404, env, request);
    } catch (err) {
      // Surface internal errors with a short code; never leak stack traces.
      console.log('worker error:', err && err.stack ? err.stack : err);
      return errorResponse('internal error', 'INTERNAL', 500, env, request);
    }
  },
};
