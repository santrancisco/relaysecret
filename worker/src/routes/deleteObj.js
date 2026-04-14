// DELETE /obj?region=&key= — delete an object via the R2 binding.
// Binding-based delete is simpler and cheaper than presigning a DELETE.

import { jsonResponse, errorResponse } from '../util/json.js';
import { resolveRegion } from '../util/regions.js';
import { KEY_REGEX } from '../util/keys.js';

export async function deleteObj(url, request, env) {
  const q = url.searchParams;
  const region = resolveRegion(q.get('region'), env);

  const key = q.get('key') || '';
  if (!KEY_REGEX.test(key)) {
    return errorResponse('invalid key', 'BAD_INPUT', 400, env, request);
  }
  if (!region.binding) {
    return errorResponse('region unavailable', 'NO_BINDING', 500, env, request);
  }

  await region.binding.delete(key);
  return jsonResponse({ ok: true, key }, 200, env, request);
}
