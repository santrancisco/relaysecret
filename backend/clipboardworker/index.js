addEventListener('fetch', event => {
  console.log(`Received new request: ${event.request.url}`)
  event.respondWith(handleRequest(event.request))
})


const setCache = (key, data) => TUNNELKV.put(key, data)
const getCache = (key) => TUNNELKV.get(key)

/**
 * Respond to the request
 * @param {Request} request
 */

async function handleRequest(request) {
  fullurl = new URL(request.url);
  console.log("keyis:" + fullurl.pathname)
  try {
    if (request.method === 'POST' && fullurl.pathname.startsWith("/update")) {
      //Update clipboard
      console.log("POST request");
      clipboardid = fullurl.pathname.split("/").pop()
      return updateClipboard(clipboardid, request)
    } else if (request.method === 'GET' && fullurl.pathname.startsWith("/get")) {
      // handling GET clipboard data request
      console.log("GET request");
      clipboardid = fullurl.pathname.split("/").pop();
      return getClipboard(clipboardid, request);
    }
    else if (request.method === 'OPTIONS') {
      // handling preflight request
      return handleOptions(request)
    }
    else {
      return await buildResponse("404 - These aren't not the droid you're looking for.", 404);
    }
  }
  catch (e) {
    await console.log(e.toString())
    return await buildResponse("500 - Something is broken", 500);
  }
}


function handleOptions(request) {
  const corsHeaders = {
    "Access-Control-Allow-Origin": "https://www.relaysecret.com",
    "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  }
  return new Response(null, {
    headers: corsHeaders
  })
}

async function buildResponse(data, status) {
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "https://www.relaysecret.com"
  }
  return new Response(
    data, {
    status: status,
    headers: headers
  }
  )
}

// update clipboard data in KV - we store a timestamp here so we can clean up in the future.
async function updateClipboard(key, request) {
  try {
    data = await request.json()
    data = data["data"] + "-" + (Math.floor(new Date() / 1000)).toString()
    await setCache(key, data)
    return await buildResponse("done", 200)
  } catch (err) {
    console.log(err.toString());
    return await buildResponse("500 - Something is broken", 500);
  }
}

// get clipboard data from KV
async function getClipboard(key) {
  try {
    data = await getCache(key)
    body = { "data": data.split("-")[0] }
    return await buildResponse(JSON.stringify(body), 200)
  } catch (err) {
    console.log(err.toString());
    return await buildResponse("500 - Something is broken", 500);
  }
}
