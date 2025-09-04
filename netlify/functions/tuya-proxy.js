
// netlify/functions/tuya-proxy.js

import crypto from "crypto";

// Simple in-memory token cache
const tokenCache = {
  token: null,
  expires: 0,
};

async function getAccessToken() {
  const now = Date.now();

  if (tokenCache.token && now < tokenCache.expires) {
    console.log("✔️ Using cached Tuya token");
    return tokenCache.token;
  }

  const url = `https://${process.env.TUYA_API_HOST}/v1.0/token?grant_type=1`;
  console.log("→ Fetching new Tuya access token:", url);

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      username: process.env.TUYA_USERNAME,
      password: process.env.TUYA_PASSWORD,
    }),
  });

  console.log(`← Token endpoint responded with status ${res.status}`);

  if (!res.ok) {
    const errText = await res.text();
    console.error("❌ Tuya token fetch error:", errText);
    throw new Error(`Unable to fetch Tuya token: ${res.status}`);
  }

  const data = await res.json();
  tokenCache.token = data.result.access_token;
  // expire_time is seconds until expiry
  tokenCache.expires = now + data.result.expire_time * 1000 - 60 * 1000;
  console.log("✔️ New Tuya token acquired; expires in (ms):", data.result.expire_time * 1000);

  return tokenCache.token;
}

function generateSign(method, path, body, t, accessToken) {
  const clientId = process.env.TUYA_CLIENT_ID;
  const nonce = Date.now().toString();
  const payload = body ? JSON.stringify(body) : "";
  const stringToSign = [clientId, accessToken, nonce, t, method, path, payload].join("");

  console.log("→ StringToSign:", stringToSign);

  const hmac = crypto
    .createHmac("sha256", process.env.TUYA_SECRET)
    .update(stringToSign)
    .digest("hex")
    .toUpperCase();

  console.log("✔️ Generated HMAC-SHA256 sign:", hmac);
  return { sign: hmac, nonce };
}

export async function handler(event) {
  console.log(">>> Incoming event:", event);

  let payload;
  try {
    payload = JSON.parse(event.body);
  } catch (err) {
    console.error("❌ Invalid JSON payload:", err.message);
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Invalid JSON body" }),
    };
  }

  const { path, method = "GET", body } = payload;
  if (!path) {
    console.error("❌ Missing 'path' in request body");
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Missing 'path' parameter" }),
    };
  }

  console.log(`→ Calling Tuya API: [${method}] ${path}`);

  try {
    const t = Date.now().toString();
    const accessToken = await getAccessToken();
    const { sign, nonce } = generateSign(method, path, body, t, accessToken);

    const url = `https://${process.env.TUYA_API_HOST}${path}`;
    const headers = {
      client_id: process.env.TUYA_CLIENT_ID,
      sign,
      t,
      nonce,
      sign_method: "HMAC-SHA256",
      access_token: accessToken,
      "Content-Type": "application/json",
    };

    console.log("→ Dispatching request to Tuya:", url);
    console.log("→ Request headers:", headers);
    if (body) console.log("→ Request body:", body);

    const res = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    console.log(`← Tuya response status: ${res.status}`);
    const text = await res.text();
    console.log("← Tuya raw response body:", text);

    let json;
    try {
      json = JSON.parse(text);
    } catch {
      console.warn("⚠️ Response is not valid JSON, returning raw text");
      return {
        statusCode: res.status,
        body: text,
      };
    }

    return {
      statusCode: res.status,
      body: JSON.stringify(json),
    };
  } catch (err) {
    console.error("❌ Error in Tuya proxy handler:", err.stack);
    return {
      statusCode: 502,
      body: JSON.stringify({ error: err.message }),
    };
  }
}
