
// netlify/functions/tuya-proxy.js

import crypto from "crypto";

// Simple in-memory token cache
const tokenCache = {
  token: null,
  expires: 0,
};

console.log("🔑 Funkcja Tuya Proxy zainicjalizowana");

// Pobieranie tokena wg aktualnej specyfikacji Tuya Cloud:
// GET /v1.0/token?grant_type=1 z podpisem HMAC(clientId + t)
async function getAccessToken() {
  const now = Date.now();
  if (tokenCache.token && now < tokenCache.expires) {
    console.log("✔️ Używam zcache'owanego tokena Tuya");
    return tokenCache.token;
  }

  const { TUYA_API_HOST, TUYA_CLIENT_ID, TUYA_SECRET } = process.env;
  if (!TUYA_API_HOST || !TUYA_CLIENT_ID || !TUYA_SECRET) {
    throw new Error("Brak wymaganych zmiennych: TUYA_API_HOST, TUYA_CLIENT_ID, TUYA_SECRET");
  }

  const t = Date.now().toString();
  // Algorytm kanoniczny (Tuya OpenAPI):
  // 1. contentSha256 = SHA256(body) (pusty string dla GET bez body)
  // 2. canonicalHeaders (tu brak dodatkowych) => pusty wiersz
  // 3. canonicalPath z zapytaniem
  // 4. stringToSign = METHOD + "\n" + contentSha256 + "\n" + canonicalHeaders + "\n" + pathWithQuery
  // 5. signStr = clientId + t + stringToSign (bez access_token przy token endpoint)
  // 6. HMAC-SHA256(signStr, secret)
  const method = 'GET';
  const bodyStr = '';
  const contentSha256 = crypto.createHash('sha256').update(bodyStr).digest('hex');
  const pathWithQuery = '/v1.0/token?grant_type=1';
  const canonicalHeadersSection = '';
  const stringToSignSection = [method, contentSha256, canonicalHeadersSection, pathWithQuery].join('\n');
  const signStr = TUYA_CLIENT_ID + t + stringToSignSection;
  const sign = crypto.createHmac('sha256', TUYA_SECRET).update(signStr).digest('hex').toUpperCase();

  const url = `https://${TUYA_API_HOST}${pathWithQuery}`;
  console.log("→ Pobieram nowy token Tuya:", url);
  console.log("→ contentSha256:", contentSha256);
  console.log("→ stringToSignSection:\n" + stringToSignSection);
  console.log("→ signStr:", signStr);
  console.log("→ sign:", sign);

  const res = await fetch(url, {
    method: method,
    headers: {
      client_id: TUYA_CLIENT_ID,
      sign,
      t,
      sign_method: "HMAC-SHA256",
    },
  });

  console.log(`← Odpowiedź token endpoint: ${res.status}`);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch {
    console.error("❌ Token response nie jest JSON:", text);
    throw new Error("Token endpoint zwrócił nie-JSON");
  }

  if (!res.ok || data.success === false) {
    console.error("❌ Błąd pobierania tokena payload:", data);
    throw new Error(`Błąd tokena: ${res.status} ${data.msg || data.message || ''}`.trim());
  }
  if (!data.result || !data.result.access_token) {
    console.error("❌ Brak access_token w odpowiedzi:", data);
    throw new Error("Brak access_token w odpowiedzi token endpointu");
  }

  tokenCache.token = data.result.access_token;
  const ttl = (data.result.expire_time || 3600) * 1000;
  tokenCache.expires = now + ttl - 60 * 1000; // bufor 60s
  console.log("✔️ Nowy token Tuya uzyskany; ważny (ms):", ttl);
  return tokenCache.token;
}

// Kanoniczny podpis (Tuya OpenAPI normal request):
// stringToSignSection = METHOD\n + SHA256(body)\n + (canonical headers puste) + \n + pathWithQuery
// signStr = clientId + accessToken + t + stringToSignSection
function generateSign(method, path, body, t, accessToken) {
  const clientId = process.env.TUYA_CLIENT_ID;
  const bodyStr = body ? JSON.stringify(body) : "";
  const contentSha256 = crypto.createHash('sha256').update(bodyStr).digest('hex');
  const methodUpper = method.toUpperCase();
  const canonicalHeadersSection = ""; // brak dodatkowych nagłówków kanonicznych w tej prostej wersji
  const stringToSignSection = [methodUpper, contentSha256, canonicalHeadersSection, path].join('\n');
  const signStr = clientId + accessToken + t + stringToSignSection;
  const sign = crypto.createHmac('sha256', process.env.TUYA_SECRET).update(signStr).digest('hex').toUpperCase();
  console.log("→ contentSha256:", contentSha256);
  console.log("→ stringToSignSection:\n" + stringToSignSection);
  console.log("→ signStr:", signStr);
  console.log("✔️ Wygenerowano podpis HMAC-SHA256:", sign);
  return { sign };
}

export async function handler(event) {
  console.log(">>> Incoming event:", event);

  // Health check GET /tuya bez body
  if (event.httpMethod === 'GET' && !event.body) {
    return { statusCode: 200, body: JSON.stringify({ ok: true, message: 'Tuya proxy działa' }) };
  }

  let payload = {};
  if (event.body) {
    try {
      payload = JSON.parse(event.body);
    } catch (err) {
      console.error("❌ Błędny JSON:", err.message);
      return { statusCode: 400, body: JSON.stringify({ error: "Błędny JSON w body" }) };
    }
  } else {
    return { statusCode: 400, body: JSON.stringify({ error: "Brak body JSON" }) };
  }

  const { path, method = "GET", body } = payload;
  if (!path) {
    console.error("❌ Brak 'path' w body");
    return { statusCode: 400, body: JSON.stringify({ error: "Brak parametru 'path'" }) };
  }

  console.log(`→ Wywołanie Tuya API: [${method}] ${path}`);

  try {
    const t = Date.now().toString();
    const accessToken = await getAccessToken();
    const { sign } = generateSign(method, path, body, t, accessToken);

    const url = `https://${process.env.TUYA_API_HOST}${path}`;
    const headers = {
      client_id: process.env.TUYA_CLIENT_ID,
      sign,
      t,
      sign_method: "HMAC-SHA256",
      sign_version: "1.0",
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
