// main.ts - Deno Deploy backend (NO API KEY AUTH)
// ESP32 Smart House (Option A)
//
// Endpoints:
//   GET  /api/commands/doorTarget?deviceId=house01   -> "true" / "false"
//   POST /api/telemetry?deviceId=house01            -> writes telemetry/state/meta
//   POST /api/state/door?deviceId=house01           -> ack door state + log
//   POST /api/commands/doorTarget?deviceId=house01  -> set doorTarget (optional)
//
// Env vars required:
//   FIREBASE_DATABASE_URL
//   FIREBASE_CLIENT_EMAIL
//   FIREBASE_PRIVATE_KEY
// Optional:
//   DEFAULT_DEVICE_ID
//   CORS_ORIGIN

type Json = Record<string, unknown>;

const DB_URL = (Deno.env.get("FIREBASE_DATABASE_URL") ?? "").replace(/\/+$/, "");
const CLIENT_EMAIL = Deno.env.get("FIREBASE_CLIENT_EMAIL") ?? "";
const PRIVATE_KEY_RAW = Deno.env.get("FIREBASE_PRIVATE_KEY") ?? "";
const DEFAULT_DEVICE_ID = Deno.env.get("DEFAULT_DEVICE_ID") ?? "house01";
const CORS_ORIGIN = Deno.env.get("CORS_ORIGIN") ?? "*";

if (!DB_URL || !CLIENT_EMAIL || !PRIVATE_KEY_RAW) {
  console.log(
    "Missing env vars. Required: FIREBASE_DATABASE_URL, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY",
  );
}

function corsHeaders(): HeadersInit {
  return {
    "access-control-allow-origin": CORS_ORIGIN,
    "access-control-allow-headers": "content-type, x-api-key",
    "access-control-allow-methods": "GET,POST,PUT,PATCH,OPTIONS",
  };
}

function jsonResponse(body: unknown, status = 200, extraHeaders: HeadersInit = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...corsHeaders(),
      ...extraHeaders,
    },
  });
}

function textResponse(body: string, status = 200, extraHeaders: HeadersInit = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      ...corsHeaders(),
      ...extraHeaders,
    },
  });
}

function badRequest(msg: string) {
  return jsonResponse({ error: msg }, 400);
}

function getDeviceId(req: Request): string {
  const u = new URL(req.url);
  return u.searchParams.get("deviceId") || DEFAULT_DEVICE_ID;
}

function nowMs() {
  return Date.now();
}

// ---- Base64URL + JWT helpers ----
function base64UrlEncode(bytes: Uint8Array): string {
  const b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function pemToPkcs8Der(pem: string): Uint8Array {
  const normalized = pem.replace(/\\n/g, "\n").trim();
  const lines = normalized.split("\n").filter((l) => !l.includes("BEGIN") && !l.includes("END"));
  const b64 = lines.join("");
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
  const der = pemToPkcs8Der(pem);
  return await crypto.subtle.importKey(
    "pkcs8",
    der.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

// ---- OAuth token cache ----
let cachedToken: { accessToken: string; expMs: number } | null = null;

async function getAccessToken(): Promise<string> {
  if (cachedToken && nowMs() < cachedToken.expMs - 5 * 60 * 1000) {
    return cachedToken.accessToken;
  }

  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 3600;

  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: CLIENT_EMAIL,
    scope:
      "https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email",
    aud: "https://oauth2.googleapis.com/token",
    iat,
    exp,
  };

  const encHeader = base64UrlEncode(utf8(JSON.stringify(header)));
  const encPayload = base64UrlEncode(utf8(JSON.stringify(payload)));
  const signingInput = `${encHeader}.${encPayload}`;

  const key = await importPrivateKey(PRIVATE_KEY_RAW);
  const sigBuf = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, utf8(signingInput));
  const sig = base64UrlEncode(new Uint8Array(sigBuf));
  const jwt = `${signingInput}.${sig}`;

  const body = new URLSearchParams();
  body.set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
  body.set("assertion", jwt);

  const resp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!resp.ok) {
    const t = await resp.text();
    throw new Error(`OAuth token error: ${resp.status} ${t}`);
  }

  const data = await resp.json() as { access_token: string; expires_in: number };
  cachedToken = {
    accessToken: data.access_token,
    expMs: Date.now() + data.expires_in * 1000,
  };
  return data.access_token;
}

// ---- RTDB REST helpers ----
async function rtdbFetch(path: string, init?: RequestInit): Promise<Response> {
  const token = await getAccessToken();
  const url = `${DB_URL}/${path.replace(/^\/+/, "")}.json?access_token=${encodeURIComponent(token)}`;
  return await fetch(url, init);
}

async function rtdbGet(path: string): Promise<unknown> {
  const resp = await rtdbFetch(path, { method: "GET" });
  if (!resp.ok) throw new Error(`RTDB GET ${path} failed: ${resp.status} ${await resp.text()}`);
  return await resp.json();
}

async function rtdbPatch(path: string, value: Json): Promise<void> {
  const resp = await rtdbFetch(path, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(value),
  });
  if (!resp.ok) throw new Error(`RTDB PATCH ${path} failed: ${resp.status} ${await resp.text()}`);
}

async function rtdbPost(path: string, value: unknown): Promise<{ name: string }> {
  const resp = await rtdbFetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(value),
  });
  if (!resp.ok) throw new Error(`RTDB POST ${path} failed: ${resp.status} ${await resp.text()}`);
  return await resp.json() as { name: string };
}

// ---- Router ----
async function handle(req: Request): Promise<Response> {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  const url = new URL(req.url);
  const path = url.pathname;

  if (req.method === "GET" && path === "/") {
    return textResponse("ok");
  }

  const deviceId = getDeviceId(req);
  const base = `devices/${deviceId}`;

  try {
    // GET: doorTarget
    if (req.method === "GET" && path === "/api/commands/doorTarget") {
      const v = await rtdbGet(`${base}/commands/doorTarget`);
      return textResponse(!!v ? "true" : "false");
    }

    // POST: telemetry
    if (req.method === "POST" && path === "/api/telemetry") {
      const body = await req.json().catch(() => null) as (Json | null);
      if (!body) return badRequest("Invalid JSON");

      const telemetry = (body.telemetry && typeof body.telemetry === "object")
        ? body.telemetry as Json
        : {};
      const state = (body.state && typeof body.state === "object") ? body.state as Json : {};
      const deviceMs = typeof body.ms === "number" ? body.ms : null;
      const wifiRssi = typeof body.wifiRssi === "number" ? body.wifiRssi : null;

      await rtdbPatch(`${base}`, {
        telemetry,
        state,
        meta: {
          lastSeenServerMs: nowMs(),
          lastSeenDeviceMs: deviceMs,
          wifiRssi,
        },
      });

      return jsonResponse({ ok: true });
    }

    // POST: door ack + log
    if (req.method === "POST" && path === "/api/state/door") {
      const body = await req.json().catch(() => null) as (Json | null);
      if (!body) return badRequest("Invalid JSON");

      const doorOpen = !!body.doorOpen;
      const source = typeof body.source === "string" ? body.source : "unknown";
      const deviceMs = typeof body.ms === "number" ? body.ms : null;

      await rtdbPatch(`${base}/state`, {
        doorOpen,
        lastDoorSource: source,
        lastDoorDeviceMs: deviceMs,
        lastDoorServerMs: nowMs(),
      });

      await rtdbPost(`${base}/logs/door`, {
        doorOpen,
        source,
        deviceMs,
        serverMs: nowMs(),
      });

      return jsonResponse({ ok: true });
    }

    // OPTIONAL: set doorTarget (for web app)
    if (req.method === "POST" && path === "/api/commands/doorTarget") {
      const body = await req.json().catch(() => null) as (Json | null);
      if (!body) return badRequest("Invalid JSON");
      if (typeof body.doorTarget !== "boolean") return badRequest("doorTarget must be boolean");

      await rtdbPatch(`${base}/commands`, {
        doorTarget: body.doorTarget,
        lastSetServerMs: nowMs(),
      });

      return jsonResponse({ ok: true });
    }

    // OPTIONAL: read entire device tree (useful for debugging UI)
    if (req.method === "GET" && path === "/api/state") {
      const v = await rtdbGet(`${base}`);
      return jsonResponse(v);
    }

    return jsonResponse({ error: "Not found" }, 404);
  } catch (e) {
    console.log("Error:", e);
    return jsonResponse({ error: String(e) }, 500);
  }
}

export default { fetch: handle };
