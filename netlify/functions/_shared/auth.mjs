import crypto from "node:crypto";

const SESSION_COOKIE = "ds_mod_session";
const CSRF_COOKIE = "ds_mod_csrf";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 h
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 8;

/** @type {Map<string, { count: number, resetAt: number }>} */
const loginAttempts = new Map();

export function json(status, body, extraHeaders = {}) {
  return {
    statusCode: status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  };
}

export function requireEnv() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const adminPassword = process.env.ADMIN_PASSWORD;
  const sessionSecret = process.env.ADMIN_SESSION_SECRET;
  if (!supabaseUrl || !serviceKey || !adminPassword || !sessionSecret) {
    const missing = [
      !supabaseUrl && "SUPABASE_URL",
      !serviceKey && "SUPABASE_SERVICE_ROLE_KEY",
      !adminPassword && "ADMIN_PASSWORD",
      !sessionSecret && "ADMIN_SESSION_SECRET",
    ].filter(Boolean);
    const err = new Error(`Config manquante : ${missing.join(", ")}`);
    err.code = "CONFIG";
    throw err;
  }
  return { supabaseUrl, serviceKey, adminPassword, sessionSecret };
}

function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromB64url(str) {
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  return Buffer.from(str.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}

function sign(payloadB64, secret) {
  return b64url(crypto.createHmac("sha256", secret).update(payloadB64).digest());
}

export function createSessionToken(secret) {
  const payload = {
    v: 1,
    exp: Date.now() + SESSION_TTL_MS,
    nonce: crypto.randomBytes(16).toString("hex"),
  };
  const payloadB64 = b64url(JSON.stringify(payload));
  return `${payloadB64}.${sign(payloadB64, secret)}`;
}

export function verifySessionToken(token, secret) {
  if (!token || typeof token !== "string" || !token.includes(".")) return false;
  const [payloadB64, sig] = token.split(".");
  if (!payloadB64 || !sig) return false;
  const expected = sign(payloadB64, secret);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try {
    const payload = JSON.parse(fromB64url(payloadB64).toString("utf8"));
    return payload?.v === 1 && typeof payload.exp === "number" && payload.exp > Date.now();
  } catch {
    return false;
  }
}

export function createCsrfToken() {
  return crypto.randomBytes(24).toString("hex");
}

export function parseCookies(header = "") {
  /** @type {Record<string, string>} */
  const out = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

export function cookie(name, value, { maxAgeSec, httpOnly = true } = {}) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "Secure",
    "SameSite=Strict",
  ];
  if (httpOnly) parts.push("HttpOnly");
  if (typeof maxAgeSec === "number") parts.push(`Max-Age=${maxAgeSec}`);
  return parts.join("; ");
}

export function clearCookie(name, { httpOnly = true } = {}) {
  return cookie(name, "", { maxAgeSec: 0, httpOnly });
}

export function clientKey(event) {
  return (
    event.headers["x-nf-client-connection-ip"] ||
    event.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    event.headers["client-ip"] ||
    "unknown"
  );
}

export function assertLoginAllowed(ip) {
  const now = Date.now();
  const row = loginAttempts.get(ip);
  if (!row || row.resetAt < now) {
    loginAttempts.set(ip, { count: 0, resetAt: now + LOGIN_WINDOW_MS });
    return;
  }
  if (row.count >= LOGIN_MAX_ATTEMPTS) {
    const err = new Error("Trop de tentatives. Réessaie dans quelques minutes.");
    err.code = "RATE";
    throw err;
  }
}

export function recordLoginFailure(ip) {
  const now = Date.now();
  const row = loginAttempts.get(ip) || { count: 0, resetAt: now + LOGIN_WINDOW_MS };
  if (row.resetAt < now) {
    loginAttempts.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
    return;
  }
  row.count += 1;
  loginAttempts.set(ip, row);
}

export function clearLoginFailures(ip) {
  loginAttempts.delete(ip);
}

export function timingSafeEqualString(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (aa.length !== bb.length) {
    crypto.timingSafeEqual(aa, aa);
    return false;
  }
  return crypto.timingSafeEqual(aa, bb);
}

export function readJsonBody(event) {
  if (!event.body) return {};
  const raw = event.isBase64Encoded
    ? Buffer.from(event.body, "base64").toString("utf8")
    : event.body;
  try {
    return JSON.parse(raw);
  } catch {
    const err = new Error("JSON invalide");
    err.code = "BAD_JSON";
    throw err;
  }
}

export function requireSession(event, sessionSecret) {
  const cookies = parseCookies(event.headers.cookie || event.headers.Cookie || "");
  const token = cookies[SESSION_COOKIE];
  if (!verifySessionToken(token, sessionSecret)) {
    const err = new Error("Connexion requise");
    err.code = "AUTH";
    throw err;
  }
  return cookies;
}

export function requireCsrf(event, cookies) {
  const header = event.headers["x-csrf-token"] || event.headers["X-CSRF-Token"];
  const expected = cookies[CSRF_COOKIE];
  if (!expected || !header || !timingSafeEqualString(header, expected)) {
    const err = new Error("Jeton CSRF invalide");
    err.code = "CSRF";
    throw err;
  }
}

export { SESSION_COOKIE, CSRF_COOKIE, SESSION_TTL_MS };
