import {
  assertLoginAllowed,
  clearLoginFailures,
  clientKey,
  cookie,
  createCsrfToken,
  createSessionToken,
  CSRF_COOKIE,
  json,
  readJsonBody,
  recordLoginFailure,
  requireEnv,
  SESSION_COOKIE,
  SESSION_TTL_MS,
  timingSafeEqualString,
} from "./_shared/auth.mjs";

export async function handler(event) {
  if (event.httpMethod === "OPTIONS") {
    return json(204, {});
  }
  if (event.httpMethod !== "POST") {
    return json(405, { error: "Méthode non autorisée" });
  }

  try {
    const { adminPassword, sessionSecret } = requireEnv();
    const ip = clientKey(event);
    assertLoginAllowed(ip);

    const body = readJsonBody(event);
    const password = String(body.password ?? "");
    if (!timingSafeEqualString(password, adminPassword)) {
      recordLoginFailure(ip);
      return json(401, { error: "Mot de passe incorrect" });
    }

    clearLoginFailures(ip);
    const session = createSessionToken(sessionSecret);
    const csrf = createCsrfToken();
    const maxAge = Math.floor(SESSION_TTL_MS / 1000);

    return {
      statusCode: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
      },
      multiValueHeaders: {
        "Set-Cookie": [
          cookie(SESSION_COOKIE, session, { maxAgeSec: maxAge, httpOnly: true }),
          cookie(CSRF_COOKIE, csrf, { maxAgeSec: maxAge, httpOnly: false }),
        ],
      },
      body: JSON.stringify({ ok: true, csrfToken: csrf }),
    };
  } catch (err) {
    if (err.code === "RATE") return json(429, { error: err.message });
    if (err.code === "CONFIG") return json(500, { error: err.message });
    if (err.code === "BAD_JSON") return json(400, { error: err.message });
    return json(500, { error: "Erreur serveur" });
  }
}
