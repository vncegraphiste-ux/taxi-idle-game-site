import {
  clearCookie,
  CSRF_COOKIE,
  json,
  SESSION_COOKIE,
} from "./_shared/auth.mjs";

export async function handler(event) {
  if (event.httpMethod !== "POST") {
    return json(405, { error: "Méthode non autorisée" });
  }

  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
    multiValueHeaders: {
      "Set-Cookie": [
        clearCookie(SESSION_COOKIE, { httpOnly: true }),
        clearCookie(CSRF_COOKIE, { httpOnly: false }),
      ],
    },
    body: JSON.stringify({ ok: true }),
  };
}
