import {
  json,
  requireCsrf,
  requireEnv,
  requireSession,
} from "./_shared/auth.mjs";
import { supabaseAdmin } from "./_shared/supabase.mjs";

export async function handler(event) {
  if (event.httpMethod !== "GET") {
    return json(405, { error: "Méthode non autorisée" });
  }

  try {
    const { supabaseUrl, serviceKey, sessionSecret } = requireEnv();
    const cookies = requireSession(event, sessionSecret);
    // GET : CSRF optionnel si cookie session SameSite=Strict ; on le vérifie si présent.
    const csrfHeader = event.headers["x-csrf-token"] || event.headers["X-CSRF-Token"];
    if (csrfHeader) requireCsrf(event, cookies);

    const supabase = supabaseAdmin(supabaseUrl, serviceKey);
    const { data, error } = await supabase
      .from("moderation_pending_reports")
      .select("*")
      .order("created_at", { ascending: true })
      .limit(200);

    if (error) {
      return json(500, { error: error.message || "Erreur Supabase" });
    }

    return json(200, { reports: data ?? [] });
  } catch (err) {
    if (err.code === "AUTH") return json(401, { error: err.message });
    if (err.code === "CSRF") return json(403, { error: err.message });
    if (err.code === "CONFIG") return json(500, { error: err.message });
    return json(500, { error: "Erreur serveur" });
  }
}
