import {
  json,
  readJsonBody,
  requireCsrf,
  requireEnv,
  requireSession,
} from "./_shared/auth.mjs";
import { supabaseAdmin } from "./_shared/supabase.mjs";

const ALLOWED = new Set(["ok", "ban_10m", "ban_forever"]);
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export async function handler(event) {
  if (event.httpMethod !== "POST") {
    return json(405, { error: "Méthode non autorisée" });
  }

  try {
    const { supabaseUrl, serviceKey, sessionSecret } = requireEnv();
    const cookies = requireSession(event, sessionSecret);
    requireCsrf(event, cookies);

    const body = readJsonBody(event);
    const reportId = String(body.reportId ?? "").trim();
    const action = String(body.action ?? "").trim();
    const note = body.note != null ? String(body.note).slice(0, 500) : null;

    if (!UUID_RE.test(reportId)) {
      return json(400, { error: "Identifiant de signalement invalide" });
    }
    if (!ALLOWED.has(action)) {
      return json(400, { error: "Action invalide" });
    }

    const supabase = supabaseAdmin(supabaseUrl, serviceKey);
    const { data, error } = await supabase.rpc("moderate_drawing_report", {
      p_report_id: reportId,
      p_action: action,
      p_note: note,
    });

    if (error) {
      const msg = error.message || "Erreur Supabase";
      if (msg.includes("report_not_found")) {
        return json(404, { error: "Signalement introuvable" });
      }
      if (msg.includes("report_already_reviewed")) {
        return json(409, { error: "Ce signalement a déjà été traité" });
      }
      return json(500, { error: msg });
    }

    return json(200, { ok: true, report: data });
  } catch (err) {
    if (err.code === "AUTH") return json(401, { error: err.message });
    if (err.code === "CSRF") return json(403, { error: err.message });
    if (err.code === "CONFIG") return json(500, { error: err.message });
    if (err.code === "BAD_JSON") return json(400, { error: err.message });
    return json(500, { error: "Erreur serveur" });
  }
}
