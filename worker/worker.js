/* Aura — Worker Cloudflare per invio OTP via email (Resend)
 *
 * Endpoints:
 *   POST /request-otp  { email }        → invia OTP a 6 cifre via email
 *   POST /verify-otp   { email, code }  → verifica OTP, ritorna { ok: true } o errore
 *
 * Sicurezza:
 *   - Chiave Resend è un SECRET del Worker (mai nel codice HTML)
 *   - OTP memorizzato in Cloudflare KV (scadenza 10 min)
 *   - Rate-limit: max 5 richieste / IP / 10 min (anti-abuso)
 *   - CORS: solo per il dominio Aura (GitHub Pages + localhost per dev)
 *   - Email validata server-side
 *   - OTP generato con crypto.getRandomValues (crittograficamente sicuro)
 */

// ⚠️ QUESTI DOMINI sono gli unici che possono chiamare il Worker.
// Cambiali se deployi l'HTML su un altro dominio.
const ALLOWED_ORIGINS = [
  "https://sasaonir.github.io",          // GitHub Pages produzione
  "http://localhost:8765",                // dev locale
  "http://127.0.0.1:8765",                // dev locale
];

// Mittente email. In trial Resend permette solo onboarding@resend.dev.
// Quando verifichi un dominio tuo su Resend, cambialo qui (es. "Aura <noreply@tuodominio.it>").
const EMAIL_FROM = "Aura <onboarding@resend.dev>";

// Indirizzi "to" permessi in modalità trial Resend.
// In trial, Resend invia SOLO a delivered@resend.dev (per testing).
// Quando verifichi un dominio tuo, RIMUOVI questo controllo (vedi sotto).
const TRIAL_ALLOWED_TO = "delivered@resend.dev";

const OTP_TTL_SECONDS = 600; // 10 minuti
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_SECONDS = 600;

// ─────────── Helpers ───────────

function jsonResp(status, body, origin) {
  const headers = { "Content-Type": "application/json" };
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }
  return new Response(JSON.stringify(body), { status, headers });
}

function corsPreflight(origin) {
  const headers = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }
  return new Response(null, { status: 204, headers });
}

function isValidEmail(e) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e || "").toLowerCase());
}

function genOTP() {
  // 6 cifre dal CSPRNG, con rejection sampling: "b % 10" su un byte (0-255) darebbe
  // più probabilità alle cifre 0-5. Si scartano i byte >= 250.
  const out = [];
  while (out.length < 6) {
    const buf = new Uint8Array(12);
    crypto.getRandomValues(buf);
    for (const b of buf) { if (b < 250 && out.length < 6) out.push(b % 10); }
  }
  return out.join("");
}

// Nel KV non si salva mai il codice in chiaro: solo SHA-256(email:codice).
async function otpDigest(email, code) {
  const data = new TextEncoder().encode(email + ":" + code);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// Confronto a tempo costante (niente early-exit sul primo carattere diverso).
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function isRateLimited(ip) {
  const key = `rl:${ip}`;
  const now = Math.floor(Date.now() / 1000);
  const raw = await AURA_KV.get(key);
  let count = 0;
  if (raw) {
    try { const d = JSON.parse(raw); if (d.expiresAt > now) count = d.count; } catch {}
  }
  if (count >= RATE_LIMIT_MAX) return true;
  await AURA_KV.put(key, JSON.stringify({ count: count + 1, expiresAt: now + RATE_LIMIT_WINDOW_SECONDS }), { expirationTtl: RATE_LIMIT_WINDOW_SECONDS });
  return false;
}

// ─────────── Invio email via Resend ───────────

async function sendOTPEmail(email, code) {
  const html = `<!doctype html><html lang="it"><body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f0a2e;color:#e8e6f5;margin:0;padding:0">
  <div style="max-width:520px;margin:0 auto;padding:32px 24px">
    <div style="text-align:center;margin-bottom:24px"><div style="display:inline-block;width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#ff7eb6,#a26bff,#5ef0e8);margin-bottom:14px"></div>
    <h1 style="margin:0 0 8px;font-size:22px;letter-spacing:-.3px">✨ Aura — Codice di ripristino</h1>
    <p style="color:#a3a0c0;font-size:14px;margin:0">Usa questo codice per reimpostare la tua password.</p></div>
    <div style="background:linear-gradient(135deg,#1a0b3d,#241559);border:1px solid #2d2059;border-radius:16px;padding:28px;text-align:center;margin:24px 0">
      <div style="font-size:38px;font-weight:800;letter-spacing:8px;color:#ffd166;font-family:'Courier New',monospace">${code}</div>
      <div style="color:#a3a0c0;font-size:12.5px;margin-top:10px">Scade tra 10 minuti</div>
    </div>
    <p style="color:#a3a0c0;font-size:13px;line-height:1.6">Se non hai richiesto tu questo codice, ignora questa email. La tua password resta invariata.</p>
    <hr style="border:0;border-top:1px solid #2d2059;margin:24px 0">
    <p style="color:#6a678a;font-size:11.5px;margin:0">Aura — piattaforma per artisti di musica AI. Email automatica, non rispondere.</p>
  </div></body></html>`;
  const text = `Aura — Codice di ripristino password\n\nIl tuo codice è: ${code}\n\nScade tra 10 minuti. Se non hai richiesto tu questo codice, ignora questa email.\n\nAura`;
  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ from: EMAIL_FROM, to: email, subject: `Aura — Codice: ${code}`, html, text }),
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Resend ${resp.status}: ${err}`);
  }
  return await resp.json();
}

// ─────────── Endpoint ───────────

async function handleRequestOTP(body, ip, origin) {
  const email = String(body.email || "").toLowerCase().trim();
  if (!isValidEmail(email)) return jsonResp(400, { ok: false, error: "Email non valida." }, origin);
  // ⚠️ In trial Resend invia SOLO a delivered@resend.dev.
  // Quando avrai verificato un dominio tuo, CANCELLA queste 2 righe.
  if (email !== TRIAL_ALLOWED_TO) {
    return jsonResp(403, { ok: false, error: "Modalità trial: in produzione le email arriveranno a tutti gli utenti. Per ora, per test, usa l'indirizzo delivered@resend.dev (visibile nel dashboard Resend → Logs).", trial: true }, origin);
  }
  if (await isRateLimited(ip)) return jsonResp(429, { ok: false, error: "Troppe richieste. Riprova tra 10 minuti." }, origin);

  const code = genOTP();
  // Salva OTP in KV: chiave = otp:<email>, valore = { code, expiresAt, attempts }
  const now = Math.floor(Date.now() / 1000);
  await AURA_KV.put(`otp:${email}`, JSON.stringify({ h: await otpDigest(email, code), expiresAt: now + OTP_TTL_SECONDS, attempts: 0 }), { expirationTtl: OTP_TTL_SECONDS });

  try {
    await sendOTPEmail(email, code);
    return jsonResp(200, { ok: true, message: "Codice inviato via email. Controlla la tua casella." }, origin);
  } catch (e) {
    console.error("OTP email failed:", e.message); // il dettaglio resta nei log del Worker, non va al client
    return jsonResp(502, { ok: false, error: "Invio email non riuscito. Riprova tra poco." }, origin);
  }
}

async function handleVerifyOTP(body, ip, origin) {
  const email = String(body.email || "").toLowerCase().trim();
  const code = String(body.code || "").trim();
  if (!isValidEmail(email)) return jsonResp(400, { ok: false, error: "Email non valida." }, origin);
  if (!/^\d{6}$/.test(code)) return jsonResp(400, { ok: false, error: "Codice non valido (6 cifre)." }, origin);
  if (await isRateLimited(ip)) return jsonResp(429, { ok: false, error: "Troppe richieste. Riprova tra 10 minuti." }, origin);

  const raw = await AURA_KV.get(`otp:${email}`);
  if (!raw) return jsonResp(400, { ok: false, error: "Codice scaduto o non richiesto. Richiedi un nuovo codice." }, origin);

  let d;
  try { d = JSON.parse(raw); } catch { return jsonResp(500, { ok: false, error: "Errore interno." }, origin); }

  const now = Math.floor(Date.now() / 1000);
  if (d.expiresAt < now) {
    await AURA_KV.delete(`otp:${email}`);
    return jsonResp(400, { ok: false, error: "Codice scaduto. Richiedi un nuovo codice." }, origin);
  }
  if (d.attempts >= 5) {
    await AURA_KV.delete(`otp:${email}`);
    return jsonResp(400, { ok: false, error: "Troppi tentativi. Richiedi un nuovo codice." }, origin);
  }
  if (!safeEqual(d.h || "", await otpDigest(email, code))) {
    d.attempts++;
    await AURA_KV.put(`otp:${email}`, JSON.stringify(d), { expirationTtl: OTP_TTL_SECONDS });
    return jsonResp(400, { ok: false, error: `Codice errato. Tentativi rimasti: ${5 - d.attempts}` }, origin);
  }
  // OK: cancella OTP (uso singolo)
  await AURA_KV.delete(`otp:${email}`);
  return jsonResp(200, { ok: true, message: "Codice verificato. Ora puoi reimpostare la password." }, origin);
}

// ─────────── Main ───────────

export default {
  async fetch(request, env) {
    // Bind KV e secret dall'env
    globalThis.AURA_KV = env.AURA_KV;
    globalThis.RESEND_API_KEY = env.RESEND_API_KEY;

    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    // CORS preflight
    if (request.method === "OPTIONS") return corsPreflight(origin);
    if (request.method !== "POST") {
      return new Response("Aura Mail Worker. POST /request-otp o /verify-otp.", { status: 200 });
    }

    // Parse body
    let body;
    try { body = await request.json(); }
    catch { return jsonResp(400, { ok: false, error: "Body JSON non valido." }, origin); }

    // IP (per rate-limit). Cloudflare mette il vero IP in CF-Connecting-IP.
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    try {
      if (url.pathname === "/request-otp") return await handleRequestOTP(body, ip, origin);
      if (url.pathname === "/verify-otp")  return await handleVerifyOTP(body, ip, origin);
      return jsonResp(404, { ok: false, error: "Endpoint non trovato. Usa /request-otp o /verify-otp." }, origin);
    } catch (e) {
      console.error("Worker error:", e.message);
      return jsonResp(500, { ok: false, error: "Errore interno." }, origin);
    }
  },
};
