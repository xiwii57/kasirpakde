// src/middleware/constants.ts
// ══════════════════════════════════════════════════════════════════
// ENV & KONSTANTA GLOBAL
// Semua nilai yang dipakai lintas modul dikumpulkan di sini.
// ══════════════════════════════════════════════════════════════════

export const ADMIN_EMAIL       = import.meta.env.ADMIN_EMAIL               as string;
export const SUPABASE_URL      = import.meta.env.PUBLIC_SUPABASE_URL       as string;
export const SUPABASE_ANON_KEY = import.meta.env.PUBLIC_SUPABASE_ANON_KEY  as string;
export const IS_PROD           = import.meta.env.PROD                      as boolean;

export const CANONICAL_HOST  = "www.karsip.my.id";
export const VERCEL_HOST_RE  = /(?:\.vercel\.app)$/i;

// Validasi wajib saat startup
for (const [key, val] of Object.entries({
    ADMIN_EMAIL,
    PUBLIC_SUPABASE_URL:      SUPABASE_URL,
    PUBLIC_SUPABASE_ANON_KEY: SUPABASE_ANON_KEY,
})) {
    if (!val || typeof val !== "string" || val.trim() === "") {
        throw new Error(`[Middleware] Env var wajib tidak ditemukan atau kosong: ${key}`);
    }
}

if (!SUPABASE_URL.startsWith("https://")) {
    throw new Error("[Middleware] PUBLIC_SUPABASE_URL harus menggunakan HTTPS.");
}

export const ADMIN_EMAIL_NORMALIZED = ADMIN_EMAIL.toLowerCase().trim();

// ── Durasi sesi ────────────────────────────────────────────────────
export const ACCESS_TOKEN_MAX_AGE  = 60 * 60;             // 1 jam (detik)
export const REFRESH_TOKEN_MAX_AGE = 60 * 60 * 24;        // 1 hari (detik)
export const MAX_SESSION_AGE_MS    = 24 * 60 * 60 * 1000; // 1 hari (ms) — batas absolut sesi

// ── Cookie options ─────────────────────────────────────────────────
export const COOKIE_OPTIONS = {
    path:     "/",
    httpOnly: true,
    sameSite: "strict" as const,
    secure:   IS_PROD,
} as const;

// ── Route config ───────────────────────────────────────────────────
export const PUBLIC_ROUTES    = new Set<string>(["/", "/dashboard/api/auth/login", "/dashboard/api/auth/logout"]);
export const AUTH_FORM_ROUTES = new Set<string>(["/dashboard/api/auth/login"]);
export const PROTECTED_PREFIXES = ["/dashboard"];
export const ERROR_PAGES        = new Set(["/401", "/403", "/404", "/429", "/500"]);

// ── Request config ─────────────────────────────────────────────────
export const STATIC_EXTS        = /\.(ico|png|jpg|jpeg|webp|svg|gif|woff2?|ttf|otf|css|js|map|txt|xml|json)$/i;
export const MAX_BODY_BYTES      = 512 * 1024;
export const ALLOWED_METHODS     = new Set(["GET", "POST", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
export const REQUIRED_CT_METHODS = new Set(["POST", "PATCH"]);
export const MAX_TOKEN_LENGTH    = 4096;
