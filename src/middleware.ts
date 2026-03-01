// src/middleware.ts
import { defineMiddleware } from "astro:middleware";
import type { AstroCookies } from "astro";

// ══════════════════════════════════════════════════════════════════
// KONSTANTA & ENV
// ══════════════════════════════════════════════════════════════════

const ADMIN_EMAIL       = import.meta.env.ADMIN_EMAIL               as string;
const SUPABASE_URL      = import.meta.env.PUBLIC_SUPABASE_URL       as string;
const SUPABASE_ANON_KEY = import.meta.env.PUBLIC_SUPABASE_ANON_KEY  as string;
const IS_PROD           = import.meta.env.PROD                      as boolean;

const ALLOWED_DOMAINS  = new Set(["karsip.my.id", "www.karsip.my.id"]);
const CANONICAL_DOMAIN = "www.karsip.my.id";

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

const ADMIN_EMAIL_NORMALIZED = ADMIN_EMAIL.toLowerCase().trim();

const COOKIE_OPTIONS = {
    path:     "/",
    httpOnly: true,
    sameSite: "lax" as const,
    secure:   IS_PROD,
} as const;

// ══════════════════════════════════════════════════════════════════
// ROUTE CLASSIFICATION
// ══════════════════════════════════════════════════════════════════

const ROUTE_CONFIG = {
    public:    ["/", "/api/auth/login", "/api/auth/logout"] as const,
        authForms: ["/api/auth/login"] as const,
} as const;

const PUBLIC_ROUTES    = new Set<string>(ROUTE_CONFIG.public);
const AUTH_FORM_ROUTES = new Set<string>(ROUTE_CONFIG.authForms);

const PROTECTED_PREFIXES = [
    "/dashboard",
"/kasir",
"/produk",
"/api/kasir",
"/api/admin",
"/api/produk",
];

const STATIC_EXTS        = /\.(ico|png|jpg|jpeg|webp|svg|gif|woff2?|ttf|otf|css|js|map|txt|xml|json)$/i;
const MAX_BODY_BYTES      = 512 * 1024;
const ALLOWED_METHODS     = new Set(["GET", "POST", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const REQUIRED_CT_METHODS = new Set(["POST", "PATCH"]);

// ══════════════════════════════════════════════════════════════════
// ERROR PAGE HELPERS
// ══════════════════════════════════════════════════════════════════

/**
 * Untuk route API  → selalu JSON (tidak ada UI)
 * Untuk route HTML → redirect ke halaman error custom
 *
 * Halaman error tersedia di:
 *   /401  — sesi habis / tidak login
 *   /403  — akses ditolak (bukan admin)
 *   /429  — rate limit
 *   /500  — server error
 *   /404  — tidak ditemukan (ditangani Astro otomatis via src/pages/404.astro)
 */
function errorPageUrl(code: 401 | 403 | 429 | 500, extra?: string): string {
    const base = `https://${CANONICAL_DOMAIN}/${code}`;
    return extra ? `${base}?${extra}` : base;
}

function htmlErrorRedirect(code: 401 | 403 | 429 | 500, extra?: string): Response {
    return new Response(null, {
        status:  302,
        headers: { Location: errorPageUrl(code, extra) },
    });
}

function jsonError(message: string, status: number, retryAfter?: number): Response {
    const headers: Record<string, string> = {
        "Content-Type":  "application/json; charset=utf-8",
        "Cache-Control": "no-store",
    };
    if (retryAfter) headers["Retry-After"] = String(retryAfter);
    return new Response(JSON.stringify({ error: message }), { status, headers });
}

// ══════════════════════════════════════════════════════════════════
// NONCE
// ══════════════════════════════════════════════════════════════════

function generateNonce(): string {
    const arr = new Uint8Array(24);
    crypto.getRandomValues(arr);
    return btoa(String.fromCharCode(...arr))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g,  "");
}

// ══════════════════════════════════════════════════════════════════
// RATE LIMITER (In-Memory)
// ══════════════════════════════════════════════════════════════════

interface RateRecord {
    count:      number;
    resetAt:    number;
    blocked:    boolean;
    blockUntil: number;
    strikes:    number;
}

const rateStore = new Map<string, RateRecord>();

const RATE_CONFIG = {
    login: {
        maxAttempts:      5,
        windowMs:         15 * 60 * 1000,
        blockMs:          30 * 60 * 1000,
        maxStrikes:       3,
        strikeMultiplier: 2,
    },
    api: {
        maxAttempts:      60,
        windowMs:         60 * 1000,
        blockMs:          5 * 60 * 1000,
        maxStrikes:       10,
        strikeMultiplier: 1.5,
    },
} as const;

type RateCategory = keyof typeof RATE_CONFIG;

function checkRateLimit(ip: string, category: RateCategory): { allowed: boolean; retryAfter: number } {
    const cfg = RATE_CONFIG[category];
    const key = `${category}:${ip.replace(/[^a-fA-F0-9.:]/g, "").slice(0, 45)}`;
    const now = Date.now();

    if (rateStore.size > 500) {
        for (const [k, r] of rateStore.entries()) {
            if (now > r.resetAt && (!r.blocked || now > r.blockUntil)) rateStore.delete(k);
        }
    }

    const rec = rateStore.get(key);

    if (!rec || now > rec.resetAt) {
        rateStore.set(key, { count: 1, resetAt: now + cfg.windowMs, blocked: false, blockUntil: 0, strikes: rec?.strikes ?? 0 });
        return { allowed: true, retryAfter: 0 };
    }
    if (rec.strikes >= cfg.maxStrikes) return { allowed: false, retryAfter: 9999 };
    if (rec.blocked && now < rec.blockUntil) {
        return { allowed: false, retryAfter: Math.ceil((rec.blockUntil - now) / 1000) };
    }
    if (rec.blocked && now >= rec.blockUntil) {
        rateStore.set(key, { count: 1, resetAt: now + cfg.windowMs, blocked: false, blockUntil: 0, strikes: rec.strikes });
        return { allowed: true, retryAfter: 0 };
    }
    rec.count++;
    if (rec.count > cfg.maxAttempts) {
        const strikes  = rec.strikes + 1;
        const blockMs  = cfg.blockMs * Math.pow(cfg.strikeMultiplier, strikes - 1);
        rec.blocked    = true;
        rec.blockUntil = now + blockMs;
        rec.strikes    = strikes;
        rateStore.set(key, rec);
        console.warn(`[Middleware] Rate limit (${category}) IP diblokir: ${ip}, strike: ${strikes}, durasi: ${Math.round(blockMs / 60000)}m`);
        return { allowed: false, retryAfter: Math.ceil(blockMs / 1000) };
    }
    return { allowed: true, retryAfter: 0 };
}

function resetLoginRateLimit(ip: string): void {
    rateStore.delete(`login:${ip.replace(/[^a-fA-F0-9.:]/g, "").slice(0, 45)}`);
}

// ══════════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════════

function getClientIp(request: Request): string {
    const cfIp = request.headers.get("cf-connecting-ip");
    if (cfIp) return cfIp.trim().slice(0, 45);
    const forwarded = request.headers.get("x-forwarded-for");
    if (forwarded) return forwarded.split(",")[0].trim().slice(0, 45);
    return request.headers.get("x-real-ip")?.trim().slice(0, 45) ?? "0.0.0.0";
}

function isProtectedRoute(pathname: string): boolean {
    return PROTECTED_PREFIXES.some((p) => pathname === p || pathname.startsWith(p + "/"));
}

function isStaticAsset(pathname: string): boolean {
    return pathname.startsWith("/_astro/") || STATIC_EXTS.test(pathname);
}

function safeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    const enc = new TextEncoder();
    const aB  = enc.encode(a);
    const bB  = enc.encode(b);
    let diff  = 0;
    for (let i = 0; i < aB.length; i++) diff |= aB[i] ^ bB[i];
    return diff === 0;
}

function clearAuthCookies(cookies: AstroCookies): void {
    cookies.delete("sb-access-token",  COOKIE_OPTIONS);
    cookies.delete("sb-refresh-token", COOKIE_OPTIONS);
}

// ══════════════════════════════════════════════════════════════════
// CSRF PROTECTION
// ══════════════════════════════════════════════════════════════════

function getAllowedOrigins(request: Request): Set<string> {
    const origins = new Set<string>(
        [...ALLOWED_DOMAINS].map(d => `https://${d}`)
    );
    const host = request.headers.get("host");
    if (host) {
        const hostname = host.split(":")[0].toLowerCase();
        if ([...ALLOWED_DOMAINS].some(d => hostname === d || hostname.endsWith(`.${d}`))) {
            origins.add(`https://${host}`);
            origins.add(`https://${hostname}`);
        }
    }
    if (!IS_PROD) {
        origins.add("http://localhost:4321");
        origins.add("http://localhost:3000");
        origins.add("http://127.0.0.1:4321");
    }
    return origins;
}

function checkOrigin(request: Request, url: URL): boolean {
    if (!REQUIRED_CT_METHODS.has(request.method)) return true;

    const origin  = request.headers.get("origin");
    const referer = request.headers.get("referer");
    const isApi   = url.pathname.startsWith("/api/");
    const isFormRoute = AUTH_FORM_ROUTES.has(url.pathname);
    const allowedOrigins = getAllowedOrigins(request);

    if (isApi) {
        if (!origin || origin === "null") {
            if (isFormRoute) {
                const host = (request.headers.get("host") ?? "").split(":")[0].toLowerCase();
                const isAllowedHost = [...ALLOWED_DOMAINS].some(d => host === d);
                if (isAllowedHost) return true;
                if (!IS_PROD && (host === "localhost" || host === "127.0.0.1")) return true;
                console.warn(`[Middleware] CSRF: host tidak dikenali untuk ${url.pathname}: ${host}`);
                return false;
            }
            console.warn(`[Middleware] CSRF: origin tidak ada untuk ${url.pathname}`);
            return false;
        }
        try {
            const originUrl = new URL(origin);
            const allowed   = allowedOrigins.has(originUrl.origin);
            if (!allowed) console.warn(`[Middleware] CSRF ditolak — origin: ${originUrl.origin}`);
            return allowed;
        } catch { return false; }
    }

    if (!origin || origin === "null") {
        if (request.method === "GET") return true;
        if (referer) {
            try { return allowedOrigins.has(new URL(referer).origin); }
            catch { return false; }
        }
        return false;
    }
    try { return allowedOrigins.has(new URL(origin).origin); }
    catch { return false; }
}

// ══════════════════════════════════════════════════════════════════
// JWT STRUCTURE VALIDATOR
// ══════════════════════════════════════════════════════════════════

function isValidJwtStructure(token: string): boolean {
    if (!token || typeof token !== "string") return false;
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const b64url = /^[A-Za-z0-9_-]+$/;
    if (!parts.every((p) => p.length > 0 && b64url.test(p))) return false;
    try {
        const padded  = parts[1].replace(/-/g, "+").replace(/_/g, "/");
        const decoded = atob(padded);
        const payload = JSON.parse(decoded) as Record<string, unknown>;
        if (typeof payload.exp !== "number")                         return false;
        if (payload.exp * 1000 < Date.now())                        return false;
        if (typeof payload.sub !== "string" || !payload.sub.trim()) return false;
        return true;
    } catch { return false; }
}

// ══════════════════════════════════════════════════════════════════
// SUPABASE REST API
// ══════════════════════════════════════════════════════════════════

interface SupabaseUser {
    id:                  string;
    email?:              string;
    email_confirmed_at?: string;
    [key: string]:       unknown;
}

async function getUserFromToken(accessToken: string): Promise<{ user: SupabaseUser | null; error: string | null }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
        const res = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
            method:  "GET",
            headers: {
                "Authorization": `Bearer ${accessToken}`,
                "apikey":        SUPABASE_ANON_KEY,
                "Content-Type":  "application/json",
            },
            signal: controller.signal,
        });
        if (!res.ok) {
            const body = await res.json().catch(() => ({})) as { message?: string };
            return { user: null, error: body.message ?? `HTTP ${res.status}` };
        }
        return { user: await res.json() as SupabaseUser, error: null };
    } catch (err) {
        return { user: null, error: err instanceof Error ? err.message : "fetch error" };
    } finally {
        clearTimeout(timer);
    }
}

async function refreshSessionFromToken(refreshToken: string): Promise<{
    data: { accessToken: string; refreshToken: string; expiresIn: number; user: SupabaseUser } | null;
    error: string | null;
}> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
        const res = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`, {
            method:  "POST",
            headers: { "apikey": SUPABASE_ANON_KEY, "Content-Type": "application/json" },
            body:    JSON.stringify({ refresh_token: refreshToken }),
                                signal:  controller.signal,
        });
        if (!res.ok) {
            const body = await res.json().catch(() => ({})) as { message?: string };
            return { data: null, error: body.message ?? `HTTP ${res.status}` };
        }
        const body = await res.json() as {
            access_token: string; refresh_token: string; expires_in: number; user: SupabaseUser;
        };
        return {
            data: {
                accessToken:  body.access_token,
                refreshToken: body.refresh_token,
                expiresIn:    body.expires_in ?? 3600,
                user:         body.user,
            },
            error: null,
        };
    } catch (err) {
        return { data: null, error: err instanceof Error ? err.message : "fetch error" };
    } finally {
        clearTimeout(timer);
    }
}

// ══════════════════════════════════════════════════════════════════
// SESSION CACHE (30 detik)
// ══════════════════════════════════════════════════════════════════

interface SessionResult {
    valid:            boolean;
    isAdmin:          boolean;
    email?:           string;
    newAccessToken?:  string;
    newRefreshToken?: string;
    newExpiresIn?:    number;
}

const sessionCache = new Map<string, { result: SessionResult; expiresAt: number }>();
const SESSION_CACHE_TTL = 30_000;

function getSessionCacheKey(token: string): string {
    return `sc:${token.slice(0, 16)}:${token.slice(-16)}`;
}

export function invalidateSessionCache(accessToken: string): void {
    if (accessToken) sessionCache.delete(getSessionCacheKey(accessToken));
}

async function validateSession(accessToken: string, refreshToken: string): Promise<SessionResult> {
    if (!accessToken || !refreshToken)     return { valid: false, isAdmin: false };
    if (!isValidJwtStructure(accessToken)) return { valid: false, isAdmin: false };

    const cacheKey = getSessionCacheKey(accessToken);

    if (sessionCache.size > 200) {
        const now = Date.now();
        for (const [k, entry] of sessionCache.entries()) {
            if (now > entry.expiresAt) sessionCache.delete(k);
        }
    }

    const cached = sessionCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt && cached.result.valid) return cached.result;
    if (cached) sessionCache.delete(cacheKey);

    try {
        const { user, error } = await getUserFromToken(accessToken);
        if (!error && user) {
            const isAdmin = safeCompare((user.email ?? "").toLowerCase().trim(), ADMIN_EMAIL_NORMALIZED);
            const result: SessionResult = { valid: true, isAdmin, email: user.email };
            sessionCache.set(cacheKey, { result, expiresAt: Date.now() + SESSION_CACHE_TTL });
            return result;
        }
        const { data: rd, error: re } = await refreshSessionFromToken(refreshToken);
        if (re || !rd) return { valid: false, isAdmin: false };
        const isAdmin = safeCompare((rd.user.email ?? "").toLowerCase().trim(), ADMIN_EMAIL_NORMALIZED);
        return {
            valid:           true,
            isAdmin,
            email:           rd.user.email,
            newAccessToken:  rd.accessToken,
            newRefreshToken: rd.refreshToken,
            newExpiresIn:    rd.expiresIn,
        };
    } catch (err) {
        console.error("[Middleware] validateSession error:", err instanceof Error ? err.message : err);
        return { valid: false, isAdmin: false };
    }
}

// ══════════════════════════════════════════════════════════════════
// CSP BUILDER
// ══════════════════════════════════════════════════════════════════

function buildCSP(nonce: string): string {
    const supabaseOrigin = new URL(SUPABASE_URL).origin;
    if (!IS_PROD) {
        return [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com ws://localhost:* http://localhost:*",
            "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'",
            "font-src 'self' https://fonts.gstatic.com",
            "frame-src https://challenges.cloudflare.com",
            `connect-src 'self' ${supabaseOrigin} wss://*.supabase.co https://challenges.cloudflare.com ws://localhost:* http://localhost:*`,
            `img-src 'self' data: blob: ${supabaseOrigin} https://*.supabase.co`,
            "form-action 'self'",
            "frame-ancestors 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "worker-src blob:",
        ].join("; ");
    }
    return [
        "default-src 'none'",
        `script-src 'self' 'nonce-${nonce}' 'wasm-unsafe-eval' https://challenges.cloudflare.com`,
        `style-src 'self' 'nonce-${nonce}' 'unsafe-inline' https://fonts.googleapis.com`,
        "font-src 'self' https://fonts.gstatic.com",
        "frame-src https://challenges.cloudflare.com",
        `connect-src 'self' ${supabaseOrigin} wss://*.supabase.co https://challenges.cloudflare.com`,
        `img-src 'self' data: blob: ${supabaseOrigin} https://*.supabase.co`,
        "form-action 'self'",
        "frame-ancestors 'none'",
        "object-src 'none'",
        "base-uri 'self'",
        "upgrade-insecure-requests",
        "manifest-src 'none'",
        "worker-src blob:",
        "media-src 'none'",
    ].join("; ");
}

// ══════════════════════════════════════════════════════════════════
// SECURITY HEADERS
// ══════════════════════════════════════════════════════════════════

function applySecurityHeaders(response: Response, nonce: string, isApiRoute: boolean): Response {
    const h = response.headers;
    h.set("Content-Security-Policy", buildCSP(nonce));
    h.set("X-Frame-Options",         "DENY");
    h.set("X-Content-Type-Options",  "nosniff");
    h.set("X-XSS-Protection",        "0");
    h.set("X-DNS-Prefetch-Control",  "off");
    h.set("Referrer-Policy",         "strict-origin-when-cross-origin");
    h.set("Permissions-Policy", [
        "camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()",
          "bluetooth=()", "accelerometer=()", "gyroscope=()", "magnetometer=()",
          "interest-cohort=()", "browsing-topics=()",
    ].join(", "));
    if (IS_PROD) h.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
    h.set("Cross-Origin-Opener-Policy",   "same-origin");
    h.set("Cross-Origin-Embedder-Policy", "unsafe-none");
    h.set("Cross-Origin-Resource-Policy", isApiRoute ? "same-site" : "same-origin");
    h.delete("Server");
    h.delete("X-Powered-By");
    h.delete("X-Runtime");
    h.delete("X-AspNet-Version");
    if (isApiRoute) {
        h.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
        h.set("Pragma",        "no-cache");
        h.set("Expires",       "0");
        h.set("Vary",          "Cookie");
    }
    return response;
}

// ══════════════════════════════════════════════════════════════════
// SUSPICIOUS REQUEST DETECTION
// ══════════════════════════════════════════════════════════════════

function isSuspiciousRequest(request: Request, pathname: string): boolean {
    const ua = request.headers.get("user-agent") ?? "";
    if (pathname.includes("../") || pathname.includes("..\\")) return true;
    if (pathname.includes("\0"))                               return true;
    if (/%[0-9a-f]{2}/i.test(pathname)) {
        const decoded = decodeURIComponent(pathname);
        if (decoded.includes("../") || decoded.includes("<script") || decoded.includes("javascript:")) return true;
    }
    if (!ua && pathname.startsWith("/api/"))                   return true;
    const badUa = ["sqlmap", "nikto", "masscan", "zgrab", "nuclei"];
    if (badUa.some((b) => ua.toLowerCase().includes(b)))      return true;
    return false;
}

// ══════════════════════════════════════════════════════════════════
// MIDDLEWARE UTAMA
// ══════════════════════════════════════════════════════════════════

export const onRequest = defineMiddleware(async (context, next) => {
    const { request, cookies, url, locals } = context;
    const pathname   = url.pathname;
    const method     = request.method;
    const ip         = getClientIp(request);
    const isApiRoute = pathname.startsWith("/api/");

    const nonce = generateNonce();
    (locals as App.Locals).nonce = nonce;

    // ── 1. Aset statis ────────────────────────────────────────────
    if (isStaticAsset(pathname)) return next();

    // ── 2. Izinkan halaman error custom diakses bebas ─────────────
    // Tanpa ini, /401 /403 /429 /500 bisa kena loop redirect
    const ERROR_PAGES = new Set(["/401", "/403", "/404", "/429", "/500"]);
    if (ERROR_PAGES.has(pathname)) {
        const response = await next();
        return applySecurityHeaders(response, nonce, false);
    }

    // ── 3. Canonical domain redirect ─────────────────────────────
    if (IS_PROD) {
        const host = (request.headers.get("host") ?? url.hostname).split(":")[0].toLowerCase();
        if (host !== CANONICAL_DOMAIN) {
            const canonical = new URL(url.pathname + url.search, `https://${CANONICAL_DOMAIN}`);
            return new Response(null, {
                status:  method === "GET" ? 301 : 308,
                headers: { "Location": canonical.toString(), "Cache-Control": "public, max-age=31536000, immutable" },
            });
        }
    }

    // ── 4. Deteksi request mencurigakan ───────────────────────────
    if (isSuspiciousRequest(request, pathname)) {
        console.warn(`[Middleware] Request mencurigakan — IP: ${ip}, path: ${pathname}`);
        return new Response("Bad Request", { status: 400 });
    }

    // ── 5. Blokir HTTP method tidak diizinkan ─────────────────────
    if (!ALLOWED_METHODS.has(method)) {
        return new Response("Method Not Allowed", {
            status:  405,
            headers: { Allow: [...ALLOWED_METHODS].join(", ") },
        });
    }

    // ── 6. Cegah body terlalu besar ───────────────────────────────
    const contentLength = parseInt(request.headers.get("content-length") ?? "0", 10);
    if (Number.isNaN(contentLength) || contentLength > MAX_BODY_BYTES) {
        return isApiRoute
        ? jsonError("Payload terlalu besar", 413)
        : htmlErrorRedirect(500);
    }

    // ── 7. CSRF check ─────────────────────────────────────────────
    if (!checkOrigin(request, url)) {
        console.warn(`[Middleware] CSRF gagal — IP: ${ip}, path: ${pathname}, method: ${method}, origin: ${request.headers.get("origin")}`);
        return isApiRoute
        ? jsonError("Forbidden: origin tidak valid", 403)
        : htmlErrorRedirect(403);
    }

    // ── 8. Content-Type validation ────────────────────────────────
    if (REQUIRED_CT_METHODS.has(method) && isApiRoute) {
        const ct      = request.headers.get("content-type") ?? "";
        const validCT = ct.includes("application/json") ||
        ct.includes("application/x-www-form-urlencoded") ||
        ct.includes("multipart/form-data");
        if (!validCT) return jsonError("Content-Type tidak valid", 415);
    }

    // ── 9. Rate limit login ───────────────────────────────────────
    if (pathname === "/api/auth/login" && method === "POST") {
        const { allowed, retryAfter } = checkRateLimit(ip, "login");
        if (!allowed) {
            const mnt = retryAfter === 9999 ? "sementara" : `${Math.ceil(retryAfter / 60)} menit`;
            console.warn(`[Middleware] Login rate limit — IP: ${ip}`);
            return isApiRoute
            ? jsonError(`Terlalu banyak percobaan. Coba lagi dalam ${mnt}.`, 429, retryAfter)
            : htmlErrorRedirect(429, `retry=${retryAfter}`);
        }
    }

    // ── 10. Rate limit API umum ───────────────────────────────────
    if (isApiRoute && method !== "GET") {
        const { allowed, retryAfter } = checkRateLimit(ip, "api");
        if (!allowed) {
            return isApiRoute
            ? jsonError("Terlalu banyak request. Coba lagi sebentar.", 429, retryAfter)
            : htmlErrorRedirect(429, `retry=${retryAfter}`);
        }
    }

    // ── 11. Route publik ──────────────────────────────────────────
    if (PUBLIC_ROUTES.has(pathname)) {
        const response = await next();
        return applySecurityHeaders(response, nonce, isApiRoute);
    }

    // ── 12. Route terproteksi — validasi session ──────────────────
    if (isProtectedRoute(pathname)) {
        const accessToken  = cookies.get("sb-access-token")?.value  ?? "";
        const refreshToken = cookies.get("sb-refresh-token")?.value ?? "";

        if (!accessToken || !refreshToken) {
            clearAuthCookies(cookies);
            return isApiRoute
            ? jsonError("Autentikasi diperlukan.", 401)
            : htmlErrorRedirect(401);
        }

        const session = await validateSession(accessToken, refreshToken);

        if (!session.valid) {
            console.warn(`[Middleware] Sesi tidak valid — IP: ${ip}, path: ${pathname}`);
            clearAuthCookies(cookies);
            return isApiRoute
            ? jsonError("Sesi tidak valid.", 401)
            : htmlErrorRedirect(401);
        }

        if (!session.isAdmin) {
            console.warn(`[Middleware] Non-admin ditolak: ${session.email} — IP: ${ip}`);
            clearAuthCookies(cookies);
            return isApiRoute
            ? jsonError("Akses ditolak.", 403)
            : htmlErrorRedirect(403);
        }

        (locals as App.Locals).user = { email: session.email ?? "", isAdmin: true };
        resetLoginRateLimit(ip);

        const response = await next();

        if (session.newAccessToken && session.newRefreshToken) {
            const expiresIn = session.newExpiresIn ?? 3600;
            cookies.set("sb-access-token",  session.newAccessToken,  { ...COOKIE_OPTIONS, maxAge: expiresIn });
            cookies.set("sb-refresh-token", session.newRefreshToken, { ...COOKIE_OPTIONS, maxAge: 60 * 60 * 24 * 7 });
        }

        return applySecurityHeaders(response, nonce, isApiRoute);
    }

    // ── 13. Fallback ──────────────────────────────────────────────
    const response = await next();
    return applySecurityHeaders(response, nonce, isApiRoute);
});
