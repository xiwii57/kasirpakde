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
const CANONICAL_HOST    = "www.karsip.my.id";
const VERCEL_HOST_RE    = /(?:\.vercel\.app)$/i;

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
    sameSite: "strict" as const,
    secure:   IS_PROD,
} as const;

// ══════════════════════════════════════════════════════════════════
// ROUTE CLASSIFICATION
// ══════════════════════════════════════════════════════════════════

const ROUTE_CONFIG = {
    public:    ["/", "/dashboard/api/auth/login", "/dashboard/api/auth/logout"] as const,
        authForms: ["/dashboard/api/auth/login"] as const,
} as const;

const PUBLIC_ROUTES    = new Set<string>(ROUTE_CONFIG.public);
const AUTH_FORM_ROUTES = new Set<string>(ROUTE_CONFIG.authForms);

const PROTECTED_PREFIXES = [
    "/dashboard",
"/kasir",
"/produk",
"/dashboard/api/kasir",
"/dashboard/api/admin",
"/dashboard/api/produk",
];

const STATIC_EXTS        = /\.(ico|png|jpg|jpeg|webp|svg|gif|woff2?|ttf|otf|css|js|map|txt|xml|json)$/i;
const MAX_BODY_BYTES      = 512 * 1024;
const ALLOWED_METHODS     = new Set(["GET", "POST", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const REQUIRED_CT_METHODS = new Set(["POST", "PATCH"]);
const MAX_TOKEN_LENGTH    = 4096;

// ══════════════════════════════════════════════════════════════════
// ERROR PAGE HELPERS
// ══════════════════════════════════════════════════════════════════

function htmlErrorRedirect(code: 401 | 403 | 429 | 500, extra?: string): Response {
    const base = `/${code}`;
    const loc  = extra ? `${base}?${extra}` : base;
    return new Response(null, {
        status:  302,
        headers: { Location: loc },
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

function isVercelHost(host: string): boolean {
    const hostname = host.split(":")[0]!.toLowerCase();
    return VERCEL_HOST_RE.test(hostname);
}

// FIX: kode lama — new URL(url.pathname + url.search + url.hash)
// crash karena pathname saja bukan URL absolut yang valid.
// Solusi: clone url object lengkap lalu ganti protocol & host.
function redirectToCanonical(url: URL): Response {
    const canonical    = new URL(url.toString());
    canonical.protocol = "https:";
    canonical.host     = CANONICAL_HOST;
    return new Response(null, {
        status:  301,
        headers: {
            "Location":      canonical.toString(),
                        "Cache-Control": "max-age=31536000",
        },
    });
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
// RATE LIMITER (In-Memory — Single Instance)
// ══════════════════════════════════════════════════════════════════

interface RateRecord {
    count:      number;
    resetAt:    number;
    blocked:    boolean;
    blockUntil: number;
    strikes:    number;
}

const rateStore = new Map<string, RateRecord>();

const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [k, r] of rateStore.entries()) {
        if (now > r.resetAt && (!r.blocked || now > r.blockUntil)) {
            rateStore.delete(k);
            cleaned++;
        }
    }
    if (cleaned > 0) console.info(`[Middleware] RateStore cleanup: ${cleaned} entry dihapus.`);
}, CLEANUP_INTERVAL_MS);

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

    if (rateStore.size > 2000) {
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
        console.warn(`[Middleware] Rate limit (${category}) IP diblokir: ${ip.slice(0, 8)}***, strike: ${strikes}, durasi: ${Math.round(blockMs / 60000)}m`);
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
    if (forwarded) return forwarded.split(",")[0]!.trim().slice(0, 45);
    return request.headers.get("x-real-ip")?.trim().slice(0, 45) ?? "0.0.0.0";
}

// FIX: tambah guard — PUBLIC_ROUTES tidak boleh dianggap protected
// meski path-nya diawali "/dashboard" (contoh: logout).
function isProtectedRoute(pathname: string): boolean {
    if (PUBLIC_ROUTES.has(pathname)) return false;
    return PROTECTED_PREFIXES.some((p) => pathname === p || pathname.startsWith(p + "/"));
}

function isStaticAsset(pathname: string): boolean {
    return pathname.startsWith("/_astro/") || STATIC_EXTS.test(pathname);
}

function safeCompare(a: string, b: string): boolean {
    const enc    = new TextEncoder();
    const maxLen = Math.max(a.length, b.length, 1);
    const aPad   = a.padEnd(maxLen, "\0");
    const bPad   = b.padEnd(maxLen, "\0");
    const aB     = enc.encode(aPad);
    const bB     = enc.encode(bPad);
    let diff     = a.length === b.length ? 0 : 1;
    for (let i = 0; i < aB.length; i++) diff |= aB[i]! ^ bB[i]!;
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
    const origins = new Set<string>();
    const host    = request.headers.get("host");
    if (host) {
        const hostname = host.split(":")[0]!.toLowerCase();
        origins.add(`https://${hostname}`);
        if (host.includes(":")) origins.add(`https://${host}`);
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

    const origin         = request.headers.get("origin");
    const referer        = request.headers.get("referer");
    const isApi          = url.pathname.startsWith("/dashboard/api/");
    const isFormRoute    = AUTH_FORM_ROUTES.has(url.pathname);
    const allowedOrigins = getAllowedOrigins(request);

    if (isApi) {
        if (!origin || origin === "null") {
            if (isFormRoute) {
                const host  = (request.headers.get("host") ?? "").split(":")[0]!.toLowerCase();
                const isDev = !IS_PROD && (host === "localhost" || host === "127.0.0.1");
                if (isDev || IS_PROD) return true;
                console.warn(`[Middleware] CSRF: origin tidak ada untuk login endpoint`);
                return false;
            }
            console.warn(`[Middleware] CSRF: origin tidak ada untuk API endpoint`);
            return false;
        }
        try {
            const originUrl = new URL(origin);
            const allowed   = allowedOrigins.has(originUrl.origin);
            if (!allowed) console.warn(`[Middleware] CSRF ditolak — origin tidak diizinkan`);
            return allowed;
        } catch { return false; }
    }

    if (!origin || origin === "null") {
        if (request.method === "GET") return true;
        if (referer) {
            try { return allowedOrigins.has(new URL(referer).origin); }
            catch { return false; }
        }
        console.warn(`[Middleware] CSRF: tidak ada origin maupun referer untuk ${request.method} request`);
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
    if (token.length > MAX_TOKEN_LENGTH)      return false;
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const b64url = /^[A-Za-z0-9_-]+$/;
    if (!parts.every((p) => p.length > 0 && b64url.test(p))) return false;
    try {
        const padded  = parts[1]!.replace(/-/g, "+").replace(/_/g, "/");
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
    const timer      = setTimeout(() => controller.abort(), 5000);
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
    const timer      = setTimeout(() => controller.abort(), 5000);
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

const sessionCache      = new Map<string, { result: SessionResult; expiresAt: number }>();
const SESSION_CACHE_TTL = 30_000;

setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [k, entry] of sessionCache.entries()) {
        if (now > entry.expiresAt) { sessionCache.delete(k); cleaned++; }
    }
    if (cleaned > 0) console.info(`[Middleware] SessionCache cleanup: ${cleaned} entry dihapus.`);
}, 2 * 60 * 1000);

async function getSessionCacheKey(token: string): Promise<string> {
    const encoded = new TextEncoder().encode(token);
    const hashBuf = await crypto.subtle.digest("SHA-256", encoded);
    const hashArr = Array.from(new Uint8Array(hashBuf));
    return "sc:" + hashArr.map(b => b.toString(16).padStart(2, "0")).join("");
}

async function invalidateSessionCache(accessToken: string): Promise<void> {
    if (accessToken) {
        const key = await getSessionCacheKey(accessToken);
        sessionCache.delete(key);
    }
}

async function validateSession(accessToken: string, refreshToken: string): Promise<SessionResult> {
    if (!accessToken || !refreshToken)     return { valid: false, isAdmin: false };

    if (accessToken.length > MAX_TOKEN_LENGTH || refreshToken.length > MAX_TOKEN_LENGTH) {
        console.warn("[Middleware] Token melebihi batas panjang maksimum.");
        return { valid: false, isAdmin: false };
    }

    if (!isValidJwtStructure(accessToken)) return { valid: false, isAdmin: false };

    const cacheKey = await getSessionCacheKey(accessToken);

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
        console.error("[Middleware] validateSession error:", err instanceof Error ? err.message : "unknown");
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
            `script-src 'self' 'nonce-${nonce}' https://challenges.cloudflare.com ws://localhost:* http://localhost:* https://static.cloudflareinsights.com`,
            "script-src-attr 'unsafe-inline'",
            `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`,
            "style-src-attr 'unsafe-inline'",
            "font-src 'self' https://fonts.gstatic.com data:",
            "frame-src https://challenges.cloudflare.com",
            `connect-src 'self' ${supabaseOrigin} wss://*.supabase.co https://challenges.cloudflare.com ws://localhost:* http://localhost:* https://static.cloudflareinsights.com`,
            `img-src 'self' data: blob: ${supabaseOrigin} https://*.supabase.co`,
            "form-action 'self'",
            "frame-ancestors 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "worker-src blob:",
            "media-src 'none'",
        ].join("; ");
    }

    return [
        "default-src 'self'",
        `script-src 'self' 'nonce-${nonce}' 'wasm-unsafe-eval' https://challenges.cloudflare.com https://static.cloudflareinsights.com`,
        "script-src-attr 'unsafe-inline'",
        `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`,
        "style-src-attr 'unsafe-inline'",
        "font-src 'self' https://fonts.gstatic.com data:",
        "frame-src https://challenges.cloudflare.com",
        `connect-src 'self' ${supabaseOrigin} wss://*.supabase.co https://challenges.cloudflare.com https://static.cloudflareinsights.com`,
        `img-src 'self' data: blob: ${supabaseOrigin} https://*.supabase.co`,
        "form-action 'self'",
        "frame-ancestors 'none'",
        "object-src 'none'",
        "base-uri 'self'",
        "upgrade-insecure-requests",
        "worker-src blob:",
        "media-src 'none'",
    ].join("; ");
}

// ══════════════════════════════════════════════════════════════════
// NONCE HTML INJECTOR
// ══════════════════════════════════════════════════════════════════

function injectNonceIntoHtml(html: string, nonce: string): string {
    return html.replace(
        /<script(?![^>]*\bnonce\b)([^>]*)>/gi,
                        `<script nonce="${nonce}"$1>`,
    );
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

async function applySecurityWithNonce(
    response: Response,
    nonce: string,
    isApiRoute: boolean,
): Promise<Response> {
    const contentType = response.headers.get("content-type") ?? "";

    if (!contentType.includes("text/html")) {
        return applySecurityHeaders(response, nonce, isApiRoute);
    }

    let html = await response.text();
    html = injectNonceIntoHtml(html, nonce);

    const newResponse = new Response(html, {
        status:  response.status,
        headers: response.headers,
    });

    newResponse.headers.set("content-type", "text/html; charset=utf-8");

    return applySecurityHeaders(newResponse, nonce, isApiRoute);
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
    if (!ua && pathname.startsWith("/dashboard/api/"))        return true;
    const badUa = ["sqlmap", "nikto", "masscan", "zgrab", "nuclei"];
    if (badUa.some((b) => ua.toLowerCase().includes(b)))      return true;
    return false;
}

// ══════════════════════════════════════════════════════════════════
// OPTIONS PREFLIGHT HANDLER
// ══════════════════════════════════════════════════════════════════

function handleOptions(request: Request): Response | null {
    if (request.method !== "OPTIONS") return null;

    const origin         = request.headers.get("origin");
    const allowedOrigins = getAllowedOrigins(request);

    if (!origin || !allowedOrigins.has(origin)) {
        return new Response(null, { status: 403 });
    }

    return new Response(null, {
        status: 204,
        headers: {
            "Access-Control-Allow-Origin":  origin,
            "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, HEAD, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age":       "600",
            "Vary":                         "Origin",
        },
    });
}

// ══════════════════════════════════════════════════════════════════
// MIDDLEWARE UTAMA
// ══════════════════════════════════════════════════════════════════

export const onRequest = defineMiddleware(async (context, next) => {
    const { request, cookies, url, locals } = context;
    const pathname   = url.pathname;
    const method     = request.method;
    const ip         = getClientIp(request);
    const isApiRoute = pathname.startsWith("/dashboard/api/");

    const nonce = generateNonce();
    (locals as App.Locals).nonce = nonce;

    // ── 0. Redirect domain Vercel → canonical ────────────────────────
    const requestHost = request.headers.get("host") ?? "";
    if (isVercelHost(requestHost)) {
        return redirectToCanonical(url);
    }

    // ── 1. Aset statis ────────────────────────────────────────────
    if (isStaticAsset(pathname)) return next();

    // ── 2. Halaman error custom diakses bebas ─────────────────────
    const ERROR_PAGES = new Set(["/401", "/403", "/404", "/429", "/500"]);
    if (ERROR_PAGES.has(pathname)) {
        const response = await next();
        return applySecurityWithNonce(response, nonce, false);
    }

    // ── 3. Deteksi request mencurigakan ───────────────────────────
    if (isSuspiciousRequest(request, pathname)) {
        console.warn(`[Middleware] Request mencurigakan — IP: ${ip.slice(0, 8)}***`);
        return new Response("Bad Request", { status: 400 });
    }

    // ── 4. Blokir HTTP method tidak diizinkan ─────────────────────
    if (!ALLOWED_METHODS.has(method)) {
        return new Response("Method Not Allowed", {
            status:  405,
            headers: { Allow: [...ALLOWED_METHODS].join(", ") },
        });
    }

    // ── 5. Tangani OPTIONS preflight ──────────────────────────────
    const optionsResponse = handleOptions(request);
    if (optionsResponse) return optionsResponse;

    // ── 6. Cegah body terlalu besar ───────────────────────────────
    const clHeader = request.headers.get("content-length");
    if (clHeader !== null) {
        const contentLength = parseInt(clHeader, 10);
        if (Number.isNaN(contentLength) || contentLength < 0 || contentLength > MAX_BODY_BYTES) {
            return isApiRoute
            ? jsonError("Payload terlalu besar", 413)
            : htmlErrorRedirect(500);
        }
    }

    // ── 7. CSRF check ─────────────────────────────────────────────
    if (!checkOrigin(request, url)) {
        console.warn(`[Middleware] CSRF gagal — IP: ${ip.slice(0, 8)}***, method: ${method}`);
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
    if (pathname === "/dashboard/api/auth/login" && method === "POST") {
        const { allowed, retryAfter } = checkRateLimit(ip, "login");
        if (!allowed) {
            const mnt = retryAfter === 9999 ? "sementara" : `${Math.ceil(retryAfter / 60)} menit`;
            console.warn(`[Middleware] Login rate limit — IP: ${ip.slice(0, 8)}***`);
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

    // ── 11. Route publik — dicek SEBELUM protected ────────────────
    // Logout (/dashboard/api/auth/logout) harus lolos di sini,
    // tidak boleh tertangkap isProtectedRoute() di step 12.
    if (PUBLIC_ROUTES.has(pathname)) {
        const response = await next();
        return applySecurityWithNonce(response, nonce, isApiRoute);
    }

    // ── 12. Route terproteksi — validasi session ──────────────────
    if (isProtectedRoute(pathname)) {
        const accessToken  = cookies.get("sb-access-token")?.value  ?? "";
        const refreshToken = cookies.get("sb-refresh-token")?.value ?? "";

        if (
            !accessToken || !refreshToken ||
            accessToken.length  > MAX_TOKEN_LENGTH ||
            refreshToken.length > MAX_TOKEN_LENGTH
        ) {
            clearAuthCookies(cookies);
            return isApiRoute
            ? jsonError("Autentikasi diperlukan.", 401)
            : htmlErrorRedirect(401);
        }

        const session = await validateSession(accessToken, refreshToken);

        if (!session.valid) {
            console.warn(`[Middleware] Sesi tidak valid — IP: ${ip.slice(0, 8)}***`);
            clearAuthCookies(cookies);
            return isApiRoute
            ? jsonError("Sesi tidak valid.", 401)
            : htmlErrorRedirect(401);
        }

        if (!session.isAdmin) {
            console.warn(`[Middleware] Non-admin ditolak — IP: ${ip.slice(0, 8)}***`);
            clearAuthCookies(cookies);
            return isApiRoute
            ? jsonError("Akses ditolak.", 403)
            : htmlErrorRedirect(403);
        }

        (locals as App.Locals).user = { email: session.email ?? "", isAdmin: true };
        resetLoginRateLimit(ip);

        if (session.newAccessToken) {
            await invalidateSessionCache(accessToken);
        }

        const response = await next();

        if (session.newAccessToken && session.newRefreshToken) {
            const expiresIn = session.newExpiresIn ?? 3600;
            cookies.set("sb-access-token",  session.newAccessToken,  { ...COOKIE_OPTIONS, maxAge: expiresIn });
            cookies.set("sb-refresh-token", session.newRefreshToken, { ...COOKIE_OPTIONS, maxAge: 60 * 60 * 24 * 7 });
        }

        return applySecurityWithNonce(response, nonce, isApiRoute);
    }

    // ── 13. Fallback ──────────────────────────────────────────────
    const response = await next();
    return applySecurityWithNonce(response, nonce, isApiRoute);
});
