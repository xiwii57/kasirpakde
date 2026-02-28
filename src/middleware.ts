// src/middleware.ts

// ─── Konstanta ────────────────────────────────────────────────────────────────

const ADMIN_EMAIL           = import.meta.env.ADMIN_EMAIL               as string;
const SUPABASE_URL          = import.meta.env.PUBLIC_SUPABASE_URL       as string;
const SUPABASE_ANON_KEY     = import.meta.env.PUBLIC_SUPABASE_ANON_KEY  as string;
const SUPABASE_SERVICE_ROLE = import.meta.env.SUPABASE_SERVICE_ROLE     as string;
const IS_PROD               = import.meta.env.PROD                      as boolean;
const CANONICAL_DOMAIN      = (import.meta.env.CANONICAL_DOMAIN as string)?.trim() ?? "";

// ─── Domain Redirect ──────────────────────────────────────────────────────────

function redirectToCanonical(request: Request, url: URL): Response | null {
    if (!IS_PROD || !CANONICAL_DOMAIN) return null;

    const host = (request.headers.get("host") ?? url.hostname).split(":")[0].toLowerCase();
    if (host === CANONICAL_DOMAIN) return null;

    const canonical = new URL(url.pathname + url.search, `https://${CANONICAL_DOMAIN}`);
    return new Response(null, {
        status: request.method === "GET" ? 301 : 308,
        headers: {
            "Location":      canonical.toString(), "Cache-Control": "no-store",
        },
    });
}

// ─── Validasi env kritis saat startup ────────────────────────────────────────

for (const [key, val] of Object.entries({
    ADMIN_EMAIL,
    PUBLIC_SUPABASE_URL:      SUPABASE_URL,
    PUBLIC_SUPABASE_ANON_KEY: SUPABASE_ANON_KEY,
    SUPABASE_SERVICE_ROLE,
})) {
    if (!val || typeof val !== "string" || val.trim() === "") {
        throw new Error(`[Middleware] Env var wajib tidak ditemukan atau kosong: ${key}`);
    }
}

if (!SUPABASE_URL.startsWith("https://")) {
    throw new Error("[Middleware] PUBLIC_SUPABASE_URL harus menggunakan HTTPS.");
}

const ADMIN_EMAIL_NORMALIZED = ADMIN_EMAIL.toLowerCase().trim();

const PUBLIC_ROUTES = new Set(["/", "/api/auth/login", "/api/auth/logout", "/api/auth/callback"]);

const PROTECTED_PREFIXES = [
    "/dashboard",
"/kasir",
"/produk",
"/api/kasir",
"/api/admin",
"/api/produk",
];

const STATIC_EXTS = /\.(ico|png|jpg|jpeg|webp|svg|gif|woff2?|ttf|otf|css|js|map|txt|xml|json)$/i;
const MAX_BODY_BYTES = 512 * 1024;
const ALLOWED_METHODS = new Set(["GET", "POST", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const REQUIRED_CONTENT_TYPE_METHODS = new Set(["POST", "PATCH"]);

// ─── Nonce ────────────────────────────────────────────────────────────────────

function generateNonce(): string {
    const arr = new Uint8Array(24);
    crypto.getRandomValues(arr);
    return btoa(String.fromCharCode(...arr))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g,  "");
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

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

function makeRateKey(ip: string, category: RateCategory): string {
    const safeIp = ip.replace(/[^a-fA-F0-9.:]/g, "").slice(0, 45);
    return `${category}:${safeIp}`;
}

function checkRateLimit(ip: string, category: RateCategory): { allowed: boolean; retryAfter: number } {
    const cfg = RATE_CONFIG[category];
    const key  = makeRateKey(ip, category);
    const now  = Date.now();
    const rec  = rateStore.get(key);

    if (!rec || now > rec.resetAt) {
        rateStore.set(key, {
            count: 1, resetAt: now + cfg.windowMs,
            blocked: false, blockUntil: 0, strikes: rec?.strikes ?? 0,
        });
        return { allowed: true, retryAfter: 0 };
    }
    if (rec.strikes >= cfg.maxStrikes) {
        console.warn(`[Middleware] Blokir permanen IP: ${ip} (${category})`);
        return { allowed: false, retryAfter: 9999 };
    }
    if (rec.blocked && now < rec.blockUntil) {
        return { allowed: false, retryAfter: Math.ceil((rec.blockUntil - now) / 1000) };
    }
    if (rec.blocked && now >= rec.blockUntil) {
        rateStore.set(key, {
            count: 1, resetAt: now + cfg.windowMs,
            blocked: false, blockUntil: 0, strikes: rec.strikes,
        });
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
    rateStore.delete(makeRateKey(ip, "login"));
}

if (typeof setInterval !== "undefined") {
    setInterval(() => {
        const now = Date.now();
        for (const [key, rec] of rateStore.entries()) {
            if (now > rec.resetAt && (!rec.blocked || now > rec.blockUntil)) {
                rateStore.delete(key);
            }
        }
    }, 60 * 60 * 1000);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

function redirectRes(url: URL, path: string): Response {
    return new Response(null, {
        status:  302,
        headers: {
            "Location":      new URL(path, url.origin).toString(),
                        "Cache-Control": "no-store, no-cache, must-revalidate, private",
                        "Pragma":        "no-cache",
        },
    });
}

function jsonError(message: string, status: number): Response {
    return new Response(JSON.stringify({ error: message }), {
        status,
        headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
    });
}

function clearSessionCookies(): string[] {
    const base = `Path=/; Max-Age=0; HttpOnly; SameSite=Lax${IS_PROD ? "; Secure" : ""}`;
    return [`sb-access-token=; ${base}`, `sb-refresh-token=; ${base}`];
}

function safeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    const enc    = new TextEncoder();
    const aBytes = enc.encode(a);
    const bBytes = enc.encode(b);
    let diff = 0;
    for (let i = 0; i < aBytes.length; i++) diff |= aBytes[i] ^ bBytes[i];
    return diff === 0;
}

// ─── GET USER VIA REST API (NO WASM) ─────────────────────────────────────────
//
// ⚠️ ROOT CAUSE FIX: supabase.auth.getUser() menggunakan WebAssembly internal
// untuk JWT verification. Vercel Serverless memblokir kompilasi WASM:
//   "CompileError: WebAssembly.compile(): Wasm code generation disallowed by embedder"
//
// Solusi: panggil Supabase Auth REST API langsung via fetch().
// - Token tetap diverifikasi SERVER-SIDE oleh Supabase (bukan client-side)
// - Hasil identik dengan getUser() — user object dengan email, id, dll
// - Zero WASM, zero CompileError
// - Timeout 5 detik untuk hindari hanging request
//
interface SupabaseUser {
    id:                  string;
    email?:              string;
    email_confirmed_at?: string;
    [key: string]:       unknown;
}

async function getUserFromToken(accessToken: string): Promise<{
    user:  SupabaseUser | null;
    error: string | null;
}> {
    try {
        const res = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
            method:  "GET",
            headers: {
                "Authorization": `Bearer ${accessToken}`,
                "apikey":        SUPABASE_ANON_KEY,
                "Content-Type":  "application/json",
            },
            signal: AbortSignal.timeout(5000),
        });

        if (!res.ok) {
            const body = await res.json().catch(() => ({})) as { message?: string };
            return { user: null, error: body.message ?? `HTTP ${res.status}` };
        }

        const user = await res.json() as SupabaseUser;
        return { user, error: null };

    } catch (err) {
        return { user: null, error: err instanceof Error ? err.message : "fetch error" };
    }
}

// ─── REFRESH TOKEN VIA REST API (NO WASM) ────────────────────────────────────
//
// Sama seperti getUserFromToken — hindari WASM dengan panggil REST API langsung.
// Digunakan saat access token expired tapi refresh token masih valid.
//
interface RefreshResult {
    accessToken:  string;
    refreshToken: string;
    expiresIn:    number;
    user:         SupabaseUser;
}

async function refreshSessionFromToken(refreshToken: string): Promise<{
    data:  RefreshResult | null;
    error: string | null;
}> {
    try {
        const res = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`, {
            method:  "POST",
            headers: {
                "apikey":       SUPABASE_ANON_KEY,
                "Content-Type": "application/json",
            },
            body:   JSON.stringify({ refresh_token: refreshToken }),
                                signal: AbortSignal.timeout(5000),
        });

        if (!res.ok) {
            const body = await res.json().catch(() => ({})) as { message?: string };
            return { data: null, error: body.message ?? `HTTP ${res.status}` };
        }

        const body = await res.json() as {
            access_token:  string;
            refresh_token: string;
            expires_in:    number;
            user:          SupabaseUser;
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
    }
}

// ─── CSP & Security Headers ───────────────────────────────────────────────────

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
        `style-src 'self' 'nonce-${nonce}' https://fonts.googleapis.com`,
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

function applySecurityHeaders(response: Response, nonce: string, isApiRoute: boolean): Response {
    const h = new Headers(response.headers);

    h.set("Content-Security-Policy",   buildCSP(nonce));
    h.set("X-Frame-Options",           "DENY");
    h.set("X-Content-Type-Options",    "nosniff");
    h.set("Referrer-Policy",           "no-referrer");
    h.set("X-XSS-Protection",          "0");
    h.set("Permissions-Policy", [
        "camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()",
          "bluetooth=()", "accelerometer=()", "gyroscope=()", "magnetometer=()",
          "interest-cohort=()", "browsing-topics=()",
    ].join(", "));

    if (!h.has("Cache-Control") || h.get("Cache-Control") === "") {
        h.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    }
    h.set("Pragma",  "no-cache");
    h.set("Expires", "0");
    h.set("Vary",    "Cookie");

    h.delete("Server");
    h.delete("X-Powered-By");
    h.delete("X-Runtime");
    h.delete("X-AspNet-Version");

    if (IS_PROD) {
        h.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
    }
    if (!isApiRoute) {
        h.set("Cross-Origin-Opener-Policy",   "same-origin");
        h.set("Cross-Origin-Embedder-Policy", "unsafe-none");
        h.set("Cross-Origin-Resource-Policy", "same-origin");
    }
    if (isApiRoute) {
        h.set("X-Content-Type-Options",       "nosniff");
        h.set("Cross-Origin-Resource-Policy", "same-site");
    }

    return new Response(response.body, {
        status:     response.status,
        statusText: response.statusText,
        headers:    h,
    });
}

// ─── CSRF Protection ──────────────────────────────────────────────────────────

function checkOrigin(request: Request, url: URL): boolean {
    if (!REQUIRED_CONTENT_TYPE_METHODS.has(request.method)) return true;

    const origin  = request.headers.get("origin");
    const referer = request.headers.get("referer");

    const allowedOrigins = new Set([
        url.origin,
        ...(CANONICAL_DOMAIN ? [`https://${CANONICAL_DOMAIN}`] : []),
    ]);

    if (origin && origin !== "null") {
        try { return allowedOrigins.has(new URL(origin).origin); }
        catch { return false; }
    }

    if (origin === "null") {
        const host          = request.headers.get("host") ?? "";
        const expectedHosts = new Set([
            url.host,
            ...(CANONICAL_DOMAIN ? [CANONICAL_DOMAIN] : []),
        ]);
        return expectedHosts.has(host.split(":")[0]) || expectedHosts.has(host);
    }

    if (referer) {
        try { return allowedOrigins.has(new URL(referer).origin); }
        catch { return false; }
    }

    if (IS_PROD) {
        console.warn(`[Middleware] CSRF: tidak ada origin/referer valid di production`);
        return false;
    }
    return true;
}

// ─── Suspicious Request Detection ────────────────────────────────────────────

function isSuspiciousRequest(request: Request, pathname: string): boolean {
    const ua = request.headers.get("user-agent") ?? "";
    if (pathname.includes("../") || pathname.includes("..\\")) return true;
    if (pathname.includes("\0")) return true;
    if (/%[0-9a-f]{2}/i.test(pathname)) {
        const decoded = decodeURIComponent(pathname);
        if (decoded.includes("../") || decoded.includes("<script") || decoded.includes("javascript:")) return true;
    }
    if (!ua && pathname.startsWith("/api/")) return true;
    if (ua.toLowerCase().includes("sqlmap") || ua.toLowerCase().includes("nikto") || ua.toLowerCase().includes("masscan")) return true;
    return false;
}

// ─── Session Validator ────────────────────────────────────────────────────────

interface SessionResult {
    valid:           boolean;
    isAdmin:         boolean;
    email?:          string;
    newAccessToken?: string;
    newExpiresIn?:   number;
}

const sessionCache = new Map<string, { result: SessionResult; expiresAt: number }>();
const SESSION_CACHE_TTL_MS = 30_000;

function getSessionCacheKey(accessToken: string): string {
    return `sc:${accessToken.slice(0, 16)}:${accessToken.slice(-16)}`;
}

export function invalidateSessionCache(accessToken: string): void {
    if (!accessToken) return;
    sessionCache.delete(getSessionCacheKey(accessToken));
}

async function validateSession(accessToken: string, refreshToken: string): Promise<SessionResult> {
    if (!accessToken || !refreshToken) return { valid: false, isAdmin: false };

    const jwtPattern = /^[\w-]+\.[\w-]+\.[\w-]+$/;
    if (!jwtPattern.test(accessToken)) return { valid: false, isAdmin: false };

    const cacheKey = getSessionCacheKey(accessToken);
    const cached   = sessionCache.get(cacheKey);

    // Hanya gunakan cache jika valid=true — jangan cache hasil gagal
    if (cached && Date.now() < cached.expiresAt && cached.result.valid) {
        return cached.result;
    }
    if (cached) sessionCache.delete(cacheKey);

    const store = (result: SessionResult) => {
        if (result.valid) {
            sessionCache.set(cacheKey, { result, expiresAt: Date.now() + SESSION_CACHE_TTL_MS });
        }
        return result;
    };

    try {
        // ✅ FIX UTAMA: gunakan REST API langsung — tidak ada WASM, tidak ada CompileError
        // Sebelumnya: supabase.auth.getUser(accessToken) → WASM crash di Vercel
        // Sekarang:   fetch ke /auth/v1/user dengan Authorization header → zero WASM
        const { user, error } = await getUserFromToken(accessToken);

        if (!error && user) {
            const isAdmin = safeCompare(
                (user.email ?? "").toLowerCase().trim(),
                                        ADMIN_EMAIL_NORMALIZED,
            );
            return store({ valid: true, isAdmin, email: user.email });
        }

        // Access token expired — coba refresh via REST API (juga no WASM)
        const { data: rd, error: re } = await refreshSessionFromToken(refreshToken);

        if (re || !rd) {
            return { valid: false, isAdmin: false };
        }

        const isAdmin = safeCompare(
            (rd.user.email ?? "").toLowerCase().trim(),
                                    ADMIN_EMAIL_NORMALIZED,
        );

        // Token baru — kembalikan tanpa cache agar request berikutnya cache token baru
        return {
            valid:           true,
            isAdmin,
            email:           rd.user.email,
            newAccessToken:  rd.accessToken,
            newExpiresIn:    rd.expiresIn,
        };

    } catch (err) {
        console.error("[Middleware] Session validation error:", err instanceof Error ? err.message : "unknown");
        return { valid: false, isAdmin: false };
    }
}

if (typeof setInterval !== "undefined") {
    setInterval(() => {
        const now = Date.now();
        for (const [key, entry] of sessionCache.entries()) {
            if (now > entry.expiresAt) sessionCache.delete(key);
        }
    }, 5 * 60 * 1000);
}

// ─── Middleware Utama ─────────────────────────────────────────────────────────

export const onRequest = defineMiddleware(async (context, next) => {
    const { request, cookies, url, locals } = context;
    const pathname   = url.pathname;
    const method     = request.method;
    const ip         = getClientIp(request);
    const isApiRoute = pathname.startsWith("/api/");

    const nonce = generateNonce();
    (locals as App.Locals).nonce = nonce;

    // ── 1. Aset statis ────────────────────────────────────────────────────────
    if (isStaticAsset(pathname)) return next();

    // ── 1b. Canonical domain redirect ─────────────────────────────────────────
    const domainRedirect = redirectToCanonical(request, url);
    if (domainRedirect) return domainRedirect;

    // ── 2. Deteksi request mencurigakan ───────────────────────────────────────
    if (isSuspiciousRequest(request, pathname)) {
        console.warn(`[Middleware] Request mencurigakan dari IP: ${ip}, path: ${pathname}`);
        return applySecurityHeaders(new Response("Bad Request", { status: 400 }), nonce, isApiRoute);
    }

    // ── 3. Blokir method berbahaya ────────────────────────────────────────────
    if (!ALLOWED_METHODS.has(method)) {
        return applySecurityHeaders(
            new Response("Method Not Allowed", { status: 405, headers: { Allow: [...ALLOWED_METHODS].join(", ") } }),
                                    nonce, isApiRoute,
        );
    }

    // ── 4. Cegah body terlalu besar ───────────────────────────────────────────
    const contentLength = parseInt(request.headers.get("content-length") ?? "0", 10);
    if (Number.isNaN(contentLength) || contentLength > MAX_BODY_BYTES) {
        return applySecurityHeaders(jsonError("Payload terlalu besar", 413), nonce, isApiRoute);
    }

    // ── 5. CSRF check ─────────────────────────────────────────────────────────
    if (!checkOrigin(request, url)) {
        console.warn(`[Middleware] CSRF check gagal — IP: ${ip}, path: ${pathname}, method: ${method}`);
        return applySecurityHeaders(jsonError("Forbidden: origin tidak valid", 403), nonce, isApiRoute);
    }

    // ── 6. Content-Type validation ────────────────────────────────────────────
    if (REQUIRED_CONTENT_TYPE_METHODS.has(method) && isApiRoute) {
        const ct = request.headers.get("content-type") ?? "";
        const validCT = ct.includes("application/json") ||
        ct.includes("application/x-www-form-urlencoded") ||
        ct.includes("multipart/form-data");
        if (!validCT) {
            return applySecurityHeaders(jsonError("Content-Type tidak valid", 415), nonce, isApiRoute);
        }
    }

    // ── 7. Rate limit login ───────────────────────────────────────────────────
    if (pathname === "/api/auth/login" && method === "POST") {
        const { allowed, retryAfter } = checkRateLimit(ip, "login");
        if (!allowed) {
            const minutes = retryAfter === 9999 ? "sementara" : `${Math.ceil(retryAfter / 60)} menit`;
            console.warn(`[Middleware] Login rate limit: ${ip}`);
            return applySecurityHeaders(
                new Response(
                    JSON.stringify({ error: `Terlalu banyak percobaan. Coba lagi dalam ${minutes}.` }),
                             { status: 429, headers: { "Content-Type": "application/json; charset=utf-8", "Retry-After": String(retryAfter), "Cache-Control": "no-store" } },
                ),
                nonce, isApiRoute,
            );
        }
    }

    // ── 8. Rate limit API umum ────────────────────────────────────────────────
    if (isApiRoute && method !== "GET") {
        const { allowed, retryAfter } = checkRateLimit(ip, "api");
        if (!allowed) {
            return applySecurityHeaders(
                new Response(
                    JSON.stringify({ error: "Terlalu banyak request. Coba lagi sebentar." }),
                             { status: 429, headers: { "Content-Type": "application/json; charset=utf-8", "Retry-After": String(retryAfter), "Cache-Control": "no-store" } },
                ),
                nonce, isApiRoute,
            );
        }
    }

    // ── 9. Route publik ───────────────────────────────────────────────────────
    if (PUBLIC_ROUTES.has(pathname)) {
        const response = await next();
        return applySecurityHeaders(response, nonce, isApiRoute);
    }

    // ── 10. Route terproteksi — validasi session ──────────────────────────────
    if (isProtectedRoute(pathname)) {
        const accessToken  = cookies.get("sb-access-token")?.value  ?? "";
        const refreshToken = cookies.get("sb-refresh-token")?.value ?? "";

        if (!accessToken || !refreshToken) {
            const fail    = isApiRoute ? jsonError("Autentikasi diperlukan.", 401) : redirectRes(url, "/?error=session_expired");
            const headers = new Headers(fail.headers);
            clearSessionCookies().forEach((c) => headers.append("Set-Cookie", c));
            return applySecurityHeaders(new Response(fail.body, { status: fail.status, headers }), nonce, isApiRoute);
        }

        const session = await validateSession(accessToken, refreshToken);

        if (!session.valid) {
            console.warn(`[Middleware] Sesi tidak valid — IP: ${ip}, path: ${pathname}`);
            const fail    = isApiRoute ? jsonError("Sesi tidak valid.", 401) : redirectRes(url, "/?error=session_expired");
            const headers = new Headers(fail.headers);
            clearSessionCookies().forEach((c) => headers.append("Set-Cookie", c));
            return applySecurityHeaders(new Response(fail.body, { status: fail.status, headers }), nonce, isApiRoute);
        }

        if (!session.isAdmin) {
            console.warn(`[Middleware] Non-admin ditolak: ${session.email} — IP: ${ip}`);
            const fail    = isApiRoute ? jsonError("Akses ditolak.", 403) : redirectRes(url, "/?error=unauthorized");
            const headers = new Headers(fail.headers);
            clearSessionCookies().forEach((c) => headers.append("Set-Cookie", c));
            return applySecurityHeaders(new Response(fail.body, { status: fail.status, headers }), nonce, isApiRoute);
        }

        (locals as App.Locals).user = { email: session.email ?? "", isAdmin: true };
        resetLoginRateLimit(ip);

        const response = await next();

        // Token direfresh — update cookie sb-access-token dengan token baru
        if (session.newAccessToken) {
            const expiresIn  = session.newExpiresIn ?? 3600;
            const cookieOpts = `Path=/; HttpOnly; SameSite=Lax; Max-Age=${expiresIn}${IS_PROD ? "; Secure" : ""}`;
            const headers    = new Headers(response.headers);
            headers.append("Set-Cookie", `sb-access-token=${session.newAccessToken}; ${cookieOpts}`);
            return applySecurityHeaders(new Response(response.body, { status: response.status, headers }), nonce, isApiRoute);
        }

        return applySecurityHeaders(response, nonce, isApiRoute);
    }

    // ── 11. Route lainnya (fallback) ──────────────────────────────────────────
    const response = await next();
    return applySecurityHeaders(response, nonce, isApiRoute);
});
