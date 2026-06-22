// src/middleware/index.ts
// ══════════════════════════════════════════════════════════════════
// MIDDLEWARE UTAMA — entry point
// Orkestrasi semua modul: rate-limit, csrf, session, csp, helpers
// ══════════════════════════════════════════════════════════════════

import { defineMiddleware } from "astro:middleware";

import {
    IS_PROD,
    COOKIE_OPTIONS,
    PUBLIC_ROUTES,
    ERROR_PAGES,
    ALLOWED_METHODS,
    REQUIRED_CT_METHODS,
    MAX_BODY_BYTES,
    MAX_TOKEN_LENGTH,
    MAX_SESSION_AGE_MS,
    ACCESS_TOKEN_MAX_AGE,
    REFRESH_TOKEN_MAX_AGE,
} from "./constants";

import {
    getClientIp,
    isProtectedRoute,
    isStaticAsset,
    isSuspiciousRequest,
    clearAuthCookies,
    generateNonce,
    htmlErrorRedirect,
    jsonError,
    isVercelHost,
    redirectToCanonical,
} from "./helpers";

import { checkRateLimit, resetLoginRateLimit } from "./rate-limit";
import { checkOrigin, handleOptions }          from "./csrf";
import { applySecurityWithNonce }              from "./csp";
import {
    validateSession,
    invalidateSessionCache,
    signSessionMeta,
    verifySessionMeta,
} from "./session";

// ══════════════════════════════════════════════════════════════════
// MIDDLEWARE
// ══════════════════════════════════════════════════════════════════

export const onRequest = defineMiddleware(async (context, next) => {
    const { request, cookies, url, locals } = context;
    const pathname   = url.pathname;
    const method     = request.method;
    const ip         = getClientIp(request);
    const isApiRoute = pathname.startsWith("/dashboard/api/");

    const nonce = generateNonce();
    (locals as App.Locals).nonce = nonce;

    // ── 0. Redirect domain Vercel → canonical ─────────────────────
    const requestHost = request.headers.get("host") ?? "";
    if (isVercelHost(requestHost)) {
        return redirectToCanonical(url);
    }

    // ── 1. Aset statis — skip semua pengecekan ────────────────────
    if (isStaticAsset(pathname)) return next();

    // ── 2. Halaman error custom — bebas diakses ───────────────────
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
            return isApiRoute ? jsonError("Payload terlalu besar", 413) : htmlErrorRedirect(500);
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
        const validCT =
        ct.includes("application/json") ||
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

    // ── 11. Route publik ──────────────────────────────────────────
    if (PUBLIC_ROUTES.has(pathname)) {
        const response = await next();
        return applySecurityWithNonce(response, nonce, isApiRoute);
    }

    // ── 12. Route terproteksi — validasi session ──────────────────
    if (isProtectedRoute(pathname)) {
        const accessToken  = cookies.get("sb-access-token")?.value  ?? "";
        const refreshToken = cookies.get("sb-refresh-token")?.value ?? "";
        const sessionMeta  = cookies.get("sb-session-meta")?.value  ?? "";

        if (
            !accessToken || !refreshToken ||
            accessToken.length  > MAX_TOKEN_LENGTH ||
            refreshToken.length > MAX_TOKEN_LENGTH
        ) {
            clearAuthCookies(cookies);
            return isApiRoute ? jsonError("Autentikasi diperlukan.", 401) : htmlErrorRedirect(401);
        }

        // Cek batas sesi absolut 1 hari via metadata cookie
        let sessionIssuedAt: number | null = null;
        if (sessionMeta) {
            sessionIssuedAt = await verifySessionMeta(sessionMeta);
            if (sessionIssuedAt === null) {
                console.warn(`[Middleware] Session meta tidak valid — IP: ${ip.slice(0, 8)}***`);
                clearAuthCookies(cookies);
                return isApiRoute ? jsonError("Sesi tidak valid.", 401) : htmlErrorRedirect(401);
            }
            if (Date.now() - sessionIssuedAt > MAX_SESSION_AGE_MS) {
                console.info(`[Middleware] Sesi kadaluarsa (>1 hari) — IP: ${ip.slice(0, 8)}***`);
                clearAuthCookies(cookies);
                return isApiRoute
                ? jsonError("Sesi telah berakhir. Silakan login kembali.", 401)
                : htmlErrorRedirect(401);
            }
        }

        const session = await validateSession(accessToken, refreshToken);

        if (!session.valid) {
            console.warn(`[Middleware] Sesi tidak valid — IP: ${ip.slice(0, 8)}***`);
            clearAuthCookies(cookies);
            return isApiRoute ? jsonError("Sesi tidak valid.", 401) : htmlErrorRedirect(401);
        }

        if (!session.isAdmin) {
            console.warn(`[Middleware] Non-admin ditolak — IP: ${ip.slice(0, 8)}***`);
            clearAuthCookies(cookies);
            return isApiRoute ? jsonError("Akses ditolak.", 403) : htmlErrorRedirect(403);
        }

        (locals as App.Locals).user = { email: session.email ?? "", isAdmin: true };
        resetLoginRateLimit(ip);

        if (session.newAccessToken) {
            await invalidateSessionCache(accessToken);
        }

        const response = await next();

        // Perbarui cookie jika access token di-refresh
        if (session.newAccessToken && session.newRefreshToken) {
            const expiresIn = session.newExpiresIn ?? ACCESS_TOKEN_MAX_AGE;
            cookies.set("sb-access-token",  session.newAccessToken,  { ...COOKIE_OPTIONS, maxAge: REFRESH_TOKEN_MAX_AGE });
            cookies.set("sb-refresh-token", session.newRefreshToken, { ...COOKIE_OPTIONS, maxAge: REFRESH_TOKEN_MAX_AGE });
            // Koreksi bug: maxAge cookie access token = 1 hari (bukan expires_in 1 jam)
            // agar cookie tidak hilang sebelum sempat di-refresh
            void expiresIn; // dipakai sebagai info saja, tidak untuk maxAge cookie
        }

        // Set metadata cookie jika belum ada (sesi lama sebelum fitur ini)
        if (!sessionMeta && !session.newAccessToken) {
            const metaValue = await signSessionMeta(Date.now());
            cookies.set("sb-session-meta", metaValue, { ...COOKIE_OPTIONS, maxAge: REFRESH_TOKEN_MAX_AGE });
        }

        return applySecurityWithNonce(response, nonce, isApiRoute);
    }

    // ── 13. Fallback ──────────────────────────────────────────────
    const response = await next();
    return applySecurityWithNonce(response, nonce, isApiRoute);
});
