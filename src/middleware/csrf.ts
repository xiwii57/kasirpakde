// src/middleware/csrf.ts
// ══════════════════════════════════════════════════════════════════
// CSRF PROTECTION & OPTIONS PREFLIGHT
// ══════════════════════════════════════════════════════════════════

import { IS_PROD, AUTH_FORM_ROUTES, REQUIRED_CT_METHODS } from "./constants";

// ── Allowed origins ────────────────────────────────────────────────

export function getAllowedOrigins(request: Request): Set<string> {
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

// ── CSRF check ─────────────────────────────────────────────────────

export function checkOrigin(request: Request, url: URL): boolean {
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
                console.warn("[CSRF] Origin tidak ada untuk login endpoint");
                return false;
            }
            console.warn("[CSRF] Origin tidak ada untuk API endpoint");
            return false;
        }
        try {
            const originUrl = new URL(origin);
            const allowed   = allowedOrigins.has(originUrl.origin);
            if (!allowed) console.warn("[CSRF] Ditolak — origin tidak diizinkan");
            return allowed;
        } catch { return false; }
    }

    if (!origin || origin === "null") {
        if (request.method === "GET") return true;
        if (referer) {
            try { return allowedOrigins.has(new URL(referer).origin); }
            catch { return false; }
        }
        console.warn(`[CSRF] Tidak ada origin maupun referer untuk ${request.method} request`);
        return false;
    }

    try { return allowedOrigins.has(new URL(origin).origin); }
    catch { return false; }
}

// ── OPTIONS preflight ──────────────────────────────────────────────

export function handleOptions(request: Request): Response | null {
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
