// src/middleware/helpers.ts
// ══════════════════════════════════════════════════════════════════
// FUNGSI UTILITAS UMUM
// ══════════════════════════════════════════════════════════════════

import type { AstroCookies } from "astro";
import {
    CANONICAL_HOST,
    VERCEL_HOST_RE,
    COOKIE_OPTIONS,
    PUBLIC_ROUTES,
    PROTECTED_PREFIXES,
    STATIC_EXTS,
} from "./constants";

// ── Redirect helpers ───────────────────────────────────────────────

export function htmlErrorRedirect(code: 401 | 403 | 429 | 500, extra?: string): Response {
    const base = `/${code}`;
    const loc  = extra ? `${base}?${extra}` : base;
    return new Response(null, {
        status:  302,
        headers: { Location: loc },
    });
}

export function jsonError(message: string, status: number, retryAfter?: number): Response {
    const headers: Record<string, string> = {
        "Content-Type":  "application/json; charset=utf-8",
        "Cache-Control": "no-store",
    };
    if (retryAfter) headers["Retry-After"] = String(retryAfter);
    return new Response(JSON.stringify({ error: message }), { status, headers });
}

// ── Host / canonical ───────────────────────────────────────────────

export function isVercelHost(host: string): boolean {
    const hostname = host.split(":")[0]!.toLowerCase();
    return VERCEL_HOST_RE.test(hostname);
}

export function redirectToCanonical(url: URL): Response {
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

// ── Client IP ──────────────────────────────────────────────────────

export function getClientIp(request: Request): string {
    const cfIp = request.headers.get("cf-connecting-ip");
    if (cfIp) return cfIp.trim().slice(0, 45);
    const forwarded = request.headers.get("x-forwarded-for");
    if (forwarded) return forwarded.split(",")[0]!.trim().slice(0, 45);
    return request.headers.get("x-real-ip")?.trim().slice(0, 45) ?? "0.0.0.0";
}

// ── Route classification ───────────────────────────────────────────

export function isProtectedRoute(pathname: string): boolean {
    if (PUBLIC_ROUTES.has(pathname)) return false;
    return PROTECTED_PREFIXES.some((p) => pathname === p || pathname.startsWith(p + "/"));
}

export function isStaticAsset(pathname: string): boolean {
    return pathname.startsWith("/_astro/") || STATIC_EXTS.test(pathname);
}

// ── Crypto utils ───────────────────────────────────────────────────

export function safeCompare(a: string, b: string): boolean {
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

export function generateNonce(): string {
    const arr = new Uint8Array(24);
    crypto.getRandomValues(arr);
    return btoa(String.fromCharCode(...arr))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g,  "");
}

// ── Cookie cleanup ─────────────────────────────────────────────────

export function clearAuthCookies(cookies: AstroCookies): void {
    cookies.delete("sb-access-token",  COOKIE_OPTIONS);
    cookies.delete("sb-refresh-token", COOKIE_OPTIONS);
    cookies.delete("sb-session-meta",  COOKIE_OPTIONS);
}

// ── Suspicious request detection ───────────────────────────────────

export function isSuspiciousRequest(request: Request, pathname: string): boolean {
    const ua = request.headers.get("user-agent") ?? "";
    if (pathname.includes("../") || pathname.includes("..\\")) return true;
    if (pathname.includes("\0"))                               return true;
    if (/%[0-9a-f]{2}/i.test(pathname)) {
        const decoded = decodeURIComponent(pathname);
        if (decoded.includes("../") || decoded.includes("<script") || decoded.includes("javascript:")) return true;
    }
    if (!ua && pathname.startsWith("/dashboard/api/")) return true;
    const badUa = ["sqlmap", "nikto", "masscan", "zgrab", "nuclei"];
    if (badUa.some((b) => ua.toLowerCase().includes(b)))      return true;
    return false;
}
