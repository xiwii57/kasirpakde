// src/middleware/csp.ts
// ══════════════════════════════════════════════════════════════════
// CSP, SECURITY HEADERS & NONCE INJECTOR
// ══════════════════════════════════════════════════════════════════

import { IS_PROD, SUPABASE_URL } from "./constants";

// ── CSP builder ────────────────────────────────────────────────────

export function buildCSP(nonce: string): string {
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

// ── Security headers ───────────────────────────────────────────────

export function applySecurityHeaders(
    response: Response,
    nonce: string,
    isApiRoute: boolean,
): Response {
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

// ── Nonce injector ─────────────────────────────────────────────────

function injectNonceIntoHtml(html: string, nonce: string): string {
    return html.replace(
        /<script(?![^>]*\bnonce\b)([^>]*)>/gi,
                        `<script nonce="${nonce}"$1>`,
    );
}

// ── Gabungan: inject nonce + terapkan security headers ─────────────

export async function applySecurityWithNonce(
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
