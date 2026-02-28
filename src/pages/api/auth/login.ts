// src/pages/api/auth/login.ts
export const prerender = false;

import type { APIRoute } from "astro";
import { createClient }  from "@supabase/supabase-js";

const ADMIN_EMAIL       = import.meta.env.ADMIN_EMAIL              as string;
const SUPABASE_URL      = import.meta.env.PUBLIC_SUPABASE_URL      as string;
const SUPABASE_ANON_KEY = import.meta.env.PUBLIC_SUPABASE_ANON_KEY as string;
const TURNSTILE_SECRET  = import.meta.env.TURNSTILE_SECRET_KEY     as string;
const IS_PROD           = import.meta.env.PROD as boolean;

// ─── Normalkan ADMIN_EMAIL sekali saja (konsisten dengan middleware) ───────────
const ADMIN_EMAIL_NORMALIZED = ADMIN_EMAIL.toLowerCase().trim();

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Ambil IP nyata klien — logika identik dengan middleware.ts.
 * cf-connecting-ip paling terpercaya (diset Cloudflare, tidak bisa dipalsukan klien).
 */
function getClientIp(request: Request): string {
    const cfIp = request.headers.get("cf-connecting-ip");
    if (cfIp) return cfIp.trim().slice(0, 45);

    const forwarded = request.headers.get("x-forwarded-for");
    if (forwarded) return forwarded.split(",")[0].trim().slice(0, 45);

    return request.headers.get("x-real-ip")?.trim().slice(0, 45) ?? "0.0.0.0";
}

/**
 * Bandingkan string secara constant-time — mencegah timing attack.
 * Identik dengan implementasi di middleware.ts.
 */
function safeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    const enc    = new TextEncoder();
    const aBytes = enc.encode(a);
    const bBytes = enc.encode(b);
    let diff = 0;
    for (let i = 0; i < aBytes.length; i++) {
        diff |= aBytes[i] ^ bBytes[i];
    }
    return diff === 0;
}

function cookieStr(name: string, value: string, maxAge: number): string {
    const base = `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Strict`;
    return IS_PROD ? `${base}; Secure` : base;
}

const SECURITY_HEADERS: [string, string][] = [
    ["Cache-Control",          "no-store"],
["X-Content-Type-Options", "nosniff"],
["X-Frame-Options",        "DENY"],
["Referrer-Policy",        "no-referrer"],
];

function redirectTo(path: string): Response {
    return new Response(null, {
        status:  302,
        headers: new Headers([["Location", path], ...SECURITY_HEADERS]),
    });
}

// Delay acak — samakan response time sukses & gagal (anti-timing attack)
function randomDelay(): Promise<void> {
    return new Promise((r) => setTimeout(r, 300 + Math.random() * 250));
}

// ─── Verifikasi Cloudflare Turnstile ──────────────────────────────────────────
async function verifyTurnstile(token: string, ip: string): Promise<boolean> {
    if (!TURNSTILE_SECRET) {
        if (!IS_PROD) return true; // skip di dev
        console.error("[Login] TURNSTILE_SECRET_KEY tidak di-set di production!");
        return false;
    }
    try {
        const res = await fetch(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            {
                method:  "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body:    new URLSearchParams({
                    secret:   TURNSTILE_SECRET,
                    response: token,
                    remoteip: ip,
                }),
                signal: AbortSignal.timeout(5000),
            },
        );
        if (!res.ok) return false;
        const data = await res.json() as { success: boolean };
        return data.success === true;
    } catch (err) {
        console.error("[Login] Turnstile error:", err);
        return false;
    }
}

// ─── POST /api/auth/login ─────────────────────────────────────────────────────
//
// Catatan: rate limiting sudah ditangani sepenuhnya oleh middleware.ts
// (checkRateLimit "login" + checkRateLimit "api"), sehingga tidak perlu
// rate limiter duplikat di sini.
//
export const POST: APIRoute = async ({ request }) => {
    const ip = getClientIp(request);

    // 1. Validasi Content-Type
    //    Middleware sudah cek untuk /api/* secara umum, tapi /api/auth/login
    //    menerima form-data, bukan JSON — validasi eksplisit tetap diperlukan.
    const ct = request.headers.get("content-type") ?? "";
    if (!ct.includes("application/x-www-form-urlencoded") && !ct.includes("multipart/form-data")) {
        await randomDelay();
        return redirectTo("/?error=invalid_credentials");
    }

    // 2. Parse form
    let formData: FormData;
    try {
        formData = await request.formData();
    } catch {
        return redirectTo("/?error=invalid_credentials");
    }

    const rawEmail = formData.get("email")?.toString().trim().toLowerCase() ?? "";
    const password = formData.get("password")?.toString()                   ?? "";
    const tsToken  = formData.get("cf-turnstile-response")?.toString()      ?? "";

    // 3. Validasi format input
    const emailRegex = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
    if (!rawEmail || !emailRegex.test(rawEmail) || rawEmail.length > 254) {
        await randomDelay();
        return redirectTo("/?error=invalid_credentials");
    }
    if (!password || password.length < 8 || password.length > 128) {
        await randomDelay();
        return redirectTo("/?error=invalid_credentials");
    }

    // 4. Verifikasi Turnstile — sebelum menyentuh Supabase
    if (!tsToken || !(await verifyTurnstile(tsToken, ip))) {
        console.warn(`[Login] Turnstile gagal dari IP: ${ip}`);
        await randomDelay();
        return redirectTo("/?error=invalid_credentials"); // tidak bocorkan alasan spesifik
    }

    // 5. Buat Supabase client per-request agar tidak ada shared state antar request
    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
        auth: {
            autoRefreshToken:   false,
            persistSession:     false,
            detectSessionInUrl: false,
        },
    });

    // 6. Login ke Supabase
    const { data, error } = await supabase.auth.signInWithPassword({
        email:    rawEmail,
        password,
    });

    if (error || !data.session || !data.user) {
        await randomDelay();
        console.warn(`[Login] Gagal: ${rawEmail} dari IP ${ip}`);
        return redirectTo("/?error=invalid_credentials");
    }

    // 7. Cek admin dengan constant-time compare (konsisten dengan middleware.ts)
    //    Pesan error SAMA untuk semua kasus — cegah user enumeration.
    const userEmail = (data.user.email ?? "").toLowerCase().trim();
    if (!safeCompare(userEmail, ADMIN_EMAIL_NORMALIZED)) {
        // Revoke session yang baru saja dibuat
        await createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
            auth: {
                autoRefreshToken:   false,
                persistSession:     false,
                detectSessionInUrl: false,
            },
            global: {
                headers: { Authorization: `Bearer ${data.session.access_token}` },
            },
        }).auth.signOut({ scope: "local" });

        await randomDelay();
        console.warn(`[Login] Bukan admin: ${userEmail} dari IP ${ip}`);
        return redirectTo("/?error=invalid_credentials"); // JANGAN "unauthorized" — bocorkan info
    }

    // 8. Sukses — set cookie
    //    Reset rate limit ditangani oleh middleware.ts (resetLoginRateLimit) setelah
    //    session tervalidasi di request berikutnya ke protected route.
    const { access_token, refresh_token, expires_in } = data.session;
    console.info(`[Login] ✓ Admin login: ${userEmail} dari IP ${ip}`);

    return new Response(null, {
        status:  302,
        headers: new Headers([
            ["Location", "/dashboard"],
            ...SECURITY_HEADERS,
            // Cookie attributes identik dengan clearSessionCookies() di middleware.ts:
            // HttpOnly, SameSite=Strict, Secure (prod only)
            ["Set-Cookie", cookieStr("sb-access-token",  access_token,  expires_in)],
                             ["Set-Cookie", cookieStr("sb-refresh-token", refresh_token, 60 * 60 * 24 * 7)], // 7 hari
        ]),
    });
};

export const GET:    APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const PUT:    APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const DELETE: APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const PATCH:  APIRoute = () => new Response("Method Not Allowed", { status: 405 });
