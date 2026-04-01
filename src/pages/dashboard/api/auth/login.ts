// src/pages/api/auth/login.ts
export const prerender = false;

import type { APIRoute } from "astro";
import { createClient }  from "@supabase/supabase-js";

// ══════════════════════════════════════════════════════════════════
// ENV — validasi saat startup
// ══════════════════════════════════════════════════════════════════

const ADMIN_EMAIL       = import.meta.env.ADMIN_EMAIL              as string;
const SUPABASE_URL      = import.meta.env.PUBLIC_SUPABASE_URL      as string;
const SUPABASE_ANON_KEY = import.meta.env.PUBLIC_SUPABASE_ANON_KEY as string;
const TURNSTILE_SECRET  = import.meta.env.TURNSTILE_SECRET_KEY     as string;
const IS_PROD           = import.meta.env.PROD                     as boolean;

if (!ADMIN_EMAIL || !SUPABASE_URL || !SUPABASE_ANON_KEY) {
    throw new Error(
        "[Login] ENV kritis tidak di-set! Pastikan ADMIN_EMAIL, " +
        "PUBLIC_SUPABASE_URL, dan PUBLIC_SUPABASE_ANON_KEY tersedia."
    );
}

const ADMIN_EMAIL_NORMALIZED = ADMIN_EMAIL.toLowerCase().trim();

// ══════════════════════════════════════════════════════════════════
// KONSTANTA
// ══════════════════════════════════════════════════════════════════

const MAX_BODY_BYTES = 16 * 1024; // 16 KB

// ── In-memory rate limiter (lapisan kedua setelah Turnstile) ──────
// Melindungi jika Turnstile dibypass atau tidak tersedia
const LOGIN_RATE_WINDOW_MS = 15 * 60_000; // 15 menit
const LOGIN_RATE_MAX       = 10;          // maks 10 percobaan / 15 menit / IP

const loginRateMap = new Map<string, { count: number; windowStart: number }>();

function checkLoginRateLimit(ip: string): boolean {
    const now    = Date.now();
    const record = loginRateMap.get(ip);
    if (!record || now - record.windowStart > LOGIN_RATE_WINDOW_MS) {
        loginRateMap.set(ip, { count: 1, windowStart: now });
        return true;
    }
    if (record.count >= LOGIN_RATE_MAX) return false;
    record.count++;
    return true;
}

setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of loginRateMap.entries()) {
        if (now - record.windowStart > LOGIN_RATE_WINDOW_MS * 2) loginRateMap.delete(ip);
    }
}, 15 * 60_000);

// ══════════════════════════════════════════════════════════════════
// COOKIE OPTIONS
// ══════════════════════════════════════════════════════════════════

const COOKIE_OPTIONS = {
    path:     "/",
    httpOnly: true,
    // FIX: "strict" lebih aman dari "lax" untuk admin panel
    // "lax" masih memungkinkan cookie dikirim saat navigasi cross-site (link dari luar)
    // "strict" memastikan cookie hanya dikirim dari origin yang sama
    sameSite: "strict" as const,
    secure:   IS_PROD,
} as const;

// ══════════════════════════════════════════════════════════════════
// RESPONSE HELPERS
// ══════════════════════════════════════════════════════════════════

// FIX: Tambah X-Content-Type-Options di semua response
function jsonOk(data: Record<string, unknown> = {}): Response {
    return new Response(JSON.stringify({ ok: true, ...data }), {
        status:  200,
        headers: {
            "Content-Type":           "application/json",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control":          "no-store",
        },
    });
}

function jsonError(error: string, status = 401): Response {
    return new Response(JSON.stringify({ ok: false, error }), {
        status,
        headers: {
            "Content-Type":           "application/json",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control":          "no-store",
        },
    });
}

// ══════════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════════

function getClientIp(request: Request, clientAddress?: string): string {
    return (
        request.headers.get("cf-connecting-ip")?.trim().slice(0, 45) ||
        request.headers.get("x-real-ip")?.trim().slice(0, 45)        ||
        request.headers.get("x-forwarded-for")?.split(",")[0].trim().slice(0, 45) ||
        clientAddress?.slice(0, 45)                                   ||
        "0.0.0.0"
    );
}

function safeCompare(a: string, b: string): boolean {
    const enc    = new TextEncoder();
    const maxLen = Math.max(a.length, b.length, 1);
    const aPad   = a.padEnd(maxLen, "\0");
    const bPad   = b.padEnd(maxLen, "\0");
    const aB     = enc.encode(aPad);
    const bB     = enc.encode(bPad);
    let diff     = a.length === b.length ? 0 : 1;
    for (let i = 0; i < aB.length; i++) diff |= aB[i] ^ bB[i];
    return diff === 0;
}

function randomDelay(): Promise<void> {
    return new Promise((r) => setTimeout(r, 300 + Math.random() * 250));
}

// ══════════════════════════════════════════════════════════════════
// CLOUDFLARE TURNSTILE VERIFICATION
// ══════════════════════════════════════════════════════════════════

async function verifyTurnstile(token: string, ip: string): Promise<boolean> {
    if (!TURNSTILE_SECRET) {
        if (!IS_PROD) return true;
        console.error("[Login] TURNSTILE_SECRET_KEY tidak di-set di production!");
        return false;
    }

    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), 5000);

    try {
        const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
            method:  "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body:    new URLSearchParams({ secret: TURNSTILE_SECRET, response: token, remoteip: ip }),
                                signal:  controller.signal,
        });
        if (!res.ok) return false;
        const data = await res.json() as { success: boolean };
        return data.success === true;
    } catch (err) {
        console.error("[Login] Turnstile error:", err instanceof Error ? err.message : "unknown");
        return false;
    } finally {
        clearTimeout(timer);
    }
}

// ══════════════════════════════════════════════════════════════════
// POST /api/auth/login
// ══════════════════════════════════════════════════════════════════

export const POST: APIRoute = async ({ request, cookies, clientAddress }) => {
    const ip = getClientIp(request, clientAddress);

    // ── 1. Rate limiting — lapisan kedua setelah Turnstile ────────
    // FIX: Cek sebelum parse body agar tidak buang resource
    if (!checkLoginRateLimit(ip)) {
        await randomDelay();
        console.warn(`[Login] Rate limit tercapai dari IP ${ip.slice(0, 8)}***`);
        return jsonError("too_many_attempts", 429);
    }

    // ── 2. Validasi Content-Type ──────────────────────────────────
    const ct = request.headers.get("content-type") ?? "";
    if (!ct.includes("application/x-www-form-urlencoded") && !ct.includes("multipart/form-data")) {
        await randomDelay();
        return jsonError("invalid_credentials");
    }

    // ── 3. Validasi ukuran body aktual sebelum parse ──────────────
    let bodyBuffer: ArrayBuffer;
    try {
        bodyBuffer = await request.arrayBuffer();
    } catch {
        await randomDelay();
        return jsonError("invalid_credentials");
    }

    if (bodyBuffer.byteLength > MAX_BODY_BYTES) {
        await randomDelay();
        return jsonError("invalid_credentials", 413);
    }

    // Reconstruct request dengan body yang sama agar formData() bisa dipanggil
    const clonedRequest = new Request(request.url, {
        method:  request.method,
        headers: request.headers,
        body:    bodyBuffer,
    });

    // ── 4. Parse & sanitasi form data ────────────────────────────
    let formData: FormData;
    try {
        formData = await clonedRequest.formData();
    } catch {
        await randomDelay();
        return jsonError("invalid_credentials");
    }

    const rawEmail = formData.get("email")?.toString().trim().toLowerCase().slice(0, 254) ?? "";
    const password = formData.get("password")?.toString().slice(0, 128)                   ?? "";
    const tsToken  = formData.get("cf-turnstile-response")?.toString().slice(0, 2048)     ?? "";

    // ── 5. Validasi format input ──────────────────────────────────
    const emailRegex = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
    if (!rawEmail || !emailRegex.test(rawEmail)) {
        await randomDelay();
        return jsonError("invalid_credentials");
    }
    if (!password || password.length < 8) {
        await randomDelay();
        return jsonError("invalid_credentials");
    }

    // ── 6. Verifikasi Turnstile captcha ───────────────────────────
    if (!tsToken || !(await verifyTurnstile(tsToken, ip))) {
        console.warn(`[Login] Turnstile gagal dari IP: ${ip.slice(0, 8)}***`);
        await randomDelay();
        return jsonError("turnstile_failed");
    }

    // ── 7. Supabase login ─────────────────────────────────────────
    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
        auth: {
            autoRefreshToken:   false,
            persistSession:     false,
            detectSessionInUrl: false,
        },
    });

    let data: Awaited<ReturnType<typeof supabase.auth.signInWithPassword>>["data"];
    let error: Awaited<ReturnType<typeof supabase.auth.signInWithPassword>>["error"];

    try {
        ({ data, error } = await supabase.auth.signInWithPassword({
            email:    rawEmail,
            password,
        }));
    } catch (err) {
        // FIX: Pastikan randomDelay tetap berjalan meski Supabase throw (timeout, dll)
        await randomDelay();
        console.error("[Login] Supabase signIn exception:", err instanceof Error ? err.message : err);
        return jsonError("invalid_credentials");
    }

    if (error || !data.session || !data.user) {
        await randomDelay();
        console.warn(`[Login] Gagal login dari IP ${ip.slice(0, 8)}***`);
        return jsonError("invalid_credentials");
    }

    // ── 8. Verifikasi admin ───────────────────────────────────────
    const userEmail = (data.user.email ?? "").toLowerCase().trim();
    if (!safeCompare(userEmail, ADMIN_EMAIL_NORMALIZED)) {
        await supabase.auth.signOut({ scope: "global" }).catch(() => null);
        await randomDelay();
        console.warn(`[Login] Bukan admin dari IP ${ip.slice(0, 8)}***`);
        return jsonError("unauthorized");
    }

    // ── 9. Verifikasi email sudah dikonfirmasi ────────────────────
    if (!data.user.email_confirmed_at) {
        await supabase.auth.signOut({ scope: "global" }).catch(() => null);
        await randomDelay();
        console.warn(`[Login] Email belum dikonfirmasi dari IP ${ip.slice(0, 8)}***`);
        return jsonError("invalid_credentials");
    }

    // ── 10. Login sukses — set cookie ─────────────────────────────
    const { access_token, refresh_token, expires_in } = data.session;

    // Buat session meta (HMAC dari waktu login)
    const issuedAt  = Date.now();
    const payload   = issuedAt.toString();
    const raw       = new TextEncoder().encode(SUPABASE_ANON_KEY.slice(0, 64));
    const key       = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig       = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
    const sigB64    = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const metaValue = `${payload}.${sigB64}`;

    cookies.set("sb-access-token",  access_token,  { ...COOKIE_OPTIONS, maxAge: expires_in });
    cookies.set("sb-refresh-token", refresh_token, { ...COOKIE_OPTIONS, maxAge: 60 * 60 * 24 });
    cookies.set("sb-session-meta",  metaValue,     { ...COOKIE_OPTIONS, maxAge: 60 * 60 * 24 });

    console.info(`[Login] ✓ Admin login berhasil dari IP ${ip.slice(0, 8)}***`);

    return jsonOk({ redirect: "/dashboard" });
};

// ══════════════════════════════════════════════════════════════════
// METHOD LAINNYA
// ══════════════════════════════════════════════════════════════════

export const GET: APIRoute = ({ redirect }) => redirect("/", 302);

export const PUT:    APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const DELETE: APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const PATCH:  APIRoute = () => new Response("Method Not Allowed", { status: 405 });
