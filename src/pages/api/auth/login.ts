// src/pages/api/auth/login.ts
export const prerender = false;

import type { APIRoute } from "astro";
import { createClient }  from "@supabase/supabase-js";

// ══════════════════════════════════════════════════════════════════
// ENV
// ══════════════════════════════════════════════════════════════════

const ADMIN_EMAIL       = import.meta.env.ADMIN_EMAIL              as string;
const SUPABASE_URL      = import.meta.env.PUBLIC_SUPABASE_URL      as string;
const SUPABASE_ANON_KEY = import.meta.env.PUBLIC_SUPABASE_ANON_KEY as string;
const TURNSTILE_SECRET  = import.meta.env.TURNSTILE_SECRET_KEY     as string;
const IS_PROD           = import.meta.env.PROD                     as boolean;

const ADMIN_EMAIL_NORMALIZED = ADMIN_EMAIL.toLowerCase().trim();

// ══════════════════════════════════════════════════════════════════
// COOKIE OPTIONS
// Satu definisi — konsisten dengan COOKIE_OPTIONS di middleware.ts.
// Jika diubah di sini, WAJIB diubah juga di middleware.ts dan sebaliknya.
// Browser mencocokkan path+secure+sameSite saat delete cookie —
// jika tidak sama persis, cookie tidak akan terhapus saat logout.
// ══════════════════════════════════════════════════════════════════

const COOKIE_OPTIONS = {
    path:     "/",
    httpOnly: true,
    sameSite: "lax" as const,
    // SameSite=Lax: cookie dikirim pada top-level GET navigation setelah
    // redirect (POST→302→GET), tapi tidak pada sub-resource cross-origin.
    // SameSite=Strict menyebabkan cookie tidak terkirim setelah redirect
    // sehingga middleware anggap session tidak ada → infinite redirect loop.
    secure:   IS_PROD,
} as const;

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
    // Timing-safe comparison — cegah email enumeration via response timing
    if (a.length !== b.length) return false;
    const enc = new TextEncoder();
    const aB  = enc.encode(a);
    const bB  = enc.encode(b);
    let diff  = 0;
    for (let i = 0; i < aB.length; i++) diff |= aB[i] ^ bB[i];
    return diff === 0;
}

function randomDelay(): Promise<void> {
    // Tambah jitter 300–550ms pada setiap response gagal
    // Cegah timing attack dan brute-force berbasis kecepatan response
    return new Promise((r) => setTimeout(r, 300 + Math.random() * 250));
}

// ══════════════════════════════════════════════════════════════════
// CLOUDFLARE TURNSTILE VERIFICATION
// ══════════════════════════════════════════════════════════════════

async function verifyTurnstile(token: string, ip: string): Promise<boolean> {
    if (!TURNSTILE_SECRET) {
        if (!IS_PROD) return true; // skip di dev jika tidak di-set
        console.error("[Login] TURNSTILE_SECRET_KEY tidak di-set di production!");
        return false;
    }
    try {
        const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
            method:  "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body:    new URLSearchParams({ secret: TURNSTILE_SECRET, response: token, remoteip: ip }),
                                signal:  AbortSignal.timeout(5000),
        });
        if (!res.ok) return false;
        const data = await res.json() as { success: boolean };
        return data.success === true;
    } catch (err) {
        console.error("[Login] Turnstile error:", err);
        return false;
    }
}

// ══════════════════════════════════════════════════════════════════
// POST /api/auth/login
// ══════════════════════════════════════════════════════════════════

export const POST: APIRoute = async ({ request, cookies, redirect, clientAddress }) => {
    const ip = getClientIp(request, clientAddress);

    // ── 1. Validasi Content-Type ──────────────────────────────────
    const ct = request.headers.get("content-type") ?? "";
    if (!ct.includes("application/x-www-form-urlencoded") && !ct.includes("multipart/form-data")) {
        await randomDelay();
        return redirect("/?error=invalid_credentials", 302);
    }

    // ── 2. Parse & sanitasi form data ────────────────────────────
    let formData: FormData;
    try {
        formData = await request.formData();
    } catch {
        await randomDelay();
        return redirect("/?error=invalid_credentials", 302);
    }

    const rawEmail  = formData.get("email")?.toString().trim().toLowerCase().slice(0, 254) ?? "";
    const password  = formData.get("password")?.toString().slice(0, 128)                   ?? "";
    const tsToken   = formData.get("cf-turnstile-response")?.toString().slice(0, 2048)     ?? "";

    // ── 3. Validasi format input ──────────────────────────────────
    const emailRegex = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
    if (!rawEmail || !emailRegex.test(rawEmail)) {
        await randomDelay();
        return redirect("/?error=invalid_credentials", 302);
    }
    if (!password || password.length < 8) {
        await randomDelay();
        return redirect("/?error=invalid_credentials", 302);
    }

    // ── 4. Verifikasi Turnstile captcha ───────────────────────────
    if (!tsToken || !(await verifyTurnstile(tsToken, ip))) {
        console.warn(`[Login] Turnstile gagal dari IP: ${ip}`);
        await randomDelay();
        return redirect("/?error=invalid_credentials", 302);
    }

    // ── 5. Supabase login ─────────────────────────────────────────
    // Buat client per-request dengan persistSession: false —
    // tidak ada state yang bocor antar request di serverless environment.
    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
        auth: {
            autoRefreshToken:   false,
            persistSession:     false,
            detectSessionInUrl: false,
        },
    });

    const { data, error } = await supabase.auth.signInWithPassword({
        email:    rawEmail,
        password,
    });

    if (error || !data.session || !data.user) {
        await randomDelay();
        console.warn(`[Login] Gagal login: ${rawEmail} dari IP ${ip}`);
        return redirect("/?error=invalid_credentials", 302);
    }

    // ── 6. Verifikasi admin ───────────────────────────────────────
    // Defense in depth: cek di sini DAN di middleware.
    // Jika bukan admin → revoke token di Supabase langsung,
    // jangan biarkan token valid beredar meski tidak bisa akses dashboard.
    const userEmail = (data.user.email ?? "").toLowerCase().trim();
    if (!safeCompare(userEmail, ADMIN_EMAIL_NORMALIZED)) {
        // Revoke token menggunakan client yang sama — tidak perlu buat client baru
        await supabase.auth.signOut({ scope: "local" });
        await randomDelay();
        console.warn(`[Login] Bukan admin: ${userEmail} dari IP ${ip}`);
        return redirect("/?error=invalid_credentials", 302);
    }

    // ── 7. Verifikasi email sudah dikonfirmasi ────────────────────
    if (!data.user.email_confirmed_at) {
        await supabase.auth.signOut({ scope: "local" });
        await randomDelay();
        console.warn(`[Login] Email belum dikonfirmasi: ${userEmail} dari IP ${ip}`);
        return redirect("/?error=invalid_credentials", 302);
    }

    // ── 8. Login sukses — set cookie via Astro cookies API ───────
    //
    // ✅ KRITIS: Pakai cookies.set() bukan raw Set-Cookie string.
    // Astro mengelola Set-Cookie header secara internal — dijamin
    // tidak hilang saat middleware memproses response, berbeda dengan
    // headers.append("Set-Cookie", ...) yang bisa hilang jika middleware
    // membuat Response baru dari nol.
    const { access_token, refresh_token, expires_in } = data.session;

    cookies.set("sb-access-token",  access_token,  { ...COOKIE_OPTIONS, maxAge: expires_in });
    cookies.set("sb-refresh-token", refresh_token, { ...COOKIE_OPTIONS, maxAge: 60 * 60 * 24 * 7 });

    console.info(`[Login] ✓ Admin login: ${userEmail} dari IP ${ip}`);

    return redirect("/dashboard", 302);
};

// ══════════════════════════════════════════════════════════════════
// METHOD LAINNYA
// ══════════════════════════════════════════════════════════════════

export const GET: APIRoute = ({ redirect }) =>
redirect("/", 302);

export const PUT:    APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const DELETE: APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const PATCH:  APIRoute = () => new Response("Method Not Allowed", { status: 405 });
