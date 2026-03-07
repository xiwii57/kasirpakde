// src/pages/api/auth/logout.ts
export const prerender = false;

import type { APIRoute } from "astro";
import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL          = import.meta.env.PUBLIC_SUPABASE_URL      as string;
const SUPABASE_ANON_KEY     = import.meta.env.PUBLIC_SUPABASE_ANON_KEY as string;
const SUPABASE_SERVICE_ROLE = import.meta.env.SUPABASE_SERVICE_ROLE    as string;
const IS_PROD               = import.meta.env.PROD as boolean;

// FIX: Hapus import invalidateSessionCache dari middleware.
// Jika middleware di-refactor, import ini akan crash seluruh logout endpoint.
// Cache invalidation sebaiknya dilakukan di middleware itu sendiri dengan
// mendeteksi response 401 dari Supabase saat token dipakai berikutnya.

// ── Helpers ────────────────────────────────────────────────────────────────

function clearSessionCookies(): string[] {
    const base = `Path=/; Max-Age=0; HttpOnly; SameSite=Strict${IS_PROD ? "; Secure" : ""}`;
    return [
        `sb-access-token=; ${base}`,
        `sb-refresh-token=; ${base}`,
    ];
}

/** Sanitasi token — pastikan berbentuk JWT 3-part sebelum dikirim ke Supabase */
function isValidJwtShape(token: string): boolean {
    return (
        typeof token === "string" &&
        token.length > 0 &&
        token.length < 2048 &&
        /^[\w-]+\.[\w-]+\.[\w-]+$/.test(token)
    );
}

// ── POST /api/auth/logout ──────────────────────────────────────────────────

export const POST: APIRoute = async ({ cookies }) => {
    const accessToken  = cookies.get("sb-access-token")?.value  ?? "";
    const refreshToken = cookies.get("sb-refresh-token")?.value ?? "";

    // Selalu clear cookie di akhir, terlepas dari hasil revoke
    const headers = new Headers([
        ["Location",      "/"],
        ["Cache-Control", "no-store, no-cache, must-revalidate, private"],
        ["Pragma",        "no-cache"],
    ]);
    clearSessionCookies().forEach(c => headers.append("Set-Cookie", c));

    // Jika tidak ada token sama sekali — langsung redirect, tidak perlu revoke
    if (!accessToken && !refreshToken) {
        return new Response(null, { status: 302, headers });
    }

    try {
        // FIX: Validasi bentuk token sebelum dikirim ke Supabase
        if (accessToken && isValidJwtShape(accessToken)) {
            // Revoke semua session user ini secara global via service role
            // (ini sekaligus me-revoke refresh_token yang terkait)
            const sbService = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
                auth: {
                    autoRefreshToken:   false,
                    persistSession:     false,
                    detectSessionInUrl: false,
                },
            });

            // FIX: signOut admin menggunakan accessToken (bukan refreshToken)
            // scope "global" memastikan semua device/session ikut di-revoke
            await sbService.auth.admin.signOut(accessToken, "global");
        }

        // Revoke sisi client juga agar Supabase JS SDK ikut bersih
        if (accessToken && isValidJwtShape(accessToken)) {
            const sbAnon = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
                auth: {
                    autoRefreshToken:   false,
                    persistSession:     false,
                    detectSessionInUrl: false,
                },
                global: {
                    headers: { Authorization: `Bearer ${accessToken}` },
                },
            });
            await sbAnon.auth.signOut({ scope: "global" });
        }
    } catch (err) {
        // FIX: Error revoke tidak boleh mencegah cookie di-clear.
        // Cookie tetap dihapus — user tetap ter-logout di browser.
        // Token yang gagal di-revoke akan expire secara natural.
        console.error(
            "[Logout] Gagal revoke session di Supabase:",
            err instanceof Error ? err.message : err
        );
    }

    return new Response(null, { status: 302, headers });
};

// ── Method lain → 405 ─────────────────────────────────────────────────────

export const GET:    APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const PUT:    APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const DELETE: APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const PATCH:  APIRoute = () => new Response("Method Not Allowed", { status: 405 });
