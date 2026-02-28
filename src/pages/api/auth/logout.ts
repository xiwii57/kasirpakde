// src/pages/api/auth/logout.ts
export const prerender = false;

import type { APIRoute } from "astro";
import { createClient }  from "@supabase/supabase-js";
import { invalidateSessionCache } from "../../../middleware"; // ← tambahan

const SUPABASE_URL          = import.meta.env.PUBLIC_SUPABASE_URL      as string;
const SUPABASE_ANON_KEY     = import.meta.env.PUBLIC_SUPABASE_ANON_KEY as string;
const SUPABASE_SERVICE_ROLE = import.meta.env.SUPABASE_SERVICE_ROLE    as string;
const IS_PROD               = import.meta.env.PROD as boolean;

function clearSessionCookies(): string[] {
    const base = `Path=/; Max-Age=0; HttpOnly; SameSite=Strict${IS_PROD ? "; Secure" : ""}`;
    return [
        `sb-access-token=; ${base}`,
        `sb-refresh-token=; ${base}`,
    ];
}

export const POST: APIRoute = async ({ cookies, request }) => {
    const accessToken  = cookies.get("sb-access-token")?.value  ?? "";
    const refreshToken = cookies.get("sb-refresh-token")?.value ?? "";

    // 1. Bust session cache di middleware — ← tambahan
    //    Tanpa ini, token lama masih lolos lewat cache 30 detik meski sudah di-revoke
    invalidateSessionCache(accessToken);

    // 2. Revoke session di Supabase — ini yang mencegah token lama bisa dipakai ulang.
    //    Dilakukan bahkan jika token sudah expired, agar refresh_token juga di-revoke.
    if (accessToken || refreshToken) {
        try {
            const sbService = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
                auth: {
                    autoRefreshToken:   false,
                    persistSession:     false,
                    detectSessionInUrl: false,
                },
            });

            if (refreshToken) {
                await sbService.auth.admin.signOut(accessToken, "global");
            }

            if (accessToken) {
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
            console.error("[Logout] Gagal revoke session di Supabase:", err instanceof Error ? err.message : err);
        }
    }

    // 3. Clear cookie di browser
    const headers = new Headers([
        ["Location",      "/"],
        ["Cache-Control", "no-store, no-cache, must-revalidate, private"],
        ["Pragma",        "no-cache"],
    ]);
    clearSessionCookies().forEach((c) => headers.append("Set-Cookie", c));

    return new Response(null, { status: 302, headers });
};

export const GET:    APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const PUT:    APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const DELETE: APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const PATCH:  APIRoute = () => new Response("Method Not Allowed", { status: 405 });
