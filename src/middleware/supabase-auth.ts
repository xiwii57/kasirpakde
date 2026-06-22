// src/middleware/supabase-auth.ts
// ══════════════════════════════════════════════════════════════════
// SUPABASE REST API — getUserFromToken & refreshSessionFromToken
// ══════════════════════════════════════════════════════════════════

import { SUPABASE_URL, SUPABASE_ANON_KEY } from "./constants";

export interface SupabaseUser {
    id:                  string;
    email?:              string;
    email_confirmed_at?: string;
    [key: string]:       unknown;
}

// ── Ambil user dari access token ───────────────────────────────────

export async function getUserFromToken(
    accessToken: string,
): Promise<{ user: SupabaseUser | null; error: string | null }> {
    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), 5000);
    try {
        const res = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
            method:  "GET",
            headers: {
                "Authorization": `Bearer ${accessToken}`,
                "apikey":        SUPABASE_ANON_KEY,
                "Content-Type":  "application/json",
            },
            signal: controller.signal,
        });
        if (!res.ok) {
            const body = await res.json().catch(() => ({})) as { message?: string };
            return { user: null, error: body.message ?? `HTTP ${res.status}` };
        }
        return { user: await res.json() as SupabaseUser, error: null };
    } catch (err) {
        return { user: null, error: err instanceof Error ? err.message : "fetch error" };
    } finally {
        clearTimeout(timer);
    }
}

// ── Refresh session dengan refresh token ───────────────────────────

export async function refreshSessionFromToken(refreshToken: string): Promise<{
    data: {
        accessToken:  string;
        refreshToken: string;
        expiresIn:    number;
        user:         SupabaseUser;
    } | null;
    error: string | null;
}> {
    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), 5000);
    try {
        const res = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`, {
            method:  "POST",
            headers: { "apikey": SUPABASE_ANON_KEY, "Content-Type": "application/json" },
            body:    JSON.stringify({ refresh_token: refreshToken }),
                                signal:  controller.signal,
        });
        if (!res.ok) {
            const body = await res.json().catch(() => ({})) as { message?: string };
            return { data: null, error: body.message ?? `HTTP ${res.status}` };
        }
        const body = await res.json() as {
            access_token: string; refresh_token: string; expires_in: number; user: SupabaseUser;
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
    } finally {
        clearTimeout(timer);
    }
}
