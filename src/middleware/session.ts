// src/middleware/session.ts
// ══════════════════════════════════════════════════════════════════
// SESSION — metadata cookie (HMAC), cache sesi, validasi sesi
// ══════════════════════════════════════════════════════════════════

import { SUPABASE_ANON_KEY, ADMIN_EMAIL_NORMALIZED, MAX_TOKEN_LENGTH } from "./constants";
import { isValidJwtStructure }                                          from "./jwt";
import { getUserFromToken, refreshSessionFromToken }                    from "./supabase-auth";
import { safeCompare }                                                  from "./helpers";

// ══════════════════════════════════════════════════════════════════
// SESSION METADATA COOKIE (HMAC-SHA256)
// Menyimpan waktu login (iat) untuk penegakan batas 1 hari absolut.
// Dienkode dengan HMAC agar tidak bisa dipalsukan klien.
// ══════════════════════════════════════════════════════════════════

async function getHmacKey(): Promise<CryptoKey> {
    const raw = new TextEncoder().encode(SUPABASE_ANON_KEY.slice(0, 64));
    return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function signSessionMeta(issuedAt: number): Promise<string> {
    const payload = issuedAt.toString();
    const key     = await getHmacKey();
    const sig     = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
    const sigB64  = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    return `${payload}.${sigB64}`;
}

export async function verifySessionMeta(value: string): Promise<number | null> {
    const parts = value.split(".");
    if (parts.length !== 2) return null;
    const [payload, sigB64] = parts as [string, string];
    const issuedAt = parseInt(payload, 10);
    if (isNaN(issuedAt) || issuedAt <= 0) return null;
    const key      = await getHmacKey();
    const sigBytes = Uint8Array.from(
        atob(sigB64.replace(/-/g, "+").replace(/_/g, "/")),
                                     (c) => c.charCodeAt(0),
    );
    const valid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(payload));
    if (!valid) return null;
    return issuedAt;
}

// ══════════════════════════════════════════════════════════════════
// SESSION CACHE
// TTL pendek (15 detik) untuk menghindari hit Supabase setiap request
// tanpa mengorbankan keamanan.
// ══════════════════════════════════════════════════════════════════

export interface SessionResult {
    valid:            boolean;
    isAdmin:          boolean;
    email?:           string;
    newAccessToken?:  string;
    newRefreshToken?: string;
    newExpiresIn?:    number;
}

const sessionCache      = new Map<string, { result: SessionResult; expiresAt: number }>();
const SESSION_CACHE_TTL = 15_000; // 15 detik

// Cleanup cache tiap 1 menit
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [k, entry] of sessionCache.entries()) {
        if (now > entry.expiresAt) { sessionCache.delete(k); cleaned++; }
    }
    if (cleaned > 0) console.info(`[Session] Cache cleanup: ${cleaned} entry dihapus.`);
}, 60_000);

async function getSessionCacheKey(token: string): Promise<string> {
    const encoded = new TextEncoder().encode(token);
    const hashBuf = await crypto.subtle.digest("SHA-256", encoded);
    const hashArr = Array.from(new Uint8Array(hashBuf));
    return "sc:" + hashArr.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function invalidateSessionCache(accessToken: string): Promise<void> {
    if (accessToken) {
        const key = await getSessionCacheKey(accessToken);
        sessionCache.delete(key);
    }
}

// ══════════════════════════════════════════════════════════════════
// VALIDATE SESSION
// Urutan: cache hit → getUserFromToken → refreshSessionFromToken
// allowExpired=true agar token expired bisa masuk ke alur refresh.
// ══════════════════════════════════════════════════════════════════

export async function validateSession(
    accessToken: string,
    refreshToken: string,
): Promise<SessionResult> {
    if (!accessToken || !refreshToken)                     return { valid: false, isAdmin: false };
    if (accessToken.length  > MAX_TOKEN_LENGTH)            return { valid: false, isAdmin: false };
    if (refreshToken.length > MAX_TOKEN_LENGTH)            return { valid: false, isAdmin: false };

    // Izinkan token expired agar bisa diteruskan ke refresh flow
    if (!isValidJwtStructure(accessToken, true))           return { valid: false, isAdmin: false };

    const cacheKey = await getSessionCacheKey(accessToken);

    // Emergency cleanup jika cache membesar
    if (sessionCache.size > 200) {
        const now = Date.now();
        for (const [k, entry] of sessionCache.entries()) {
            if (now > entry.expiresAt) sessionCache.delete(k);
        }
    }

    // Cache hit
    const cached = sessionCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt && cached.result.valid) return cached.result;
    if (cached) sessionCache.delete(cacheKey);

    try {
        // Coba validasi access token ke Supabase
        const { user, error } = await getUserFromToken(accessToken);
        if (!error && user) {
            const isAdmin = safeCompare((user.email ?? "").toLowerCase().trim(), ADMIN_EMAIL_NORMALIZED);
            const result: SessionResult = { valid: true, isAdmin, email: user.email };
            sessionCache.set(cacheKey, { result, expiresAt: Date.now() + SESSION_CACHE_TTL });
            return result;
        }

        // Access token expired / invalid — coba refresh
        const { data: rd, error: re } = await refreshSessionFromToken(refreshToken);
        if (re || !rd) return { valid: false, isAdmin: false };

        const isAdmin = safeCompare((rd.user.email ?? "").toLowerCase().trim(), ADMIN_EMAIL_NORMALIZED);
        // Invalidasi cache token lama
        sessionCache.delete(cacheKey);
        return {
            valid:           true,
            isAdmin,
            email:           rd.user.email,
            newAccessToken:  rd.accessToken,
            newRefreshToken: rd.refreshToken,
            newExpiresIn:    rd.expiresIn,
        };
    } catch (err) {
        console.error("[Session] validateSession error:", err instanceof Error ? err.message : "unknown");
        return { valid: false, isAdmin: false };
    }
}
