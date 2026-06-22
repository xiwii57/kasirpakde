// src/middleware/jwt.ts
// ══════════════════════════════════════════════════════════════════
// JWT STRUCTURE VALIDATOR
// ══════════════════════════════════════════════════════════════════

import { MAX_TOKEN_LENGTH, MAX_SESSION_AGE_MS } from "./constants";

/**
 * Validasi struktur JWT secara lokal (tanpa verifikasi signature ke Supabase).
 *
 * @param token        - JWT string yang akan divalidasi
 * @param allowExpired - Jika true, token yang sudah expired (exp < now) tetap
 *                       lolos validasi struktur. Dipakai sebelum refresh agar
 *                       token expired bisa diteruskan ke refreshSessionFromToken().
 */
export function isValidJwtStructure(token: string, allowExpired = false): boolean {
    if (!token || typeof token !== "string") return false;
    if (token.length > MAX_TOKEN_LENGTH)      return false;

    const parts = token.split(".");
    if (parts.length !== 3) return false;

    const b64url = /^[A-Za-z0-9_-]+$/;
    if (!parts.every((p) => p.length > 0 && b64url.test(p))) return false;

    try {
        const padded  = parts[1]!.replace(/-/g, "+").replace(/_/g, "/");
        const decoded = atob(padded);
        const payload = JSON.parse(decoded) as Record<string, unknown>;

        // exp: harus ada; kalau allowExpired=false, tidak boleh sudah lewat
        if (typeof payload.exp !== "number") return false;
        if (!allowExpired && payload.exp * 1000 < Date.now()) return false;

        // sub: harus ada dan tidak kosong
        if (typeof payload.sub !== "string" || !payload.sub.trim()) return false;

        // iat: harus ada, tidak di masa depan (toleransi 1 menit), tidak lebih dari 1 hari lalu
        if (typeof payload.iat !== "number")                         return false;
        const iatMs = payload.iat * 1000;
        if (iatMs > Date.now() + 60_000)                            return false;
        if (Date.now() - iatMs > MAX_SESSION_AGE_MS + 60_000)       return false;

        // nbf (not before): jika ada, token belum boleh dipakai sebelum waktu ini
        if (typeof payload.nbf === "number" && payload.nbf * 1000 > Date.now() + 60_000) return false;

        return true;
    } catch { return false; }
}
