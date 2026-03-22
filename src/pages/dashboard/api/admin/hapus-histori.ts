// src/pages/api/admin/hapus-histori.ts
export const prerender = false;

import type { APIRoute } from "astro";
import { createClient }        from "@supabase/supabase-js";
import { createServiceClient } from "../../../../lib/supabase";

// ══════════════════════════════════════════════════════════════════
// DELETE /api/admin/hapus-histori
//
// Body JSON:
//   { type: "transaksi" | "harga_log", range: "hari_ini" | "7_hari" | "30_hari" | "semua" }
//
// Endpoint ini memiliki auth guard sendiri sebagai lapisan pertahanan
// (defense in depth) — tidak hanya mengandalkan middleware.
// ══════════════════════════════════════════════════════════════════

const ADMIN_EMAIL  = import.meta.env.ADMIN_EMAIL              as string;
const SUPABASE_URL = import.meta.env.PUBLIC_SUPABASE_URL      as string;
const ANON_KEY     = import.meta.env.PUBLIC_SUPABASE_ANON_KEY as string;

const MAX_BODY_BYTES  = 1 * 1024; // 1 KB — body hanya berisi 2 field kecil
const MAX_TOKEN_LEN   = 1024;
const BATCH_SIZE      = 500;      // Hapus transaksi per batch agar tidak OOM

type DeleteType  = "transaksi" | "harga_log";
type DeleteRange = "hari_ini" | "7_hari" | "30_hari" | "semua";

const ALLOWED_TYPES:  Set<string> = new Set(["transaksi", "harga_log"]);
const ALLOWED_RANGES: Set<string> = new Set(["hari_ini", "7_hari", "30_hari", "semua"]);

// ── Helpers ────────────────────────────────────────────────────────

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

function jsonError(message: string, status = 400): Response {
    return new Response(JSON.stringify({ ok: false, error: message }), {
        status,
        headers: {
            "Content-Type":           "application/json",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control":          "no-store",
        },
    });
}

// ── FIX: Auth guard lokal sebagai defense in depth ────────────────
// Tidak hanya mengandalkan middleware — jika middleware misconfigured
// atau di-bypass, endpoint ini tetap aman.
async function adminGuard(cookies: any): Promise<boolean> {
    const token = cookies.get("sb-access-token")?.value;
    if (!token || typeof token !== "string") return false;
    if (token.length > MAX_TOKEN_LEN) return false;
    if (!/^[\w-]+\.[\w-]+\.[\w-]+$/.test(token)) return false;

    try {
        const anonClient = createClient(SUPABASE_URL, ANON_KEY, {
            auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
        });
        const { data, error } = await anonClient.auth.getUser(token);
        if (error || !data?.user?.email) return false;
        return data.user.email.toLowerCase().trim() === ADMIN_EMAIL.toLowerCase().trim();
    } catch {
        return false;
    }
}

// ── Hitung cutoff waktu dari range ────────────────────────────────
function getRangeCutoff(range: DeleteRange): Date | null {
    if (range === "semua") return null;

    const nowUTC   = new Date();
    const nowWIB   = new Date(nowUTC.getTime() + 7 * 60 * 60 * 1000);
    const todayWIB = new Date(nowWIB);
    todayWIB.setHours(0, 0, 0, 0);
    const todayStartUTC = new Date(todayWIB.getTime() - 7 * 60 * 60 * 1000);

    if (range === "hari_ini") return todayStartUTC;

    const daysBack = range === "7_hari" ? 6 : 29;
    return new Date(todayStartUTC.getTime() - daysBack * 24 * 60 * 60 * 1000);
}

// ══════════════════════════════════════════════════════════════════
// DELETE handler
// ══════════════════════════════════════════════════════════════════

export const DELETE: APIRoute = async ({ request, cookies }) => {
    // ── 1. FIX: Auth guard lokal — wajib admin ────────────────────
    const isAdmin = await adminGuard(cookies);
    if (!isAdmin) return jsonError("Unauthorized", 401);

    // ── 2. FIX: Validasi Content-Type ────────────────────────────
    const ct = request.headers.get("content-type") ?? "";
    if (!ct.includes("application/json")) {
        return jsonError("Content-Type harus application/json", 415);
    }

    // ── 3. FIX: Baca + validasi ukuran body aktual ────────────────
    let buf: ArrayBuffer;
    try {
        buf = await request.arrayBuffer();
    } catch {
        return jsonError("Gagal membaca body", 400);
    }
    if (buf.byteLength > MAX_BODY_BYTES) {
        return jsonError("Payload terlalu besar", 413);
    }

    let body: unknown;
    try {
        body = JSON.parse(new TextDecoder().decode(buf));
    } catch {
        return jsonError("Body JSON tidak valid.");
    }

    if (!body || typeof body !== "object") return jsonError("Body tidak valid.");

    const { type, range } = body as Record<string, unknown>;

    // ── 4. Validasi input — whitelist ketat ───────────────────────
    if (typeof type !== "string" || !ALLOWED_TYPES.has(type)) {
        return jsonError("Parameter 'type' tidak valid. Gunakan: transaksi | harga_log");
    }
    if (typeof range !== "string" || !ALLOWED_RANGES.has(range)) {
        return jsonError("Parameter 'range' tidak valid. Gunakan: hari_ini | 7_hari | 30_hari | semua");
    }

    const deleteType  = type  as DeleteType;
    const deleteRange = range as DeleteRange;

    // ── 5. Eksekusi delete ────────────────────────────────────────
    const sb     = createServiceClient();
    const cutoff = getRangeCutoff(deleteRange);

    const rangeLabel: Record<DeleteRange, string> = {
        hari_ini: "hari ini",
        "7_hari":  "7 hari terakhir",
        "30_hari": "30 hari terakhir",
        semua:     "semua waktu",
    };

    try {
        if (deleteType === "transaksi") {
            // FIX: Fetch ID dalam batch agar tidak OOM jika data jutaan baris
            let totalDeleted = 0;
            let hasMore      = true;

            while (hasMore) {
                let trxQuery = sb
                .from("transaksi")
                .select("id")
                .limit(BATCH_SIZE);

                if (cutoff) trxQuery = trxQuery.gte("created_at", cutoff.toISOString());

                const { data: trxIds, error: fetchErr } = await trxQuery;
                if (fetchErr) {
                    console.error("[hapus-histori] Fetch transaksi IDs error:", fetchErr.message);
                    return jsonError("Gagal mengambil data transaksi.", 500);
                }

                if (!trxIds || trxIds.length === 0) {
                    hasMore = false;
                    break;
                }

                const ids = trxIds.map((t: { id: string }) => t.id);

                // Hapus transaksi_item (FK child) terlebih dahulu
                const { error: itemErr } = await sb
                .from("transaksi_item")
                .delete()
                .in("transaksi_id", ids);

                if (itemErr) {
                    console.error("[hapus-histori] Hapus transaksi_item error:", itemErr.message);
                    return jsonError("Gagal menghapus item transaksi.", 500);
                }

                // Hapus transaksi (FK parent)
                const { error: trxErr } = await sb
                .from("transaksi")
                .delete()
                .in("id", ids);

                if (trxErr) {
                    console.error("[hapus-histori] Hapus transaksi error:", trxErr.message);
                    return jsonError("Gagal menghapus transaksi.", 500);
                }

                totalDeleted += ids.length;

                // Jika batch kurang dari BATCH_SIZE, berarti sudah habis
                if (ids.length < BATCH_SIZE) hasMore = false;
            }

            console.info(`[hapus-histori] ✓ Hapus ${totalDeleted} transaksi (${rangeLabel[deleteRange]})`);
            return jsonOk({ deleted: totalDeleted, type: deleteType, range: deleteRange });

        } else {
            // Hapus harga_log langsung — tidak ada FK child
            let logQuery = sb.from("harga_log").delete({ count: "exact" });

            if (cutoff) {
                logQuery = logQuery.gte("changed_at", cutoff.toISOString());
            } else {
                // Supabase wajib minimal 1 filter — pakai dummy UUID untuk "hapus semua"
                logQuery = logQuery.neq("id", "00000000-0000-0000-0000-000000000000");
            }

            const { error: logErr, count } = await logQuery;
            if (logErr) {
                console.error("[hapus-histori] Hapus harga_log error:", logErr.message);
                return jsonError("Gagal menghapus log harga.", 500);
            }

            console.info(`[hapus-histori] ✓ Hapus ${count ?? 0} log harga (${rangeLabel[deleteRange]})`);
            return jsonOk({ deleted: count ?? 0, type: deleteType, range: deleteRange });
        }

    } catch (err) {
        console.error("[hapus-histori] Unexpected error:", err instanceof Error ? err.message : err);
        return jsonError("Terjadi kesalahan server.", 500);
    }
};

// ── Blokir method lain ─────────────────────────────────────────────
export const GET:  APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const POST: APIRoute = () => new Response("Method Not Allowed", { status: 405 });
