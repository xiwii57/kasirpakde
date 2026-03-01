// src/pages/api/admin/hapus-histori.ts
export const prerender = false;

import type { APIRoute } from "astro";
import { createServiceClient } from "../../../lib/supabase";

// ══════════════════════════════════════════════════════════════════
// DELETE /api/admin/hapus-histori
//
// Body JSON:
//   { type: "transaksi" | "harga_log", range: "hari_ini" | "7_hari" | "30_hari" | "semua" }
//
// Middleware sudah validasi:
//   - Cookie session admin (isAdmin: true)
//   - CSRF origin check
//   - Rate limit
// Endpoint ini hanya perlu validasi input & eksekusi delete.
// ══════════════════════════════════════════════════════════════════

type DeleteType  = "transaksi" | "harga_log";
type DeleteRange = "hari_ini" | "7_hari" | "30_hari" | "semua";

const ALLOWED_TYPES:  Set<string> = new Set(["transaksi", "harga_log"]);
const ALLOWED_RANGES: Set<string> = new Set(["hari_ini", "7_hari", "30_hari", "semua"]);

function jsonOk(data: Record<string, unknown> = {}): Response {
    return new Response(JSON.stringify({ ok: true, ...data }), {
        status:  200,
        headers: { "Content-Type": "application/json" },
    });
}

function jsonError(message: string, status = 400): Response {
    return new Response(JSON.stringify({ ok: false, error: message }), {
        status,
        headers: { "Content-Type": "application/json" },
    });
}

// Hitung batas waktu UTC dari range yang dipilih
function getRangeCutoff(range: DeleteRange): Date | null {
    if (range === "semua") return null;

    // Semua kalkulasi berbasis WIB (UTC+7) → awal hari WIB → konversi ke UTC
    const nowUTC   = new Date();
    const nowWIB   = new Date(nowUTC.getTime() + 7 * 60 * 60 * 1000);
    const todayWIB = new Date(nowWIB);
    todayWIB.setHours(0, 0, 0, 0);
    // Awal hari ini WIB → UTC
    const todayStartUTC = new Date(todayWIB.getTime() - 7 * 60 * 60 * 1000);

    if (range === "hari_ini") return todayStartUTC;

    const daysBack = range === "7_hari" ? 6 : 29;
    return new Date(todayStartUTC.getTime() - daysBack * 24 * 60 * 60 * 1000);
}

export const DELETE: APIRoute = async ({ request }) => {
    // ── 1. Parse body ─────────────────────────────────────────────
    let body: unknown;
    try {
        body = await request.json();
    } catch {
        return jsonError("Body JSON tidak valid.");
    }

    if (!body || typeof body !== "object") return jsonError("Body tidak valid.");

    const { type, range } = body as Record<string, unknown>;

    // ── 2. Validasi input — whitelist ketat ───────────────────────
    if (typeof type !== "string" || !ALLOWED_TYPES.has(type)) {
        return jsonError("Parameter 'type' tidak valid. Gunakan: transaksi | harga_log");
    }
    if (typeof range !== "string" || !ALLOWED_RANGES.has(range)) {
        return jsonError("Parameter 'range' tidak valid. Gunakan: hari_ini | 7_hari | 30_hari | semua");
    }

    const deleteType  = type  as DeleteType;
    const deleteRange = range as DeleteRange;

    // ── 3. Eksekusi delete ────────────────────────────────────────
    const sb      = createServiceClient();
    const cutoff  = getRangeCutoff(deleteRange);
    const rangeLabel: Record<DeleteRange, string> = {
        hari_ini: "hari ini",
        "7_hari":  "7 hari terakhir",
        "30_hari": "30 hari terakhir",
        semua:     "semua waktu",
    };

    try {
        if (deleteType === "transaksi") {
            // Hapus transaksi_item dulu (FK constraint)
            // Ambil ID transaksi yang akan dihapus
            let trxQuery = sb.from("transaksi").select("id");
            if (cutoff) trxQuery = trxQuery.gte("created_at", cutoff.toISOString());

            const { data: trxIds, error: fetchErr } = await trxQuery;
            if (fetchErr) {
                console.error("[hapus-histori] Fetch transaksi IDs error:", fetchErr.message);
                return jsonError("Gagal mengambil data transaksi.", 500);
            }

            if (trxIds && trxIds.length > 0) {
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

                console.info(`[hapus-histori] ✓ Hapus ${ids.length} transaksi (${rangeLabel[deleteRange]})`);
                return jsonOk({ deleted: ids.length, type: deleteType, range: deleteRange });
            }

            // Tidak ada data untuk dihapus
            return jsonOk({ deleted: 0, type: deleteType, range: deleteRange });

        } else {
            // Hapus harga_log — tidak ada FK child, langsung delete
            let logQuery = sb.from("harga_log").delete();
            if (cutoff) {
                logQuery = logQuery.gte("changed_at", cutoff.toISOString());
            } else {
                // Supabase mengharuskan minimal 1 filter — pakai neq uuid dummy
                // untuk "hapus semua" tanpa filter waktu
                logQuery = logQuery.neq("id", "00000000-0000-0000-0000-000000000000");
            }

            const { error: logErr, count } = await logQuery;
            if (logErr) {
                console.error("[hapus-histori] Hapus harga_log error:", logErr.message);
                return jsonError("Gagal menghapus log harga.", 500);
            }

            console.info(`[hapus-histori] ✓ Hapus log harga (${rangeLabel[deleteRange]})`);
            return jsonOk({ deleted: count ?? 0, type: deleteType, range: deleteRange });
        }

    } catch (err) {
        console.error("[hapus-histori] Unexpected error:", err instanceof Error ? err.message : err);
        return jsonError("Terjadi kesalahan server.", 500);
    }
};

// Blokir method lain
export const GET:  APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const POST: APIRoute = () => new Response("Method Not Allowed", { status: 405 });
