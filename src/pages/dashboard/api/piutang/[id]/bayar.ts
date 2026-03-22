// src/pages/api/piutang/[id]/bayar.ts
import type { APIRoute } from "astro";
import { createServiceClient } from "../../../../../lib/supabase";

export const prerender = false;

/* ═══════════════════════════════════════════════════════════════════════
 * POST /api/piutang/:id/bayar
 * Mencatat satu transaksi pembayaran (cicilan atau pelunasan).
 *
 * Alur:
 * 1. Validasi input
 * 2. Ambil data piutang saat ini untuk cek sisa
 * 3. Insert ke piutang_bayar
 * 4. Update kolom `terbayar` di piutang (akumulasi)
 * 5. Jika terbayar >= total_hutang → set status = 'lunas'
 * 6. Return piutang terbaru + row bayar yang baru dibuat
 *
 * Body (JSON):
 * {
 *   jumlah   : number   — wajib, nominal yang dibayar (> 0, ≤ sisa)
 *   catatan? : string   — keterangan pembayaran (opsional)
 * }
 *
 * Response 201:
 * {
 *   bayar   : { id, piutang_id, jumlah, catatan, created_at },
 *   piutang : { id, nama, total_hutang, terbayar, sisa, status, ... }
 * }
 ═ ═*══════════════════════════════════════════════════════════════════════ */
export const POST: APIRoute = async ({ params, request, cookies }) => {
    /* ── Auth ───────────────────────────────────────────────────────────── */
    const token = cookies.get("sb-access-token")?.value;
    if (!token) {
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { id } = params;
    if (!id) {
        return Response.json({ error: "ID piutang tidak ditemukan" }, { status: 400 });
    }

    /* ── Parse body ─────────────────────────────────────────────────────── */
    let body: any;
    try {
        body = await request.json();
    } catch {
        return Response.json({ error: "Body tidak valid (bukan JSON)" }, { status: 400 });
    }

    /* ── Validasi jumlah ────────────────────────────────────────────────── */
    const jumlah = parseFloat(body.jumlah);
    if (isNaN(jumlah) || jumlah <= 0) {
        return Response.json(
            { error: "jumlah harus berupa angka positif" },
            { status: 422 }
        );
    }

    const catatan: string | null = body.catatan
    ? body.catatan.toString().trim().slice(0, 120)
    : null;

    const sb = createServiceClient();

    try {
        /* ── 1. Ambil data piutang saat ini ─────────────────────────────────
         *     Kita perlu nilai terbayar & total_hutang untuk menghitung sisa
         *     dan menentukan apakah sudah lunas setelah pembayaran ini.        */
        const { data: piutang, error: errFetch } = await sb
        .from("piutang")
        .select("id, nama, total_hutang, terbayar, status")
        .eq("id", id)
        .single();

        if (errFetch) {
            const status = errFetch.code === "PGRST116" ? 404 : 500;
            return Response.json({ error: errFetch.message }, { status });
        }

        /* ── 2. Cek status ──────────────────────────────────────────────────
         *     Jangan izinkan pembayaran untuk piutang yang sudah lunas.        */
        if (piutang.status === "lunas") {
            return Response.json(
                { error: "Piutang ini sudah berstatus lunas" },
                { status: 409 }
            );
        }

        const sisaSekarang = Math.max(
            0,
            (piutang.total_hutang ?? 0) - (piutang.terbayar ?? 0)
        );

        /* ── 3. Cek jumlah tidak melebihi sisa ─────────────────────────────── */
        if (jumlah > sisaSekarang + 0.01) { /* toleransi float kecil */
            return Response.json(
                {
                    error: `Jumlah pembayaran (${jumlah}) melebihi sisa hutang (${sisaSekarang})`,
                },
                { status: 422 }
            );
        }

        /* ── 4. Normalkan jumlah (tidak melebihi sisa persis) ───────────────── */
        const jumlahFinal = Math.min(jumlah, sisaSekarang);

        /* ── 5. Hitung terbayar baru & status baru ─────────────────────────── */
        const terbayarBaru  = (piutang.terbayar ?? 0) + jumlahFinal;
        const sisaBaru      = Math.max(0, (piutang.total_hutang ?? 0) - terbayarBaru);
        const statusBaru    = sisaBaru <= 0 ? "lunas" : "aktif";

        /* ── 6. Insert piutang_bayar ────────────────────────────────────────── */
        const { data: bayarRow, error: errBayar } = await sb
        .from("piutang_bayar")
        .insert({
            piutang_id : id,
            jumlah     : jumlahFinal,
            catatan,
            created_at : new Date().toISOString(),
        })
        .select("id, piutang_id, jumlah, catatan, created_at")
        .single();

        if (errBayar) {
            console.error("[POST /api/piutang/:id/bayar] insert bayar:", errBayar);
            return Response.json({ error: errBayar.message }, { status: 500 });
        }

        /* ── 7. Update piutang: terbayar + status ───────────────────────────── */
        const { data: piutangUpdated, error: errUpdate } = await sb
        .from("piutang")
        .update({
            terbayar   : terbayarBaru,
            status     : statusBaru,
            updated_at : new Date().toISOString(),
        })
        .eq("id", id)
        .select(
            "id, nama, telepon, total_hutang, terbayar, status, jatuh_tempo, catatan, tanggal, updated_at"
        )
        .single();

        if (errUpdate) {
            /* Pembayaran sudah tercatat tapi update gagal — log untuk debugging */
            console.error("[POST /api/piutang/:id/bayar] update piutang:", errUpdate);
            return Response.json({ error: errUpdate.message }, { status: 500 });
        }

        /* ── 8. Response sukses ─────────────────────────────────────────────── */
        return Response.json(
            {
                bayar: bayarRow,
                piutang: {
                    ...piutangUpdated,
                    sisa: Math.max(
                        0,
                        (piutangUpdated.total_hutang ?? 0) - (piutangUpdated.terbayar ?? 0)
                    ),
                },
                lunas: statusBaru === "lunas",
            },
            { status: 201 }
        );
    } catch (err: any) {
        console.error("[POST /api/piutang/:id/bayar] unexpected:", err);
        return Response.json({ error: "Internal server error" }, { status: 500 });
    }
};
