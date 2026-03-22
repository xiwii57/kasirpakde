// src/pages/api/piutang/[id].ts
import type { APIRoute } from "astro";
import { createServiceClient } from "../../../../lib/supabase";

export const prerender = false;

/* ═══════════════════════════════════════════════════════════════════════
 * GET /api/piutang/:id
 * Mengembalikan detail satu piutang + seluruh riwayat pembayarannya.
 ═ ═*══════════════════════════════════════════════════════════════════════ */
export const GET: APIRoute = async ({ params, cookies }) => {
    const token = cookies.get("sb-access-token")?.value;
    if (!token) return Response.json({ error: "Unauthorized" }, { status: 401 });

    const { id } = params;
    if (!id) return Response.json({ error: "ID tidak ditemukan" }, { status: 400 });

    try {
        const sb = createServiceClient();

        const { data, error } = await sb
        .from("piutang")
        .select(
            `
            id,
            nama,
            telepon,
            total_hutang,
            terbayar,
            catatan,
            tanggal,
            jatuh_tempo,
            status,
            created_at,
            updated_at,
            piutang_bayar (
                id,
                jumlah,
                catatan,
                created_at
            )
            `
        )
        .eq("id", id)
        .single();

        if (error) {
            const status = error.code === "PGRST116" ? 404 : 500;
            return Response.json({ error: error.message }, { status });
        }

        return Response.json({
            ...data,
            sisa: Math.max(0, (data.total_hutang ?? 0) - (data.terbayar ?? 0)),
        });
    } catch (err: any) {
        console.error("[GET /api/piutang/:id]", err);
        return Response.json({ error: "Internal server error" }, { status: 500 });
    }
};

/* ═══════════════════════════════════════════════════════════════════════
 * PATCH /api/piutang/:id
 * Update data piutang (nama, telepon, catatan, jatuh_tempo, total_hutang).
 * Semua field opsional — hanya field yang dikirim yang diupdate.
 *
 * Body (JSON) — semua opsional:
 * {
 *   nama?         : string
 *   telepon?      : string | null
 *   total_hutang? : number
 *   jatuh_tempo?  : string | null   ("YYYY-MM-DD" atau null untuk hapus)
 *   catatan?      : string | null
 * }
 ═ ═*══════════════════════════════════════════════════════════════════════ */
export const PATCH: APIRoute = async ({ params, request, cookies }) => {
    const token = cookies.get("sb-access-token")?.value;
    if (!token) return Response.json({ error: "Unauthorized" }, { status: 401 });

    const { id } = params;
    if (!id) return Response.json({ error: "ID tidak ditemukan" }, { status: 400 });

    let body: any;
    try {
        body = await request.json();
    } catch {
        return Response.json({ error: "Body tidak valid" }, { status: 400 });
    }

    const updates: Record<string, any> = {};
    const errors: string[] = [];

    /* nama */
    if ("nama" in body) {
        const nama = (body.nama ?? "").toString().trim();
        if (!nama) errors.push("nama tidak boleh kosong");
        else if (nama.length > 80) errors.push("nama maksimal 80 karakter");
        else updates.nama = nama;
    }

    /* telepon */
    if ("telepon" in body) {
        if (body.telepon === null || body.telepon === "") {
            updates.telepon = null;
        } else {
            const t = body.telepon.toString().trim().replace(/\D/g, "").replace(/^(62|0)/, "");
            if (t.length < 7 || t.length > 15) errors.push("telepon tidak valid");
            else updates.telepon = t;
        }
    }

    /* total_hutang */
    if ("total_hutang" in body) {
        const v = parseFloat(body.total_hutang);
        if (isNaN(v) || v <= 0) errors.push("total_hutang harus angka positif");
        else updates.total_hutang = v;
    }

    /* jatuh_tempo */
    if ("jatuh_tempo" in body) {
        if (body.jatuh_tempo === null || body.jatuh_tempo === "") {
            updates.jatuh_tempo = null;
        } else {
            const d = new Date(body.jatuh_tempo);
            if (isNaN(d.getTime())) errors.push("jatuh_tempo bukan tanggal valid");
            else updates.jatuh_tempo = d.toISOString().split("T")[0];
        }
    }

    /* catatan */
    if ("catatan" in body) {
        updates.catatan = body.catatan
        ? body.catatan.toString().trim().slice(0, 200)
        : null;
    }

    if (errors.length > 0) {
        return Response.json({ error: errors.join("; ") }, { status: 422 });
    }

    if (Object.keys(updates).length === 0) {
        return Response.json({ error: "Tidak ada field yang diupdate" }, { status: 400 });
    }

    updates.updated_at = new Date().toISOString();

    try {
        const sb = createServiceClient();

        const { data, error } = await sb
        .from("piutang")
        .update(updates)
        .eq("id", id)
        .select("id, nama, telepon, total_hutang, terbayar, status, jatuh_tempo, catatan, updated_at")
        .single();

        if (error) {
            const status = error.code === "PGRST116" ? 404 : 500;
            return Response.json({ error: error.message }, { status });
        }

        return Response.json({
            ...data,
            sisa: Math.max(0, (data.total_hutang ?? 0) - (data.terbayar ?? 0)),
        });
    } catch (err: any) {
        console.error("[PATCH /api/piutang/:id]", err);
        return Response.json({ error: "Internal server error" }, { status: 500 });
    }
};

/* ═══════════════════════════════════════════════════════════════════════
 * DELETE /api/piutang/:id
 * Hapus piutang beserta semua riwayat pembayarannya (cascade via FK
 * atau manual delete).
 ═ ═*══════════════════════════════════════════════════════════════════════ */
export const DELETE: APIRoute = async ({ params, cookies }) => {
    const token = cookies.get("sb-access-token")?.value;
    if (!token) return Response.json({ error: "Unauthorized" }, { status: 401 });

    const { id } = params;
    if (!id) return Response.json({ error: "ID tidak ditemukan" }, { status: 400 });

    try {
        const sb = createServiceClient();

        /* Hapus riwayat bayar dulu (jika FK tidak ON DELETE CASCADE) */
        const { error: errBayar } = await sb
        .from("piutang_bayar")
        .delete()
        .eq("piutang_id", id);

        if (errBayar) {
            console.error("[DELETE /api/piutang/:id] delete piutang_bayar:", errBayar);
            return Response.json({ error: errBayar.message }, { status: 500 });
        }

        /* Hapus piutang utama */
        const { error } = await sb
        .from("piutang")
        .delete()
        .eq("id", id);

        if (error) {
            const status = error.code === "PGRST116" ? 404 : 500;
            return Response.json({ error: error.message }, { status });
        }

        return Response.json({ success: true }, { status: 200 });
    } catch (err: any) {
        console.error("[DELETE /api/piutang/:id]", err);
        return Response.json({ error: "Internal server error" }, { status: 500 });
    }
};
