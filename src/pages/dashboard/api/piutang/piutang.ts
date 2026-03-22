// src/pages/api/piutang/piutang.ts
import type { APIRoute } from "astro";
import { createServiceClient } from "../../../../lib/supabase";

export const prerender = false;

/* ═══════════════════════════════════════════════════════════════════════
 * GET /api/piutang/piutang
 * Mengembalikan semua data piutang beserta riwayat bayar dan terbayar.
 *
 * Query params (opsional):
 *   ?status=aktif          → hanya yang belum lunas
 *   ?status=lunas          → hanya yang sudah lunas
 *   ?q=nama                → filter by nama (ILIKE)
 *   ?limit=50              → batas jumlah (default 100)
 *   ?offset=0              → pagination offset
 ═ ═*══════════════════════════════════════════════════════════════════════ */
export const GET: APIRoute = async ({ request, cookies }) => {
    /* ── Auth check ────────────────────────────────────────────────────── */
    const token = cookies.get("sb-access-token")?.value;
    if (!token) {
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    try {
        const sb  = createServiceClient();
        const url = new URL(request.url);

        const status = url.searchParams.get("status");   /* 'aktif' | 'lunas' | null */
        const q      = url.searchParams.get("q");        /* search nama */
        const limit  = Math.min(parseInt(url.searchParams.get("limit") || "100"), 200);
        const offset = parseInt(url.searchParams.get("offset") || "0");

        /* ── Base query ──────────────────────────────────────────────────── */
        let query = sb
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
            `,
            { count: "exact" }
        )
        .order("created_at", { ascending: false })
        .range(offset, offset + limit - 1);

        /* ── Filter status ───────────────────────────────────────────────── */
        if (status === "aktif") {
            query = query.neq("status", "lunas");
        } else if (status === "lunas") {
            query = query.eq("status", "lunas");
        }

        /* ── Filter nama ─────────────────────────────────────────────────── */
        if (q && q.trim()) {
            query = query.ilike("nama", `%${q.trim()}%`);
        }

        const { data, error, count } = await query;

        if (error) {
            console.error("[GET /api/piutang/piutang]", error);
            return Response.json({ error: error.message }, { status: 500 });
        }

        /* ── Hitung sisa per record (derived field) ──────────────────────── */
        const enriched = (data ?? []).map((p) => ({
            ...p,
            sisa: Math.max(0, (p.total_hutang ?? 0) - (p.terbayar ?? 0)),
        }));

        return Response.json(
            { data: enriched, total: count ?? enriched.length },
            { status: 200 }
        );
    } catch (err: any) {
        console.error("[GET /api/piutang/piutang] unexpected:", err);
        return Response.json({ error: "Internal server error" }, { status: 500 });
    }
};

/* ═══════════════════════════════════════════════════════════════════════
 * POST /api/piutang/piutang
 * Membuat catatan hutang baru.
 *
 * Body (JSON):
 * {
 *   nama          : string   — wajib, nama debitur
 *   telepon?      : string   — nomor HP (tanpa +62, boleh kosong)
 *   total_hutang  : number   — wajib, nominal hutang > 0
 *   jatuh_tempo?  : string   — ISO date "YYYY-MM-DD" (opsional)
 *   catatan?      : string   — keterangan bebas (opsional)
 * }
 *
 * Response 201:
 * { data: { id, nama, total_hutang, terbayar, status, ... } }
 ═ ═*══════════════════════════════════════════════════════════════════════ */
export const POST: APIRoute = async ({ request, cookies }) => {
    /* ── Auth check ────────────────────────────────────────────────────── */
    const token = cookies.get("sb-access-token")?.value;
    if (!token) {
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    /* ── Parse body ────────────────────────────────────────────────────── */
    let body: any;
    try {
        body = await request.json();
    } catch {
        return Response.json({ error: "Body tidak valid (bukan JSON)" }, { status: 400 });
    }

    /* ── Validasi ──────────────────────────────────────────────────────── */
    const errors: string[] = [];

    const nama: string = (body.nama ?? "").toString().trim();
    if (!nama) errors.push("nama wajib diisi");
    if (nama.length > 80) errors.push("nama maksimal 80 karakter");

    const totalHutang = parseFloat(body.total_hutang);
    if (isNaN(totalHutang) || totalHutang <= 0) {
        errors.push("total_hutang harus berupa angka positif");
    }

    let telepon: string | null = null;
    if (body.telepon) {
        telepon = body.telepon.toString().trim().replace(/\D/g, ""); /* hanya digit */
        if (telepon.length < 7 || telepon.length > 15) {
            errors.push("telepon tidak valid (7–15 digit)");
        }
        /* normalisasi: hapus leading 0 atau 62, simpan tanpa prefix */
        telepon = telepon.replace(/^(62|0)/, "");
    }

    let jatuhTempo: string | null = null;
    if (body.jatuh_tempo) {
        const d = new Date(body.jatuh_tempo);
        if (isNaN(d.getTime())) {
            errors.push("jatuh_tempo bukan tanggal valid");
        } else {
            jatuhTempo = d.toISOString().split("T")[0]; /* YYYY-MM-DD */
        }
    }

    const catatan: string | null =
    body.catatan ? body.catatan.toString().trim().slice(0, 200) : null;

    if (errors.length > 0) {
        return Response.json({ error: errors.join("; ") }, { status: 422 });
    }

    /* ── Insert ke Supabase ────────────────────────────────────────────── */
    try {
        const sb = createServiceClient();

        const { data, error } = await sb
        .from("piutang")
        .insert({
            nama,
            telepon,
            total_hutang : totalHutang,
            terbayar     : 0,
            status       : "aktif",
            jatuh_tempo  : jatuhTempo,
            catatan,
            tanggal      : new Date().toISOString(),
        })
        .select(
            "id, nama, telepon, total_hutang, terbayar, status, jatuh_tempo, catatan, tanggal, created_at"
        )
        .single();

        if (error) {
            console.error("[POST /api/piutang/piutang]", error);
            return Response.json({ error: error.message }, { status: 500 });
        }

        return Response.json(
            { data: { ...data, sisa: data.total_hutang } },
            { status: 201 }
        );
    } catch (err: any) {
        console.error("[POST /api/piutang/piutang] unexpected:", err);
        return Response.json({ error: "Internal server error" }, { status: 500 });
    }
};
