export const prerender = false;

import type { APIRoute } from "astro";
import { createServiceClient } from "../../../lib/supabase";

// ── Konstanta ──────────────────────────────────────────────────────────────
const MAX_NAMA     = 100;
const MAX_HARGA    = 999_999_999;
const MAX_BODY     = 512 * 1024; // 512 KB — FIX #10
const UUID_RE      = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const KATEGORI_OK  = new Set([
    "Minuman", "Makanan", "Rokok", "Es Krim",
    "Kebutuhan Rumah", "Pulsa & Data", "Lainnya",
]);

// ── Helpers ────────────────────────────────────────────────────────────────
function json(data: unknown, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type":           "application/json",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control":          "no-store",
        },
    });
}

/** Verifikasi token ke Supabase — bukan sekadar cek keberadaan cookie */
async function authGuard(cookies: any): Promise<boolean> {
    const token = cookies.get("sb-access-token")?.value;
    if (!token) return false;

    const sb = createServiceClient();
    const { data, error } = await sb.auth.getUser(token);
    return !error && !!data?.user;
}

// FIX #10 — Baca body aktual dan cek ukurannya, bukan hanya header Content-Length
async function readJsonBody(request: Request): Promise<{ ok: true; body: unknown } | { ok: false; error: string; status: number }> {
    let buf: ArrayBuffer;
    try {
        buf = await request.arrayBuffer();
    } catch {
        return { ok: false, error: "Gagal membaca body", status: 400 };
    }
    if (buf.byteLength > MAX_BODY) {
        return { ok: false, error: "Payload terlalu besar (maks 512 KB)", status: 413 };
    }
    try {
        const body = JSON.parse(new TextDecoder().decode(buf));
        return { ok: true, body };
    } catch {
        return { ok: false, error: "Body bukan JSON valid", status: 400 };
    }
}

function isValidUUID(id: string): boolean {
    return UUID_RE.test(id);
}

function sanitizeNama(s: string): string {
    return s.trim().replace(/\s+/g, " ").slice(0, MAX_NAMA);
}

function validateHarga(val: unknown, fieldName: string): { ok: true; value: number } | { ok: false; error: string } {
    const n = Number(val);
    if (!Number.isFinite(n) || n < 0)
        return { ok: false, error: `${fieldName} harus angka >= 0` };
    if (n > MAX_HARGA)
        return { ok: false, error: `${fieldName} terlalu besar` };
    return { ok: true, value: Math.round(n) };
}

function validateKategori(k: string): string {
    return KATEGORI_OK.has(k) ? k : "Lainnya";
}

// ── GET /api/produk/produk ─────────────────────────────────────────────────
export const GET: APIRoute = async ({ url, cookies }) => {
    if (!await authGuard(cookies)) return json({ error: "Unauthorized" }, 401);

    const sb        = createServiceClient();
    const search    = url.searchParams.get("q")?.slice(0, 100)  ?? "";
    const katFilter = url.searchParams.get("kategori")          ?? "";
    const filterLow = url.searchParams.get("filter") === "low_margin";

    const safeKat = katFilter && KATEGORI_OK.has(katFilter) ? katFilter : "";

    let query = sb
    .from("produk")
    .select("id, nama_produk, harga_beli, harga_jual, kategori, quick_cash, created_at, updated_at")
    .order("nama_produk");

    if (search)  query = query.ilike("nama_produk", `%${search.replace(/[%_]/g, "\\$&")}%`);
    if (safeKat) query = query.eq("kategori", safeKat);

    const { data, error } = await query;
    if (error) return json({ error: "Gagal mengambil data" }, 500);

    let produk = data ?? [];
    if (filterLow)
        produk = produk.filter(
            (p: any) => p.harga_beli > 0 && (p.harga_jual - p.harga_beli) / p.harga_beli < 0.1
        );

    return json(produk);
};

// ── POST /api/produk/produk ────────────────────────────────────────────────
export const POST: APIRoute = async ({ request, cookies }) => {
    if (!await authGuard(cookies)) return json({ error: "Unauthorized" }, 401);

    // FIX #10 — Baca + validasi ukuran body aktual
    const read = await readJsonBody(request);
    if (!read.ok) return json({ error: read.error }, read.status);
    const body = read.body;

    const sb = createServiceClient();

    // ── Bulk insert ──
    if (Array.isArray(body)) {
        if (body.length === 0)   return json({ error: "Array kosong" }, 400);
        if (body.length > 500)   return json({ error: "Maks 500 produk per request" }, 400);

        const rows: any[] = [];
        for (const [i, r] of body.entries()) {
            const nama = sanitizeNama(String(r.nama_produk ?? ""));
            if (!nama) return json({ error: `Baris ${i + 1}: nama_produk wajib` }, 400);

            const beli = validateHarga(r.harga_beli ?? 0, "harga_beli");
            const jual = validateHarga(r.harga_jual ?? 0, "harga_jual");
            if (!beli.ok) return json({ error: `Baris ${i + 1}: ${beli.error}` }, 400);
            if (!jual.ok) return json({ error: `Baris ${i + 1}: ${jual.error}` }, 400);

            rows.push({
                nama_produk: nama,
                harga_beli:  beli.value,
                harga_jual:  jual.value,
                kategori:    validateKategori(String(r.kategori ?? "")),
                      quick_cash:  Boolean(r.quick_cash),
            });
        }

        const { error } = await sb.from("produk").insert(rows);
        if (error) return json({ error: "Gagal menyimpan data" }, 500);
        return json({ inserted: rows.length });
    }

    // ── Single insert ──
    if (typeof body !== "object" || body === null)
        return json({ error: "Body tidak valid" }, 400);

    const b = body as Record<string, unknown>;
    const nama = sanitizeNama(String(b.nama_produk ?? ""));
    if (!nama) return json({ error: "nama_produk wajib diisi" }, 400);

    const beli = validateHarga(b.harga_beli ?? 0, "harga_beli");
    const jual = validateHarga(b.harga_jual ?? 0, "harga_jual");
    if (!beli.ok) return json({ error: beli.error }, 400);
    if (!jual.ok) return json({ error: jual.error }, 400);
    if (jual.value <= 0) return json({ error: "harga_jual harus > 0" }, 400);

    const { data, error } = await sb
    .from("produk")
    .insert({
        nama_produk: nama,
        harga_beli:  beli.value,
        harga_jual:  jual.value,
        kategori:    validateKategori(String(b.kategori ?? "")),
            quick_cash:  Boolean(b.quick_cash),
    })
    .select("id, nama_produk, harga_beli, harga_jual, kategori, quick_cash")
    .single();

    if (error) return json({ error: "Gagal menyimpan data" }, 500);
    return json(data, 201);
};

// ── PATCH /api/produk/produk?id=<uuid> ────────────────────────────────────
export const PATCH: APIRoute = async ({ request, url, cookies }) => {
    if (!await authGuard(cookies)) return json({ error: "Unauthorized" }, 401);

    const id = url.searchParams.get("id") ?? "";
    if (!isValidUUID(id)) return json({ error: "ID tidak valid" }, 400);

    // FIX #10 — Baca + validasi ukuran body aktual
    const read = await readJsonBody(request);
    if (!read.ok) return json({ error: read.error }, read.status);
    const body = read.body;

    if (typeof body !== "object" || body === null)
        return json({ error: "Body tidak valid" }, 400);

    const b = body as Record<string, unknown>;
    const patch: Record<string, unknown> = {};

    if ("nama_produk" in b) {
        const nama = sanitizeNama(String(b.nama_produk));
        if (!nama) return json({ error: "nama_produk tidak boleh kosong" }, 400);
        patch.nama_produk = nama;
    }
    if ("harga_beli" in b) {
        const v = validateHarga(b.harga_beli, "harga_beli");
        if (!v.ok) return json({ error: v.error }, 400);
        patch.harga_beli = v.value;
    }
    if ("harga_jual" in b) {
        const v = validateHarga(b.harga_jual, "harga_jual");
        if (!v.ok) return json({ error: v.error }, 400);
        if (v.value <= 0) return json({ error: "harga_jual harus > 0" }, 400);
        patch.harga_jual = v.value;
    }
    if ("kategori" in b) {
        patch.kategori = validateKategori(String(b.kategori));
    }
    if ("quick_cash" in b) {
        patch.quick_cash = Boolean(b.quick_cash);
    }

    if (Object.keys(patch).length === 0)
        return json({ error: "Tidak ada field yang diupdate" }, 400);

    const sb = createServiceClient();
    const { error } = await sb.from("produk").update(patch).eq("id", id);
    if (error) return json({ error: "Gagal mengupdate data" }, 500);
    return json({ ok: true });
};

// ── DELETE /api/produk/produk ──────────────────────────────────────────────
// ?id=<uuid>                          → hapus satu produk
// ?bulk=all                           → hapus SEMUA produk
// ?bulk=kategori&kategori=<nama>      → hapus per kategori
export const DELETE: APIRoute = async ({ url, cookies }) => {
    if (!await authGuard(cookies)) return json({ error: "Unauthorized" }, 401);

    const sb       = createServiceClient();
    const id       = url.searchParams.get("id")       ?? "";
    const bulk     = url.searchParams.get("bulk")     ?? "";
    const kategori = url.searchParams.get("kategori") ?? "";

    // ── Hapus satu produk ──────────────────────────────────────────────────
    if (id) {
        if (!isValidUUID(id)) return json({ error: "ID tidak valid" }, 400);
        const { error } = await sb.from("produk").delete().eq("id", id);
        if (error) return json({ error: "Gagal menghapus data" }, 500);
        return json({ ok: true });
    }

    // ── Hapus massal semua produk ──────────────────────────────────────────
    if (bulk === "all") {
        const { error, count } = await sb
        .from("produk")
        .delete({ count: "exact" })
        .neq("id", "00000000-0000-0000-0000-000000000000");
        if (error) return json({ error: "Gagal menghapus semua produk" }, 500);
        return json({ ok: true, deleted: count ?? 0 });
    }

    // ── Hapus massal per kategori ──────────────────────────────────────────
    if (bulk === "kategori") {
        if (!KATEGORI_OK.has(kategori))
            return json({ error: "Kategori tidak valid" }, 400);

        const { error, count } = await sb
        .from("produk")
        .delete({ count: "exact" })
        .eq("kategori", kategori);
        if (error) return json({ error: "Gagal menghapus produk kategori" }, 500);
        return json({ ok: true, deleted: count ?? 0 });
    }

    return json({ error: "Parameter tidak valid. Gunakan ?id=, ?bulk=all, atau ?bulk=kategori&kategori=..." }, 400);
};
