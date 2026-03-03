// src/pages/api/kasir/transaksi.ts
//
// GET  /api/kasir/transaksi  — histori transaksi hari ini (+ items)
// POST /api/kasir/transaksi  — simpan transaksi baru
export const prerender = false;

import type { APIRoute } from "astro";
import { createServiceClient } from "../../../lib/supabase";

// ─── Konstanta ────────────────────────────────────────────────────────────────

const MAX_TOKEN_LEN  = 1024;
const AUTH_TIMEOUT   = 5_000;
const MAX_ITEMS      = 100;
const MAX_NAMA_LEN   = 200;
const MAX_QTY        = 9_999;
const MAX_HARGA      = 100_000_000;
const MAX_TOTAL      = 500_000_000;

// Batas body aktual POST transaksi: 100 item × ~200 byte + overhead = ~64 KB
const MAX_BODY_BYTES = 64 * 1024;

const VALID_METODE = new Set(["cash", "qris"]);
const VALID_STATUS = new Set(["paid"]);

// ─── Auth Guard ───────────────────────────────────────────────────────────────

async function authGuard(cookies: any): Promise<boolean> {
    const token = cookies.get("sb-access-token")?.value;
    if (!token || typeof token !== "string") return false;
    if (token.length > MAX_TOKEN_LEN) return false;
    if (!/^[\w-]+\.[\w-]+\.[\w-]+$/.test(token)) return false;

    try {
        const result = await Promise.race([
            createServiceClient().auth.getUser(token),
                                          new Promise<never>((_, reject) =>
                                          setTimeout(() => reject(new Error("timeout")), AUTH_TIMEOUT)
                                          ),
        ]);
        return !result.error && !!result.data?.user?.id;
    } catch {
        return false;
    }
}

// ─── Response Helper ──────────────────────────────────────────────────────────

function json(data: unknown, status = 200): Response {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type":  "application/json; charset=utf-8",
            "Cache-Control": "no-store",
        },
    });
}

// ─── Sanitize string ──────────────────────────────────────────────────────────

function sanitizeStr(val: unknown, maxLen: number): string {
    return String(val ?? "")
    .trim()
    .replace(/[\x00-\x1F\x7F]/g, "")
    .slice(0, maxLen);
}

// ─── Validate UUID ────────────────────────────────────────────────────────────

function isUUID(val: unknown): boolean {
    return typeof val === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(val);
}

// ─── Read + validasi body JSON aktual ────────────────────────────────────────

async function readJsonBody(request: Request, maxBytes: number): Promise<
{ ok: true; body: unknown } | { ok: false; error: string; status: number }
> {
    let buf: ArrayBuffer;
    try {
        buf = await request.arrayBuffer();
    } catch {
        return { ok: false, error: "Gagal membaca body", status: 400 };
    }
    if (buf.byteLength > maxBytes) {
        return { ok: false, error: `Payload terlalu besar (maks ${maxBytes / 1024} KB)`, status: 413 };
    }
    try {
        return { ok: true, body: JSON.parse(new TextDecoder().decode(buf)) };
    } catch {
        return { ok: false, error: "Body bukan JSON valid", status: 400 };
    }
}

// ─── GET: histori transaksi hari ini ─────────────────────────────────────────

export const GET: APIRoute = async ({ cookies }) => {
    if (!await authGuard(cookies)) return json({ error: "Unauthorized" }, 401);

    const sb  = createServiceClient();
    const now = new Date();

    const todayWIB = new Date(now.toLocaleString("en-US", { timeZone: "Asia/Jakarta" }));
    todayWIB.setHours(0, 0, 0, 0);
    const startUTC = new Date(todayWIB.getTime() - 7 * 60 * 60 * 1000).toISOString();

    const { data, error } = await sb
    .from("transaksi")
    .select(`
    id,
    created_at,
    total,
    metode_bayar,
    status,
    transaksi_item ( id, nama_produk, harga_jual, harga_beli, qty )
    `)
    .gte("created_at", startUTC)
    .eq("status", "paid")
    .order("created_at", { ascending: false })
    .limit(200);

    if (error) {
        console.error("[transaksi GET]", error.message);
        return json({ error: "Gagal mengambil histori" }, 500);
    }

    return json(data ?? []);
};

// ─── POST: simpan transaksi baru ──────────────────────────────────────────────

export const POST: APIRoute = async ({ request, cookies }) => {
    if (!await authGuard(cookies)) return json({ error: "Unauthorized" }, 401);

    // Baca + validasi ukuran body aktual sebelum parse JSON
    const read = await readJsonBody(request, MAX_BODY_BYTES);
    if (!read.ok) return json({ error: read.error }, read.status);
    const body = read.body;

    if (typeof body !== "object" || body === null || Array.isArray(body)) {
        return json({ error: "Body harus berupa object" }, 400);
    }

    const b = body as Record<string, unknown>;

    // ── Validasi metode_bayar ────────────────────────────────────────────────
    const metodeBayar = sanitizeStr(b["metode_bayar"], 20).toLowerCase();
    if (!VALID_METODE.has(metodeBayar)) {
        return json({ error: `metode_bayar tidak valid. Gunakan: ${[...VALID_METODE].join(", ")}` }, 400);
    }

    // ── Validasi status ──────────────────────────────────────────────────────
    const status = sanitizeStr(b["status"], 20).toLowerCase();
    if (!VALID_STATUS.has(status)) {
        return json({ error: `status tidak valid. Gunakan: ${[...VALID_STATUS].join(", ")}` }, 400);
    }

    // ── Validasi total (dari client — akan diverifikasi ulang vs DB di bawah) ─
    const totalClient = Math.round(Number(b["total"] ?? 0));
    if (!Number.isFinite(totalClient) || totalClient <= 0) {
        return json({ error: "total harus berupa angka positif" }, 400);
    }
    if (totalClient > MAX_TOTAL) {
        return json({ error: `total melebihi batas maksimum (${MAX_TOTAL.toLocaleString("id-ID")})` }, 400);
    }

    // ── Validasi struktur items dari client ──────────────────────────────────
    const rawItems = b["items"];
    if (!Array.isArray(rawItems) || rawItems.length === 0) {
        return json({ error: "items wajib ada dan tidak boleh kosong" }, 400);
    }
    if (rawItems.length > MAX_ITEMS) {
        return json({ error: `Terlalu banyak item. Maks ${MAX_ITEMS} per transaksi` }, 400);
    }

    // ── Tipe data intermediate sebelum harga di-override dari DB ─────────────
    type ItemInput = {
        produk_id:   string | null;
        nama_produk: string;
        qty:         number;
        // harga_jual & harga_beli dari client — hanya sebagai fallback
        // untuk produk tanpa produk_id (produk custom / non-katalog)
        harga_jual_client: number;
        harga_beli_client: number;
    };

    const itemsInput: ItemInput[] = [];

    for (let i = 0; i < rawItems.length; i++) {
        const r = rawItems[i];
        if (typeof r !== "object" || r === null) {
            return json({ error: `Item ${i + 1}: format tidak valid` }, 400);
        }
        const row = r as Record<string, unknown>;

        const nama = sanitizeStr(row["nama_produk"], MAX_NAMA_LEN);
        if (!nama) return json({ error: `Item ${i + 1}: nama_produk wajib diisi` }, 400);

        const qty = Math.round(Number(row["qty"] ?? 1));
        if (!Number.isFinite(qty) || qty < 1 || qty > MAX_QTY) {
            return json({ error: `Item ${i + 1}: qty harus antara 1–${MAX_QTY}` }, 400);
        }

        // Harga dari client hanya dipakai untuk produk tanpa produk_id
        const hargaJualClient = Math.round(Number(row["harga_jual"] ?? 0));
        const hargaBeliClient = Math.round(Number(row["harga_beli"] ?? 0));

        if (!Number.isFinite(hargaJualClient) || hargaJualClient < 0 || hargaJualClient > MAX_HARGA) {
            return json({ error: `Item ${i + 1}: harga_jual tidak valid` }, 400);
        }
        if (!Number.isFinite(hargaBeliClient) || hargaBeliClient < 0 || hargaBeliClient > MAX_HARGA) {
            return json({ error: `Item ${i + 1}: harga_beli tidak valid` }, 400);
        }

        const produkId = isUUID(row["produk_id"]) ? (row["produk_id"] as string) : null;

        itemsInput.push({
            produk_id:         produkId,
            nama_produk:       nama,
            qty,
            harga_jual_client: hargaJualClient,
            harga_beli_client: hargaBeliClient,
        });
    }

    // ── FIX: Override harga dari database untuk produk yang punya produk_id ──
    //
    // SEBELUMNYA: harga_jual & harga_beli diambil langsung dari client body.
    // Ini memungkinkan price manipulation — attacker bisa kirim harga_jual: 1
    // untuk semua produk dan transaksi tetap diterima, merusak laporan laba.
    //
    // SEKARANG: untuk setiap item yang memiliki produk_id valid, harga
    // di-fetch dari database dan digunakan untuk menggantikan nilai dari client.
    // Produk tanpa produk_id (produk custom/non-katalog) tetap pakai harga client.

    const sb = createServiceClient();

    const produkIds = [...new Set(
        itemsInput.filter(i => i.produk_id !== null).map(i => i.produk_id!)
    )];

    // Map produk_id → { harga_jual, harga_beli } dari DB
    const dbHargaMap = new Map<string, { harga_jual: number; harga_beli: number }>();

    if (produkIds.length > 0) {
        const { data: produkData, error: produkErr } = await sb
        .from("produk")
        .select("id, harga_jual, harga_beli")
        .in("id", produkIds);

        if (produkErr) {
            console.error("[transaksi POST] fetch harga produk:", produkErr.message);
            return json({ error: "Gagal memverifikasi harga produk" }, 500);
        }

        for (const p of produkData ?? []) {
            dbHargaMap.set(p.id, { harga_jual: p.harga_jual, harga_beli: p.harga_beli });
        }

        // Pastikan semua produk_id yang dikirim client benar-benar ada di DB
        for (const id of produkIds) {
            if (!dbHargaMap.has(id)) {
                return json({ error: `Produk dengan ID ${id} tidak ditemukan` }, 400);
            }
        }
    }

    // Bangun item final dengan harga dari DB (override) atau harga client (fallback)
    type ItemRow = {
        produk_id:   string | null;
        nama_produk: string;
        harga_jual:  number;
        harga_beli:  number;
        qty:         number;
    };

    const items: ItemRow[] = itemsInput.map(item => {
        const dbHarga = item.produk_id ? dbHargaMap.get(item.produk_id) : undefined;
        return {
            produk_id:   item.produk_id,
            nama_produk: item.nama_produk,
            qty:         item.qty,
            // Gunakan harga dari DB jika ada, fallback ke harga client untuk produk custom
            harga_jual:  dbHarga ? dbHarga.harga_jual : item.harga_jual_client,
            harga_beli:  dbHarga ? dbHarga.harga_beli : item.harga_beli_client,
        };
    });

    // ── Verifikasi total client cocok dengan harga dari DB ───────────────────
    // Ini mendeteksi jika client mencoba manipulasi total secara langsung
    const totalDariDB = items.reduce((s, i) => s + i.harga_jual * i.qty, 0);
    if (totalDariDB !== totalClient) {
        console.warn(`[transaksi POST] Total tidak sesuai DB. Client: ${totalClient}, DB: ${totalDariDB}`);
        return json({
            error: `Total tidak sesuai dengan harga produk saat ini. Mohon refresh halaman dan coba lagi.`,
        }, 400);
    }

    // ── Simpan ke database ───────────────────────────────────────────────────
    const { data: trx, error: trxErr } = await sb
    .from("transaksi")
    .insert({
        total:        totalDariDB, // selalu pakai total yang dihitung dari DB
        metode_bayar: metodeBayar,
        status,
        created_at:   new Date().toISOString(),
    })
    .select("id")
    .single();

    if (trxErr || !trx) {
        console.error("[transaksi POST] insert transaksi:", trxErr?.message);
        return json({ error: "Gagal menyimpan transaksi" }, 500);
    }

    const { error: itemErr } = await sb
    .from("transaksi_item")
    .insert(items.map(it => ({ transaksi_id: trx.id, ...it })));

    if (itemErr) {
        console.error("[transaksi POST] insert items:", itemErr.message);
        await sb.from("transaksi").delete().eq("id", trx.id);
        return json({ error: "Gagal menyimpan item transaksi" }, 500);
    }

    return json({ ok: true, id: trx.id }, 201);
};

// ─── Method lain → 405 ───────────────────────────────────────────────────────

const NOT_ALLOWED = Object.freeze(
    new Response(JSON.stringify({ error: "Method Not Allowed" }), {
        status:  405,
        headers: {
            "Content-Type":  "application/json",
            "Allow":         "GET, POST",
            "Cache-Control": "no-store",
        },
    })
);

export const PUT:    APIRoute = () => NOT_ALLOWED.clone();
export const PATCH:  APIRoute = () => NOT_ALLOWED.clone();
export const DELETE: APIRoute = () => NOT_ALLOWED.clone();
