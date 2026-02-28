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
const MAX_ITEMS      = 100;       // maks item per transaksi
const MAX_NAMA_LEN   = 200;       // maks panjang nama produk
const MAX_QTY        = 9_999;     // maks qty per item
const MAX_HARGA      = 100_000_000; // maks harga (Rp 100 juta)
const MAX_TOTAL      = 500_000_000; // maks total (Rp 500 juta)

// Metode bayar yang valid — hanya cash dan qris statis
const VALID_METODE = new Set(["cash", "qris"]);

// Status yang valid
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
    .replace(/[\x00-\x1F\x7F]/g, "") // hapus control characters
    .slice(0, maxLen);
}

// ─── Validate UUID ────────────────────────────────────────────────────────────

function isUUID(val: unknown): boolean {
    return typeof val === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(val);
}

// ─── GET: histori transaksi hari ini ─────────────────────────────────────────

export const GET: APIRoute = async ({ cookies }) => {
    if (!await authGuard(cookies)) return json({ error: "Unauthorized" }, 401);

    const sb  = createServiceClient();
    const now = new Date();

    // Awal hari WIB (UTC+7)
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

    // Parse body
    let body: unknown;
    try {
        body = await request.json();
    } catch {
        return json({ error: "Body tidak valid" }, 400);
    }

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

    // ── Validasi total ───────────────────────────────────────────────────────
    const total = Math.round(Number(b["total"] ?? 0));
    if (!Number.isFinite(total) || total <= 0) {
        return json({ error: "total harus berupa angka positif" }, 400);
    }
    if (total > MAX_TOTAL) {
        return json({ error: `total melebihi batas maksimum (${MAX_TOTAL.toLocaleString("id-ID")})` }, 400);
    }

    // ── Validasi items ───────────────────────────────────────────────────────
    const rawItems = b["items"];
    if (!Array.isArray(rawItems) || rawItems.length === 0) {
        return json({ error: "items wajib ada dan tidak boleh kosong" }, 400);
    }
    if (rawItems.length > MAX_ITEMS) {
        return json({ error: `Terlalu banyak item. Maks ${MAX_ITEMS} per transaksi` }, 400);
    }

    type ItemRow = {
        produk_id:   string | null;
        nama_produk: string;
        harga_jual:  number;
        harga_beli:  number;
        qty:         number;
    };

    const items: ItemRow[] = [];
    for (let i = 0; i < rawItems.length; i++) {
        const r = rawItems[i];
        if (typeof r !== "object" || r === null) {
            return json({ error: `Item ${i + 1}: format tidak valid` }, 400);
        }
        const row = r as Record<string, unknown>;

        const nama = sanitizeStr(row["nama_produk"], MAX_NAMA_LEN);
        if (!nama) return json({ error: `Item ${i + 1}: nama_produk wajib diisi` }, 400);

        const hargaJual = Math.round(Number(row["harga_jual"] ?? 0));
        const hargaBeli = Math.round(Number(row["harga_beli"] ?? 0));
        const qty       = Math.round(Number(row["qty"]        ?? 1));

        if (!Number.isFinite(hargaJual) || hargaJual < 0 || hargaJual > MAX_HARGA) {
            return json({ error: `Item ${i + 1}: harga_jual tidak valid` }, 400);
        }
        if (!Number.isFinite(hargaBeli) || hargaBeli < 0 || hargaBeli > MAX_HARGA) {
            return json({ error: `Item ${i + 1}: harga_beli tidak valid` }, 400);
        }
        if (!Number.isFinite(qty) || qty < 1 || qty > MAX_QTY) {
            return json({ error: `Item ${i + 1}: qty harus antara 1–${MAX_QTY}` }, 400);
        }

        // produk_id opsional — validasi UUID jika ada
        const produkId = isUUID(row["produk_id"]) ? (row["produk_id"] as string) : null;

        items.push({ produk_id: produkId, nama_produk: nama, harga_jual: hargaJual, harga_beli: hargaBeli, qty });
    }

    // ── Verifikasi total cocok dengan items ──────────────────────────────────
    const totalHitung = items.reduce((s, i) => s + i.harga_jual * i.qty, 0);
    if (totalHitung !== total) {
        return json({ error: `Total tidak sesuai. Dihitung: ${totalHitung}, dikirim: ${total}` }, 400);
    }

    // ── Simpan ke database ───────────────────────────────────────────────────
    const sb = createServiceClient();

    const { data: trx, error: trxErr } = await sb
    .from("transaksi")
    .insert({
        total,
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
        // Rollback — hapus transaksi yang sudah tersimpan
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
