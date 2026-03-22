export const prerender = false;

import type { APIRoute } from "astro";
import { createClient } from "@supabase/supabase-js";
import { createServiceClient, KATEGORI_LIST } from "../../../../lib/supabase";

// ── Konstanta ──────────────────────────────────────────────────────────────
const MAX_NAMA         = 100;
const MAX_HARGA        = 999_999_999;
const MAX_BODY         = 512 * 1024; // 512 KB
const UUID_RE          = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const KATEGORI_OK      = new Set<string>(KATEGORI_LIST);
const ADMIN_EMAIL      = import.meta.env.ADMIN_EMAIL          as string;
const SUPABASE_URL     = import.meta.env.PUBLIC_SUPABASE_URL  as string;
const ANON_KEY         = import.meta.env.PUBLIC_SUPABASE_ANON_KEY as string;
const TURNSTILE_SECRET = import.meta.env.TURNSTILE_SECRET_KEY as string;

// ── In-memory rate limiter ─────────────────────────────────────────────────
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX       = 60;

const rateLimitMap = new Map<string, { count: number; windowStart: number }>();

function checkRateLimit(ip: string): boolean {
    const now    = Date.now();
    const record = rateLimitMap.get(ip);
    if (!record || now - record.windowStart > RATE_LIMIT_WINDOW_MS) {
        rateLimitMap.set(ip, { count: 1, windowStart: now });
        return true;
    }
    if (record.count >= RATE_LIMIT_MAX) return false;
    record.count++;
    return true;
}

setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of rateLimitMap.entries()) {
        if (now - record.windowStart > RATE_LIMIT_WINDOW_MS * 2) {
            rateLimitMap.delete(ip);
        }
    }
}, 5 * 60_000);

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

function getClientIp(request: Request): string {
    return (
        request.headers.get("cf-connecting-ip") ??
        request.headers.get("x-forwarded-for")?.split(",")[0].trim() ??
        "unknown"
    );
}

async function verifyToken(cookies: any): Promise<{ id: string; email: string } | null> {
    const token = cookies.get("sb-access-token")?.value;
    if (!token) return null;

    const anonClient = createClient(SUPABASE_URL, ANON_KEY, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    });

    const { data, error } = await anonClient.auth.getUser(token);
    if (error || !data?.user) return null;

    return {
        id:    data.user.id,
        email: data.user.email ?? "",
    };
}

async function authGuard(cookies: any) {
    return verifyToken(cookies);
}

async function adminGuard(cookies: any): Promise<boolean> {
    const user = await verifyToken(cookies);
    if (!user) return false;
    return user.email === ADMIN_EMAIL;
}

async function verifyTurnstile(token: string | null, ip: string): Promise<boolean> {
    if (!token) return false;
    try {
        const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                secret:   TURNSTILE_SECRET,
                response: token,
                remoteip: ip,
            }),
        });
        const data = await res.json() as { success: boolean };
        return data.success === true;
    } catch (err) {
        console.error("[Turnstile] Gagal verifikasi:", err);
        return false;
    }
}

async function readJsonBody(request: Request): Promise<
{ ok: true; body: unknown } |
{ ok: false; error: string; status: number }
> {
    const ct = request.headers.get("content-type") ?? "";
    if (!ct.includes("application/json")) {
        return { ok: false, error: "Content-Type harus application/json", status: 415 };
    }

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
    return s
    .trim()
    .replace(/[\x00-\x1F\x7F]/g, "")
    .replace(/\s+/g, " ")
    .slice(0, MAX_NAMA);
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

function parseBoolean(val: unknown): boolean {
    if (typeof val === "boolean") return val;
    if (val === "true"  || val === 1) return true;
    if (val === "false" || val === 0) return false;
    return false;
}

// ── GET /api/produk/produk ─────────────────────────────────────────────────
export const GET: APIRoute = async ({ url, request, cookies }) => {
    const ip = getClientIp(request);
    if (!checkRateLimit(ip)) return json({ error: "Terlalu banyak request" }, 429);

    const user = await authGuard(cookies);
    if (!user) return json({ error: "Unauthorized" }, 401);

    const sb        = createServiceClient();
    const search    = url.searchParams.get("q")?.slice(0, 100)  ?? "";
    const katFilter = url.searchParams.get("kategori")          ?? "";
    const filterLow = url.searchParams.get("filter") === "low_margin";

    const page  = Math.max(1, parseInt(url.searchParams.get("page")  ?? "1",   10));
    const limit = Math.min(200, Math.max(1, parseInt(url.searchParams.get("limit") ?? "100", 10)));
    const from  = (page - 1) * limit;
    const to    = from + limit - 1;

    const safeKat = katFilter && KATEGORI_OK.has(katFilter) ? katFilter : "";

    let query = sb
    .from("produk")
    .select("id, nama_produk, harga_beli, harga_jual, kategori, quick_cash, created_at, updated_at", { count: "exact" })
    .order("nama_produk")
    .range(from, to);

    if (search)  query = query.ilike("nama_produk", `%${search.replace(/[%_]/g, "\\$&")}%`);
    if (safeKat) query = query.eq("kategori", safeKat);

    const { data, error, count } = await query;
    if (error) {
        console.error("[GET /api/produk] Supabase error:", error);
        return json({ error: "Gagal mengambil data" }, 500);
    }

    let produk = data ?? [];
    if (filterLow)
        produk = produk.filter(
            (p: any) => p.harga_beli > 0 && (p.harga_jual - p.harga_beli) / p.harga_beli < 0.1
        );

    return json({ data: produk, total: count ?? 0, page, limit });
};

// ── POST /api/produk/produk ────────────────────────────────────────────────
export const POST: APIRoute = async ({ request, cookies }) => {
    const ip = getClientIp(request);
    if (!checkRateLimit(ip)) return json({ error: "Terlalu banyak request" }, 429);

    const user = await authGuard(cookies);
    if (!user) return json({ error: "Unauthorized" }, 401);

    const read = await readJsonBody(request);
    if (!read.ok) return json({ error: read.error }, read.status);
    const body = read.body;

    const sb = createServiceClient();

    // ── Bulk insert ──
    if (Array.isArray(body)) {
        if (body.length === 0)  return json({ error: "Array kosong" }, 400);
        if (body.length > 500)  return json({ error: "Maks 500 produk per request" }, 400);

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
                      quick_cash:  parseBoolean(r.quick_cash),
            });
        }

        const { error } = await sb.from("produk").insert(rows);
        if (error) {
            console.error("[POST /api/produk] Bulk insert error:", error);
            return json({ error: "Gagal menyimpan data" }, 500);
        }
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
            quick_cash:  parseBoolean(b.quick_cash),
    })
    .select("id, nama_produk, harga_beli, harga_jual, kategori, quick_cash")
    .single();

    if (error) {
        console.error("[POST /api/produk] Single insert error:", error);
        return json({ error: "Gagal menyimpan data" }, 500);
    }
    return json(data, 201);
};

// ── PATCH /api/produk/produk?id=<uuid> ────────────────────────────────────
export const PATCH: APIRoute = async ({ request, url, cookies }) => {
    const ip = getClientIp(request);
    if (!checkRateLimit(ip)) return json({ error: "Terlalu banyak request" }, 429);

    const user = await authGuard(cookies);
    if (!user) return json({ error: "Unauthorized" }, 401);

    const id = url.searchParams.get("id") ?? "";
    if (!isValidUUID(id)) return json({ error: "ID tidak valid" }, 400);

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
        patch.quick_cash = parseBoolean(b.quick_cash);
    }

    if (Object.keys(patch).length === 0)
        return json({ error: "Tidak ada field yang diupdate" }, 400);

    const sb = createServiceClient();
    const { error } = await sb.from("produk").update(patch).eq("id", id);
    if (error) {
        console.error("[PATCH /api/produk] Update error:", error);
        return json({ error: "Gagal mengupdate data" }, 500);
    }
    return json({ ok: true });
};

// ── DELETE /api/produk/produk ──────────────────────────────────────────────
// ?id=<uuid>                              → hapus satu (auth biasa)
// ?bulk=all                               → hapus SEMUA (admin only + Turnstile via body)
// ?bulk=kategori&kategori=<nama>          → hapus per kategori (admin only + Turnstile via body)
//
// FIX: turnstile_token dibaca dari JSON body, BUKAN query param,
// agar tidak masuk server log / browser history.
export const DELETE: APIRoute = async ({ url, request, cookies }) => {
    const ip = getClientIp(request);
    if (!checkRateLimit(ip)) return json({ error: "Terlalu banyak request" }, 429);

    const sb       = createServiceClient();
    const id       = url.searchParams.get("id")       ?? "";
    const bulk     = url.searchParams.get("bulk")     ?? "";
    const kategori = url.searchParams.get("kategori") ?? "";

    // ── Hapus satu produk — cukup auth biasa ──────────────────────────────
    if (id) {
        const user = await authGuard(cookies);
        if (!user) return json({ error: "Unauthorized" }, 401);

        if (!isValidUUID(id)) return json({ error: "ID tidak valid" }, 400);

        const { error } = await sb.from("produk").delete().eq("id", id);
        if (error) {
            console.error("[DELETE /api/produk] Delete single error:", error);
            return json({ error: "Gagal menghapus data" }, 500);
        }
        return json({ ok: true });
    }

    // ── Operasi bulk — wajib admin + Turnstile dari body ─────────────────
    if (bulk === "all" || bulk === "kategori") {
        const isAdmin = await adminGuard(cookies);
        if (!isAdmin) return json({ error: "Forbidden: hanya admin" }, 403);

        // Baca turnstile_token dari JSON body
        const read = await readJsonBody(request);
        if (!read.ok) return json({ error: read.error }, read.status);

        const body = read.body as Record<string, unknown>;
        const cfToken = typeof body?.turnstile_token === "string" ? body.turnstile_token : null;

        const turnstileOk = await verifyTurnstile(cfToken, ip);
        if (!turnstileOk) return json({ error: "Verifikasi Turnstile gagal" }, 403);

        if (bulk === "all") {
            const { error, count } = await sb
            .from("produk")
            .delete({ count: "exact" })
            .neq("id", "00000000-0000-0000-0000-000000000000");
            if (error) {
                console.error("[DELETE /api/produk] Delete all error:", error);
                return json({ error: "Gagal menghapus semua produk" }, 500);
            }
            console.info(`[DELETE /api/produk] bulk=all oleh admin, deleted=${count}`);
            return json({ ok: true, deleted: count ?? 0 });
        }

        if (bulk === "kategori") {
            if (!KATEGORI_OK.has(kategori))
                return json({ error: "Kategori tidak valid" }, 400);

            const { error, count } = await sb
            .from("produk")
            .delete({ count: "exact" })
            .eq("kategori", kategori);
            if (error) {
                console.error("[DELETE /api/produk] Delete by kategori error:", error);
                return json({ error: "Gagal menghapus produk kategori" }, 500);
            }
            console.info(`[DELETE /api/produk] bulk=kategori(${kategori}) oleh admin, deleted=${count}`);
            return json({ ok: true, deleted: count ?? 0 });
        }
    }

    return json({ error: "Parameter tidak valid. Gunakan ?id=, ?bulk=all, atau ?bulk=kategori&kategori=..." }, 400);
};
