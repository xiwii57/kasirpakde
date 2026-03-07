// src/pages/api/produk/foto.ts
export const prerender = false;

import type { APIRoute } from "astro";
import { createClient } from "@supabase/supabase-js";
import { createServiceClient } from "../../../lib/supabase";

// ── Konstanta ──────────────────────────────────────────────────────────────
const BUCKET       = "produk-foto";
const MAX_SIZE     = 5 * 1024 * 1024; // 5 MB
const UUID_RE      = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SUPABASE_URL = import.meta.env.PUBLIC_SUPABASE_URL       as string;
const ANON_KEY     = import.meta.env.PUBLIC_SUPABASE_ANON_KEY  as string;

// Magic bytes untuk validasi konten file di server (tidak bisa dipalsukan client)
const MAGIC: Record<string, { bytes: number[]; offset?: number }[]> = {
    "image/jpeg": [{ bytes: [0xFF, 0xD8, 0xFF] }],
    "image/png":  [{ bytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] }],
    "image/webp": [{ bytes: [0x52, 0x49, 0x46, 0x46] }, { bytes: [0x57, 0x45, 0x42, 0x50], offset: 8 }],
    "image/gif":  [{ bytes: [0x47, 0x49, 0x46, 0x38] }],
};

// ── In-memory rate limiter (lebih ketat untuk upload) ──────────────────────
// Upload dibatasi lebih ketat karena menyentuh storage
const UPLOAD_RATE_WINDOW_MS = 60_000; // 1 menit
const UPLOAD_RATE_MAX       = 20;     // maks 20 upload / menit / IP

const uploadRateMap = new Map<string, { count: number; windowStart: number }>();

function checkUploadRateLimit(ip: string): boolean {
    const now    = Date.now();
    const record = uploadRateMap.get(ip);

    if (!record || now - record.windowStart > UPLOAD_RATE_WINDOW_MS) {
        uploadRateMap.set(ip, { count: 1, windowStart: now });
        return true;
    }
    if (record.count >= UPLOAD_RATE_MAX) return false;
    record.count++;
    return true;
}

setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of uploadRateMap.entries()) {
        if (now - record.windowStart > UPLOAD_RATE_WINDOW_MS * 2) {
            uploadRateMap.delete(ip);
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

/**
 * FIX: Verifikasi token pakai anon client, bukan service role.
 * Kembalikan { id, email } jika valid, null jika tidak.
 */
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

function isValidUUID(id: string): boolean {
    return UUID_RE.test(id);
}

/**
 * FIX: Validasi magic bytes yang lebih robust.
 * WebP membutuhkan dua signature: RIFF di offset 0 DAN WEBP di offset 8.
 * Kembalikan mime type yang terdeteksi, atau null jika tidak cocok.
 */
async function validateMagicBytes(blob: Blob): Promise<string | null> {
    const buf   = await blob.slice(0, 16).arrayBuffer();
    const bytes = new Uint8Array(buf);

    for (const [mime, signatures] of Object.entries(MAGIC)) {
        // WebP perlu dua signature sekaligus
        if (mime === "image/webp") {
            const [riff, webp] = signatures;
            const riffOk = riff.bytes.every((b, i) => bytes[i] === b);
            const webpOk = webp.bytes.every((b, i) => bytes[(webp.offset ?? 0) + i] === b);
            if (riffOk && webpOk) return mime;
            continue;
        }

        // Format lain — cukup satu signature
        const sig = signatures[0];
        if (sig.bytes.every((b, i) => bytes[(sig.offset ?? 0) + i] === b)) {
            return mime;
        }
    }

    return null;
}

/**
 * FIX: Validasi bahwa URL yang dikembalikan Supabase berasal dari
 * domain yang sama dengan SUPABASE_URL, bukan redirect ke domain lain.
 */
function isSafePublicUrl(url: string): boolean {
    try {
        const parsed     = new URL(url);
        const supaOrigin = new URL(SUPABASE_URL).hostname;
        return parsed.hostname === supaOrigin;
    } catch {
        return false;
    }
}

// ── POST /api/produk/foto (upload) ─────────────────────────────────────────
export const POST: APIRoute = async ({ request, cookies }) => {
    // Rate limit upload lebih ketat
    const ip = getClientIp(request);
    if (!checkUploadRateLimit(ip)) return json({ error: "Terlalu banyak request upload" }, 429);

    // FIX: Verifikasi token pakai anon client
    const user = await verifyToken(cookies);
    if (!user) return json({ error: "Unauthorized" }, 401);

    // FIX: Content-Length hanya sebagai guard kasar — tidak dijadikan satu-satunya
    // validasi ukuran. Validasi aktual tetap dari file.size di bawah.
    const cl = parseInt(request.headers.get("content-length") ?? "0", 10);
    if (!Number.isNaN(cl) && cl > MAX_SIZE + 64 * 1024) {
        return json({ error: `Payload terlalu besar (maks ${MAX_SIZE / (1024 * 1024)} MB)` }, 413);
    }

    let form: FormData | null = null;
    try { form = await request.formData(); }
    catch { return json({ error: "FormData tidak valid" }, 400); }

    const id   = form.get("id");
    const file = form.get("file");

    // ── Validasi ID ──
    if (!id || typeof id !== "string")
        return json({ error: "Missing id" }, 400);
    if (!isValidUUID(id))
        return json({ error: "ID tidak valid" }, 400);

    // ── Validasi file dasar ──
    if (!file || !(file instanceof Blob))
        return json({ error: "Missing file" }, 400);
    if (file.size === 0)
        return json({ error: "File kosong" }, 400);

    // FIX: Validasi ukuran dari objek Blob — tidak bisa dipalsukan lewat header
    if (file.size > MAX_SIZE)
        return json({ error: "File terlalu besar (maks 5 MB)" }, 413);

    // ── Validasi MIME type dari client (layer 1 — bisa dipalsukan, early reject) ──
    const ALLOWED_MIME = new Set(Object.keys(MAGIC));
    if (!ALLOWED_MIME.has(file.type))
        return json({ error: "Tipe file tidak diizinkan" }, 400);

    // ── Validasi magic bytes (layer 2 — tidak bisa dipalsukan) ──
    const realMime = await validateMagicBytes(file);
    if (!realMime)
        return json({ error: "Konten file bukan gambar yang valid" }, 400);

    // FIX: Tolak jika MIME client tidak cocok dengan konten aktual
    if (realMime !== file.type)
        return json({ error: "Tipe file tidak sesuai dengan konten" }, 400);

    // ── Pastikan produk dengan ID ini benar-benar ada ──
    const sb = createServiceClient();
    const { data: produk, error: produkErr } = await sb
    .from("produk")
    .select("id")
    .eq("id", id)
    .single();

    if (produkErr || !produk)
        return json({ error: "Produk tidak ditemukan" }, 404);

    // ── Upload ke storage ──
    // Nama file selalu pakai UUID produk — tidak ada user input dalam path
    const path = `${id}.webp`;

    await sb.storage.from(BUCKET).remove([path]);

    // FIX: Pakai realMime dari magic bytes, bukan hardcoded atau dari client
    const { error: upErr } = await sb.storage.from(BUCKET).upload(path, file, {
        contentType: realMime,
        upsert:      true,
    });

    if (upErr) {
        console.error("[POST /api/produk/foto] Upload error:", upErr);
        return json({ error: "Gagal upload file" }, 500);
    }

    const { data } = sb.storage.from(BUCKET).getPublicUrl(path);

    // FIX: Validasi URL hasil Supabase sebelum dikembalikan ke client
    if (!isSafePublicUrl(data.publicUrl)) {
        console.error("[POST /api/produk/foto] URL tidak aman:", data.publicUrl);
        return json({ error: "Gagal mendapatkan URL file" }, 500);
    }

    const url = `${data.publicUrl}?t=${Date.now()}`;
    return json({ ok: true, url });
};

// ── DELETE /api/produk/foto?id=<uuid> ──────────────────────────────────────
export const DELETE: APIRoute = async ({ url, request, cookies }) => {
    const ip = getClientIp(request);
    if (!checkUploadRateLimit(ip)) return json({ error: "Terlalu banyak request" }, 429);

    // FIX: Verifikasi token pakai anon client
    const user = await verifyToken(cookies);
    if (!user) return json({ error: "Unauthorized" }, 401);

    const id = url.searchParams.get("id") ?? "";
    if (!isValidUUID(id))
        return json({ error: "ID tidak valid" }, 400);

    const sb = createServiceClient();
    const { data: produk, error: produkErr } = await sb
    .from("produk")
    .select("id")
    .eq("id", id)
    .single();

    if (produkErr || !produk)
        return json({ error: "Produk tidak ditemukan" }, 404);

    const { error } = await sb.storage.from(BUCKET).remove([`${id}.webp`]);
    if (error) {
        console.error("[DELETE /api/produk/foto] Remove error:", error);
        return json({ error: "Gagal menghapus file" }, 500);
    }

    return json({ ok: true });
};

// ── Method lain ditolak ────────────────────────────────────────────────────
export const GET:   APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const PATCH: APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const PUT:   APIRoute = () => new Response("Method Not Allowed", { status: 405 });
