export const prerender = false;

import type { APIRoute } from "astro";
import { createServiceClient } from "../../../lib/supabase";

const BUCKET    = "produk-foto";
const MAX_SIZE  = 5 * 1024 * 1024; // 5 MB
const UUID_RE   = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Magic bytes untuk validasi file di server (bukan percaya client MIME)
const MAGIC: Record<string, number[][]> = {
    "image/jpeg": [[0xFF, 0xD8, 0xFF]],
    "image/png":  [[0x89, 0x50, 0x4E, 0x47]],
    "image/webp": [[0x52, 0x49, 0x46, 0x46]], // RIFF....WEBP
    "image/gif":  [[0x47, 0x49, 0x46, 0x38]],
};

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

function isValidUUID(id: string): boolean {
    return UUID_RE.test(id);
}

/**
 * Validasi magic bytes — cek konten file sungguhan, bukan hanya MIME dari client.
 * WebP: bytes 0-3 = "RIFF", bytes 8-11 = "WEBP"
 */
async function validateMagicBytes(blob: Blob): Promise<string | null> {
    const buf    = await blob.slice(0, 12).arrayBuffer();
    const bytes  = new Uint8Array(buf);

    for (const [mime, patterns] of Object.entries(MAGIC)) {
        for (const pattern of patterns) {
            if (pattern.every((b, i) => bytes[i] === b)) {
                // Untuk WebP perlu cek tambahan "WEBP" di offset 8
                if (mime === "image/webp") {
                    const webp = [0x57, 0x45, 0x42, 0x50];
                    if (webp.every((b, i) => bytes[8 + i] === b)) return mime;
                    continue;
                }
                return mime;
            }
        }
    }
    return null; // tidak dikenali
}

// ── POST /api/produk/foto (upload) ────────────────────────────────────────
export const POST: APIRoute = async ({ request, cookies }) => {
    if (!await authGuard(cookies)) return json({ error: "Unauthorized" }, 401);

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
    if (file.size > MAX_SIZE)
        return json({ error: "File terlalu besar (maks 5 MB)" }, 400);

    // ── Validasi MIME client (layer 1) ──
    const ALLOWED_MIME = new Set(Object.keys(MAGIC));
    if (!ALLOWED_MIME.has(file.type))
        return json({ error: "Tipe file tidak diizinkan" }, 400);

    // ── Validasi magic bytes (layer 2 — tidak bisa dipalsukan) ──
    const realMime = await validateMagicBytes(file);
    if (!realMime)
        return json({ error: "Konten file bukan gambar yang valid" }, 400);

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
    const path = `${id}.webp`;

    // Hapus lama dulu (ignore error)
    await sb.storage.from(BUCKET).remove([path]);

    const { error: upErr } = await sb.storage.from(BUCKET).upload(path, file, {
        contentType: "image/webp",
        upsert:      true,
    });

    if (upErr) return json({ error: "Gagal upload file" }, 500);

    const { data } = sb.storage.from(BUCKET).getPublicUrl(path);
    const url      = `${data.publicUrl}?t=${Date.now()}`;

    return json({ ok: true, url });
};

// ── DELETE /api/produk/foto?id=<uuid> ─────────────────────────────────────
export const DELETE: APIRoute = async ({ url, cookies }) => {
    if (!await authGuard(cookies)) return json({ error: "Unauthorized" }, 401);

    const id = url.searchParams.get("id") ?? "";
    if (!isValidUUID(id))
        return json({ error: "ID tidak valid" }, 400);

    // ── Pastikan produk ada sebelum hapus ──
    const sb = createServiceClient();
    const { data: produk } = await sb
    .from("produk")
    .select("id")
    .eq("id", id)
    .single();

    if (!produk) return json({ error: "Produk tidak ditemukan" }, 404);

    const { error } = await sb.storage.from(BUCKET).remove([`${id}.webp`]);
    if (error) return json({ error: "Gagal menghapus file" }, 500);

    return json({ ok: true });
};

// ── Method lain ditolak ───────────────────────────────────────────────────
export const GET:   APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const PATCH: APIRoute = () => new Response("Method Not Allowed", { status: 405 });
export const PUT:   APIRoute = () => new Response("Method Not Allowed", { status: 405 });
