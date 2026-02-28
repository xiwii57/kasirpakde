// src/pages/api/produk/template-csv.ts
export const prerender = false;

import type { APIRoute } from "astro";
import { createServiceClient } from "../../../lib/supabase";

// ─── Konstanta ────────────────────────────────────────────────────────────────

// Panjang maksimum JWT yang wajar — RS256/ES256 umumnya < 1024 karakter.
// 2048 terlalu longgar dan membuka pintu DoS kecil ke Supabase.
const MAX_TOKEN_LENGTH = 1024;

// Batas waktu validasi token — cegah Supabase hanging terlalu lama
const AUTH_TIMEOUT_MS = 5_000;

// ─── Auth ─────────────────────────────────────────────────────────────────────

async function authGuard(cookies: any): Promise<boolean> {
    const token = cookies.get("sb-access-token")?.value;

    // Tolak token kosong / bukan string / terlalu panjang
    if (!token || typeof token !== "string" || token.length > MAX_TOKEN_LENGTH) return false;

    // Validasi format JWT minimal — harus tiga segmen base64url dipisah titik
    // Mencegah request ke Supabase dengan input yang jelas tidak valid
    const JWT_PATTERN = /^[\w-]+\.[\w-]+\.[\w-]+$/;
    if (!JWT_PATTERN.test(token)) return false;

    try {
        // Race antara validasi Supabase dan timeout — hindari hanging
        const result = await Promise.race([
            createServiceClient().auth.getUser(token),
                                          new Promise<never>((_, reject) =>
                                          setTimeout(() => reject(new Error("auth_timeout")), AUTH_TIMEOUT_MS)
                                          ),
        ]);

        return !result.error && !!result.data?.user?.id;
    } catch {
        // Timeout, network error, atau Supabase down → tolak, jangan crash
        return false;
    }
}

// ─── Konten template ──────────────────────────────────────────────────────────

// CRLF (\r\n) — standar RFC 4180, kompatibel Excel di Windows.
// Di-encode sekali saat module load agar tidak diulang per request (zero-copy).
const TEMPLATE_ROWS = [
    "nama_produk,harga_beli,harga_jual,kategori,quick_cash",
"Aqua 600ml,2500,4000,Minuman,true",
"Indomie Goreng,2800,4000,Makanan,true",
"Chitato BBQ 68g,6500,9000,Makanan,false",
"Gudang Garam Surya 16,22000,27000,Rokok,true",
];
const TEMPLATE_BYTES: Uint8Array = new TextEncoder().encode(
    TEMPLATE_ROWS.join("\r\n") + "\r\n",
);
const CONTENT_LENGTH = String(TEMPLATE_BYTES.byteLength);

// ETag statis berbasis hash konten — memungkinkan conditional GET yang benar
// tanpa membocorkan timestamp server (Last-Modified bisa jadi sidechannel).
// Dihitung sekali saat startup, bukan per request.
const ETAG = await (async () => {
    const hash  = await crypto.subtle.digest("SHA-256", TEMPLATE_BYTES);
    const hex   = Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
    return `"${hex.slice(0, 16)}"`;   // 16 karakter hex cukup untuk ETag
})();

// ─── Security headers helper ──────────────────────────────────────────────────

// Dipisah ke fungsi agar tidak ada risiko header terlewat atau typo
// ketika ada beberapa code-path response (GET, HEAD, 304, 401, dst).
function secureDownloadHeaders(withBody = true): HeadersInit {
    return {
        // ── Konten & unduhan ────────────────────────────────────────────────
        "Content-Type":        "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="template_import_produk.csv"',
        ...(withBody ? { "Content-Length": CONTENT_LENGTH } : {}),

        // ── Validasi konten ─────────────────────────────────────────────────
        "ETag":                ETAG,

        // ── Cache ───────────────────────────────────────────────────────────
        // no-store: jangan simpan di cache browser, proxy, atau CDN.
        // File ini sensitif (template bisnis) dan mengandung session cookie
        // sebagai gate — tidak boleh di-cache oleh siapapun.
        "Cache-Control": "no-store",
        "Pragma":        "no-cache",   // HTTP/1.0 compat untuk proxy lama

        // ── Security ────────────────────────────────────────────────────────
        // nosniff: cegah browser mengira file CSV sebagai HTML/JS
        "X-Content-Type-Options": "nosniff",
        // CSP ketat: file CSV tidak perlu load resource apapun
        "Content-Security-Policy": "default-src 'none'; sandbox",
        // Cegah file di-embed di iframe (clickjacking)
        "X-Frame-Options": "DENY",
        // Matikan reflective XSS filter lama (justru bisa jadi attack vector)
        "X-XSS-Protection": "0",
        // Tidak ada informasi referrer yang bocor ke server tujuan
        "Referrer-Policy": "no-referrer",
        // HSTS — browser harus gunakan HTTPS seterusnya (1 tahun)
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        // Larang semua fitur browser yang tidak relevan
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        // Cegah file diakses oleh origin lain via fetch/XHR
        "Cross-Origin-Resource-Policy": "same-site",
        // Lepas header server yang bisa bocorkan info infrastruktur
        // (tidak bisa di-delete lewat Headers API, tapi eksplisit kosongkan)
        "Server": "",
    };
}

// ─── GET /api/produk/template-csv ────────────────────────────────────────────

export const GET: APIRoute = async ({ cookies, request }) => {
    // 1. Autentikasi
    if (!await authGuard(cookies)) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
            status: 401,
            headers: {
                "Content-Type":  "application/json",
                "Cache-Control": "no-store",
                // Tidak kirim WWW-Authenticate dengan detail realm — meminimalkan
                // informasi yang bocor ke penyerang tentang mekanisme auth
            },
        });
    }

    // 2. Tolak request yang membawa body (tidak standar pada GET, bisa jadi probe)
    const cl = request.headers.get("content-length");
    if (cl !== null && cl !== "0") {
        return new Response(JSON.stringify({ error: "Bad Request" }), {
            status: 400,
            headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
        });
    }

    // 3. Conditional GET — hindari transfer data jika konten tidak berubah
    // Ini aman karena ETag dihitung dari konten file, bukan waktu
    const ifNoneMatch = request.headers.get("if-none-match");
    if (ifNoneMatch === ETAG) {
        return new Response(null, {
            status: 304,
            headers: {
                "ETag":          ETAG,
                "Cache-Control": "no-store",
            },
        });
    }

    // 4. Kembalikan file dengan security headers lengkap
    return new Response(TEMPLATE_BYTES, {
        status:  200,
        headers: secureDownloadHeaders(true),
    });
};

// ─── HEAD — identik GET tapi tanpa body (RFC 7231 §4.3.2) ────────────────────

export const HEAD: APIRoute = async ({ cookies }) => {
    if (!await authGuard(cookies)) {
        return new Response(null, {
            status:  401,
            headers: { "Cache-Control": "no-store" },
        });
    }
    return new Response(null, {
        status:  200,
        headers: secureDownloadHeaders(false),
    });
};

// ─── Semua method lain → 405 ──────────────────────────────────────────────────
// Allow header wajib ada saat 405 (RFC 9110 §15.5.6).
// Response di-freeze sebagai konstanta — tidak dibuat ulang tiap request.
const METHOD_NOT_ALLOWED = Object.freeze(
    new Response(JSON.stringify({ error: "Method Not Allowed" }), {
        status:  405,
        headers: {
            "Content-Type":  "application/json",
            "Allow":         "GET, HEAD",
            "Cache-Control": "no-store",
        },
    })
);

export const POST:   APIRoute = () => METHOD_NOT_ALLOWED.clone();
export const PUT:    APIRoute = () => METHOD_NOT_ALLOWED.clone();
export const DELETE: APIRoute = () => METHOD_NOT_ALLOWED.clone();
export const PATCH:  APIRoute = () => METHOD_NOT_ALLOWED.clone();
