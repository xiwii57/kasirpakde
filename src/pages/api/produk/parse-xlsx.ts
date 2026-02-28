// src/pages/api/produk/parse-xlsx.ts
//
// POST /api/produk/parse-xlsx
// Menerima file .csv atau .xlsx via multipart/form-data,
// mem-parse isinya, dan mengembalikan array produk yang sudah dinormalisasi.
// Tidak menyimpan ke database — hanya parsing untuk preview di client.
export const prerender = false;

import type { APIRoute } from "astro";
import { createServiceClient } from "../../../lib/supabase";

// ─── Konstanta ────────────────────────────────────────────────────────────────

const MAX_TOKEN_LENGTH = 1024;
const AUTH_TIMEOUT_MS  = 5_000;
const MAX_FILE_BYTES   = 2 * 1024 * 1024;
const MAX_ROWS         = 1_000;
const MAX_NAMA_LEN     = 200;
const MAX_KATEGORI_LEN = 100;
const MAX_HARGA        = 100_000_000;

const VALID_KATEGORI = new Set([
    "Minuman", "Makanan", "Snack", "Rokok", "Sembako",
    "Kebersihan", "Kesehatan", "ATK", "Lainnya",
]);

// ─── Auth ─────────────────────────────────────────────────────────────────────

async function authGuard(cookies: any): Promise<boolean> {
    const token = cookies.get("sb-access-token")?.value;
    if (!token || typeof token !== "string" || token.length > MAX_TOKEN_LENGTH) return false;
    if (!/^[\w-]+\.[\w-]+\.[\w-]+$/.test(token)) return false;
    try {
        const result = await Promise.race([
            createServiceClient().auth.getUser(token),
                                          new Promise<never>((_, reject) =>
                                          setTimeout(() => reject(new Error("timeout")), AUTH_TIMEOUT_MS)
                                          ),
        ]);
        return !result.error && !!result.data?.user?.id;
    } catch { return false; }
}

// ─── Response Helper ──────────────────────────────────────────────────────────

function json(data: unknown, status = 200): Response {
    return new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
    });
}

// ─── Sanitize / Convert ───────────────────────────────────────────────────────

function sanitize(val: unknown, maxLen: number): string {
    return String(val ?? "").trim().replace(/[\x00-\x1F\x7F]/g, "").slice(0, maxLen);
}

function toInt(val: unknown): number {
    const n = parseInt(String(val ?? "0").replace(/[^\d-]/g, ""), 10);
    return Number.isFinite(n) ? Math.max(0, n) : 0;
}

function toBool(val: unknown): boolean {
    const s = String(val ?? "").trim().toLowerCase();
    return s === "true" || s === "1" || s === "ya" || s === "yes";
}

function normalizeKategori(raw: string): string {
    const s = sanitize(raw, MAX_KATEGORI_LEN);
    for (const k of VALID_KATEGORI) {
        if (k.toLowerCase() === s.toLowerCase()) return k;
    }
    return "Lainnya";
}

function normalizeHeader(h: string): string {
    return h.toLowerCase().trim().replace(/\s+/g, "_").replace(/[^a-z0-9_]/g, "");
}

// ─── Column Detection ─────────────────────────────────────────────────────────

interface ColMap { nama: number; beli: number; jual: number; kategori: number; qc: number; }

function detectColumns(headers: string[]): ColMap | null {
    const map: Record<string, number> = {};
    headers.forEach((h, i) => { map[normalizeHeader(h)] = i; });

    const namaIdx     = map["nama_produk"] ?? map["nama"]     ?? map["product"]   ?? -1;
    const beliIdx     = map["harga_beli"]  ?? map["beli"]     ?? map["cost"]      ?? -1;
    const jualIdx     = map["harga_jual"]  ?? map["jual"]     ?? map["price"]     ?? map["harga"] ?? -1;
    const kategoriIdx = map["kategori"]    ?? map["category"] ?? map["kat"]       ?? -1;
    const qcIdx       = map["quick_cash"]  ?? map["qc"]       ?? map["quickcash"] ?? -1;

    if (namaIdx === -1 || jualIdx === -1) return null;
    return { nama: namaIdx, beli: beliIdx, jual: jualIdx, kategori: kategoriIdx, qc: qcIdx };
}

// ─── Row Builder ──────────────────────────────────────────────────────────────

interface ProdukRow {
    nama_produk: string;
    harga_beli:  number;
    harga_jual:  number;
    kategori:    string;
    quick_cash:  boolean;
}

function buildRow(cells: string[], cols: ColMap): ProdukRow | null {
    const nama = sanitize(cells[cols.nama] ?? "", MAX_NAMA_LEN);
    if (!nama) return null;

    const jual = toInt(cells[cols.jual] ?? "0");
    if (jual <= 0 || jual > MAX_HARGA) return null;

    const beli     = cols.beli >= 0 ? toInt(cells[cols.beli] ?? "0") : 0;
    const kategori = cols.kategori >= 0 ? normalizeKategori(cells[cols.kategori] ?? "") : "Lainnya";
    const qc       = cols.qc >= 0 ? toBool(cells[cols.qc] ?? "false") : false;

    return { nama_produk: nama, harga_beli: Math.min(beli, MAX_HARGA), harga_jual: jual, kategori, quick_cash: qc };
}

// ─── CSV Parser ───────────────────────────────────────────────────────────────

function parseCSV(text: string): string[][] {
    const rows: string[][] = [];
    const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");

    for (const line of lines) {
        if (!line.trim()) continue;
        const cells: string[] = [];
        let cur = "", inQ = false;

        for (let i = 0; i < line.length; i++) {
            const ch = line[i];
            if (ch === '"') {
                if (inQ && line[i + 1] === '"') { cur += '"'; i++; }
                else inQ = !inQ;
            } else if (ch === ',' && !inQ) {
                cells.push(cur.trim()); cur = "";
            } else { cur += ch; }
        }
        cells.push(cur.trim());
        rows.push(cells);
    }
    return rows;
}

// ─── DEFLATE decompressor (Node 18+ / Vercel Edge) ───────────────────────────

async function inflateAsync(data: Uint8Array): Promise<Uint8Array> {
    const ds = new (globalThis as any).DecompressionStream("deflate-raw");
    const writer = ds.writable.getWriter();
    const reader = ds.readable.getReader();
    writer.write(data).catch(() => {});
    writer.close().catch(() => {});
    const chunks: Uint8Array[] = [];
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) chunks.push(value);
    }
    const total = chunks.reduce((s, c) => s + c.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }
    return out;
}

// ─── XML helper ───────────────────────────────────────────────────────────────

function xmlUnescape(s: string): string {
    return s
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'");
}

function extractCellValue(attrs: string, inner: string, sharedStrings: string[]): string {
    const isShared = /t="s"/.test(attrs);
    const isInline = /t="inlineStr"/.test(attrs) || /t="inline"/.test(attrs);

    const vMatch = inner.match(/<v>([\s\S]*?)<\/v>/);
    const tMatch = inner.match(/<t[^>]*>([\s\S]*?)<\/t>/);

    if (isShared && vMatch) {
        return sharedStrings[parseInt(vMatch[1], 10)] ?? "";
    }
    if (isInline) {
        // openpyxl menyimpan string sebagai <is><t>nilai</t></is>
        const isBlock = inner.match(/<is>([\s\S]*?)<\/is>/);
        if (isBlock) {
            let val = "";
            for (const t of isBlock[1].matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)) val += t[1];
            return xmlUnescape(val);
        }
        return tMatch ? xmlUnescape(tMatch[1]) : "";
    }
    if (tMatch) return xmlUnescape(tMatch[1]);
    if (vMatch) return vMatch[1]; // angka — kembalikan as-is
    return "";
}

// ─── XLSX Parser ─────────────────────────────────────────────────────────────

async function parseXLSX(buffer: ArrayBuffer): Promise<string[][]> {
    const bytes = new Uint8Array(buffer);

    function readU16(p: number) { return bytes[p] | (bytes[p + 1] << 8); }
    function readU32(p: number) {
        return (bytes[p] | (bytes[p+1]<<8) | (bytes[p+2]<<16) | (bytes[p+3]<<24)) >>> 0;
    }

    // Ekstrak semua entry ZIP — support method 0 (store) dan 8 (deflate)
    const files = new Map<string, string>();
    let pos = 0;

    while (pos < bytes.length - 4) {
        if (bytes[pos] !== 0x50 || bytes[pos+1] !== 0x4b ||
            bytes[pos+2] !== 0x03 || bytes[pos+3] !== 0x04) { pos++; continue; }

            const compMethod = readU16(pos + 8);
        const compSize   = readU32(pos + 18);
        const uncompSize = readU32(pos + 22);
        const nameLen    = readU16(pos + 26);
        const extraLen   = readU16(pos + 28);
        const nameStart  = pos + 30;
        const name       = new TextDecoder().decode(bytes.slice(nameStart, nameStart + nameLen));
        const dataStart  = nameStart + nameLen + extraLen;
        const dataEnd    = dataStart + compSize;

        // Hanya proses file XML yang relevan untuk efisiensi
        const relevant = name.includes("sheet1") || name.includes("Sheet1") ||
        name.toLowerCase().includes("sharedstr");

        if (relevant && uncompSize <= 10 * 1024 * 1024) {
            try {
                let raw: Uint8Array;
                if (compMethod === 0) {
                    raw = bytes.slice(dataStart, dataEnd);
                } else if (compMethod === 8) {
                    raw = await inflateAsync(bytes.slice(dataStart, dataEnd));
                } else {
                    pos = dataEnd; continue;
                }
                files.set(name, new TextDecoder("utf-8", { fatal: false }).decode(raw));
            } catch (e) {
                console.error("[parse-xlsx] decompress failed:", name, e);
            }
        }

        pos = dataEnd;
    }

    // Parse shared strings (opsional — openpyxl kadang pakai inlineStr)
    const sharedStrings: string[] = [];
    const ssXml = files.get("xl/sharedStrings.xml") ?? files.get("xl/sharedstrings.xml") ?? "";
    if (ssXml) {
        for (const m of ssXml.matchAll(/<si>([\s\S]*?)<\/si>/g)) {
            let val = "";
            for (const t of m[1].matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)) val += t[1];
            sharedStrings.push(xmlUnescape(val));
        }
    }

    // Parse sheet1
    const sheetXml = files.get("xl/worksheets/sheet1.xml")
    ?? files.get("xl/worksheets/Sheet1.xml") ?? "";
    if (!sheetXml) return [];

    const rows: string[][] = [];

    for (const rowM of sheetXml.matchAll(/<row[^>]*>([\s\S]*?)<\/row>/g)) {
        const cells: string[] = [];

        for (const cellM of rowM[1].matchAll(/<c\s([^>]*)>([\s\S]*?)<\/c>/g)) {
            const attrs  = cellM[1];
            const inner  = cellM[2];
            const refM   = attrs.match(/r="([A-Z]+)\d+"/);
            const colRef = refM?.[1] ?? "";
            const colIdx = colRef
            ? colRef.split("").reduce((acc, ch) => acc * 26 + ch.charCodeAt(0) - 64, 0) - 1
            : cells.length;

            while (cells.length <= colIdx) cells.push("");
            cells[colIdx] = extractCellValue(attrs, inner, sharedStrings);
        }

        if (cells.some(c => c.trim())) rows.push(cells);
    }

    return rows;
}

// ─── Deduplicate ──────────────────────────────────────────────────────────────

function dedup(rows: ProdukRow[]): { produk: ProdukRow[]; duplicates: number } {
    const seen = new Set<string>();
    const out: ProdukRow[] = [];
    let dups = 0;
    for (const r of rows) {
        const key = r.nama_produk.toLowerCase().trim();
        if (seen.has(key)) { dups++; continue; }
        seen.add(key); out.push(r);
    }
    return { produk: out, duplicates: dups };
}

// ─── POST /api/produk/parse-xlsx ─────────────────────────────────────────────

export const POST: APIRoute = async ({ request, cookies }) => {
    if (!await authGuard(cookies)) return json({ error: "Unauthorized" }, 401);

    const ct = request.headers.get("content-type") ?? "";
    if (!ct.includes("multipart/form-data"))
        return json({ error: "Content-Type harus multipart/form-data" }, 415);

    let form: FormData;
    try { form = await request.formData(); }
    catch { return json({ error: "Gagal membaca form data" }, 400); }

    const file = form.get("file");
    if (!file || !(file instanceof File))
        return json({ error: "Field 'file' wajib ada dan berupa file" }, 400);

    const fname  = file.name.toLowerCase();
    const isCSV  = fname.endsWith(".csv");
    const isXLSX = fname.endsWith(".xlsx") || fname.endsWith(".xls");
    if (!isCSV && !isXLSX)
        return json({ error: "Hanya file .csv atau .xlsx yang didukung" }, 400);

    if (file.size === 0)            return json({ error: "File kosong" }, 400);
    if (file.size > MAX_FILE_BYTES) return json({ error: "Ukuran file maks 2 MB" }, 400);

    let rawRows: string[][];
    try {
        rawRows = isCSV
        ? parseCSV(await file.text())
        : await parseXLSX(await file.arrayBuffer());
    } catch (e) {
        console.error("[parse-xlsx] error:", e);
        return json({ error: "Gagal membaca isi file. Pastikan format file benar." }, 422);
    }

    if (rawRows.length < 2)
        return json({ error: "File tidak memiliki data. Pastikan ada baris header dan minimal 1 baris data." }, 422);

    const cols = detectColumns(rawRows[0]);
    if (!cols)
        return json({ error: "Kolom wajib tidak ditemukan. Pastikan ada kolom 'nama_produk' dan 'harga_jual'." }, 422);

    const produkRaw: ProdukRow[] = [];
    for (const row of rawRows.slice(1, MAX_ROWS + 1)) {
        if (row.every(c => !c.trim())) continue;
        const p = buildRow(row, cols);
        if (p) produkRaw.push(p);
    }

    if (produkRaw.length === 0)
        return json({ error: "Tidak ada data produk valid yang ditemukan di file." }, 422);

    const { produk, duplicates } = dedup(produkRaw);

    return json({
        ok: true, produk, duplicates,
        total:   produk.length,
        skipped: rawRows.length - 1 - produkRaw.length,
    });
};

// ─── Method lain → 405 ───────────────────────────────────────────────────────

const NOT_ALLOWED = Object.freeze(
    new Response(JSON.stringify({ error: "Method Not Allowed" }), {
        status: 405,
        headers: { "Content-Type": "application/json", "Allow": "POST", "Cache-Control": "no-store" },
    })
);

export const GET:    APIRoute = () => NOT_ALLOWED.clone();
export const PUT:    APIRoute = () => NOT_ALLOWED.clone();
export const DELETE: APIRoute = () => NOT_ALLOWED.clone();
export const PATCH:  APIRoute = () => NOT_ALLOWED.clone();
