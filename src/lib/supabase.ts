// src/lib/supabase.ts
import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL      = import.meta.env.PUBLIC_SUPABASE_URL as string;
const SUPABASE_ANON_KEY = import.meta.env.PUBLIC_SUPABASE_ANON_KEY as string;
const SERVICE_ROLE_KEY  = import.meta.env.SUPABASE_SERVICE_ROLE as string;

// Client untuk browser / realtime (anon key)
export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
});

// Client server-side dengan service role (bypass RLS) — HANYA di server
export function createServiceClient() {
    return createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    });
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface Produk {
    id:          string;
    nama_produk: string;
    harga_beli:  number;
    harga_jual:  number;
    kategori:    string;
    quick_cash:  boolean;
    created_at:  string;
    updated_at:  string;
}

export interface HargaLog {
    id:              string;
    produk_id:       string;
    nama_produk:     string;
    harga_beli_lama: number | null;
    harga_beli_baru: number | null;
    harga_jual_lama: number | null;
    harga_jual_baru: number | null;
    changed_at:      string;
}

export interface TopSeller {
    produk_id:   string;
    nama_produk: string;
    kategori:    string;
    total_terjual: number;
    total_omzet:   number;
}

export const KATEGORI_LIST = [
"Minuman",
"Makanan",
"Snack",
"Rokok",
"Sembako",
"Bumbu & Masak",
"Roti & Kue",
"Es Krim & Frozen",
"Kebersihan Diri",
"Kebersihan Rumah",
"Obat & Kesehatan",
"Alat Tulis",
"Lainnya",
] as const;

export type Kategori = typeof KATEGORI_LIST[number];
