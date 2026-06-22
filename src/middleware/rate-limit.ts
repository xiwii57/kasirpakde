// src/middleware/rate-limit.ts
// ══════════════════════════════════════════════════════════════════
// RATE LIMITER (In-Memory — Single Instance)
// ══════════════════════════════════════════════════════════════════

interface RateRecord {
    count:      number;
    resetAt:    number;
    blocked:    boolean;
    blockUntil: number;
    strikes:    number;
}

const rateStore = new Map<string, RateRecord>();

// Cleanup berkala — hapus entry yang sudah tidak aktif
const CLEANUP_INTERVAL_MS = 3 * 60 * 1000; // 3 menit
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [k, r] of rateStore.entries()) {
        if (now > r.resetAt && (!r.blocked || now > r.blockUntil)) {
            rateStore.delete(k);
            cleaned++;
        }
    }
    if (cleaned > 0) console.info(`[RateLimit] Cleanup: ${cleaned} entry dihapus.`);
}, CLEANUP_INTERVAL_MS);

const RATE_CONFIG = {
    login: {
        maxAttempts:      5,
        windowMs:         15 * 60 * 1000,  // 15 menit
        blockMs:          60 * 60 * 1000,  // 1 jam
        maxStrikes:       3,
        strikeMultiplier: 3,
    },
    api: {
        maxAttempts:      60,
        windowMs:         60 * 1000,
        blockMs:          10 * 60 * 1000,  // 10 menit
        maxStrikes:       10,
        strikeMultiplier: 1.5,
    },
} as const;

export type RateCategory = keyof typeof RATE_CONFIG;

export function checkRateLimit(
    ip: string,
    category: RateCategory,
): { allowed: boolean; retryAfter: number } {
    const cfg = RATE_CONFIG[category];
    const key = `${category}:${ip.replace(/[^a-fA-F0-9.:]/g, "").slice(0, 45)}`;
    const now = Date.now();

    // Emergency cleanup jika store terlalu besar
    if (rateStore.size > 2000) {
        for (const [k, r] of rateStore.entries()) {
            if (now > r.resetAt && (!r.blocked || now > r.blockUntil)) rateStore.delete(k);
        }
    }

    const rec = rateStore.get(key);

    // Window baru atau entry pertama
    if (!rec || now > rec.resetAt) {
        rateStore.set(key, {
            count:      1,
            resetAt:    now + cfg.windowMs,
            blocked:    false,
            blockUntil: 0,
            strikes:    rec?.strikes ?? 0,
        });
        return { allowed: true, retryAfter: 0 };
    }

    // Sudah melewati batas strike maksimum — permanen diblokir
    if (rec.strikes >= cfg.maxStrikes) return { allowed: false, retryAfter: 9999 };

    // Sedang dalam masa blokir
    if (rec.blocked && now < rec.blockUntil) {
        return { allowed: false, retryAfter: Math.ceil((rec.blockUntil - now) / 1000) };
    }

    // Masa blokir selesai — reset
    if (rec.blocked && now >= rec.blockUntil) {
        rateStore.set(key, { count: 1, resetAt: now + cfg.windowMs, blocked: false, blockUntil: 0, strikes: rec.strikes });
        return { allowed: true, retryAfter: 0 };
    }

    // Tambah counter, cek batas
    rec.count++;
    if (rec.count > cfg.maxAttempts) {
        const strikes  = rec.strikes + 1;
        const blockMs  = cfg.blockMs * Math.pow(cfg.strikeMultiplier, strikes - 1);
        rec.blocked    = true;
        rec.blockUntil = now + blockMs;
        rec.strikes    = strikes;
        rateStore.set(key, rec);
        console.warn(`[RateLimit] IP diblokir (${category}) — strike: ${strikes}, durasi: ${Math.round(blockMs / 60000)}m`);
        return { allowed: false, retryAfter: Math.ceil(blockMs / 1000) };
    }

    return { allowed: true, retryAfter: 0 };
}

export function resetLoginRateLimit(ip: string): void {
    rateStore.delete(`login:${ip.replace(/[^a-fA-F0-9.:]/g, "").slice(0, 45)}`);
}
