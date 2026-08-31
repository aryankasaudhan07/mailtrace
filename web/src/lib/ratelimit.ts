/**
 * Small fixed-window rate limiter. Two backends behind one interface, matching
 * the rest of the app: Vercel KV (atomic INCR + EXPIRE, shared across serverless
 * instances) in production, an in-memory Map in dev/tests.
 *
 * Used to protect the abuse-prone endpoints: auth (credential brute-force, OTP
 * brute-force, OTP-email spam), the expensive analyze pipeline, and the public
 * tracking pixel.
 */
import { HttpError } from './auth';

function useKv(): boolean {
  return Boolean(process.env.KV_REST_API_URL || process.env.KV_URL);
}

const mem = new Map<string, { count: number; resetAt: number }>();

export interface RateResult { ok: boolean; retryAfter: number }

/** Count one hit against `key`; returns ok:false once `limit` is exceeded within
 *  `windowSec`. Never throws (a limiter failure must not take the endpoint down). */
export async function rateLimit(key: string, limit: number, windowSec: number): Promise<RateResult> {
  try {
    if (useKv()) {
      const { kv } = await import('@vercel/kv');
      const k = `rl:${key}`;
      const n = await kv.incr(k);
      if (n === 1) await kv.expire(k, windowSec);
      if (n > limit) {
        const ttl = await kv.ttl(k);
        return { ok: false, retryAfter: ttl > 0 ? ttl : windowSec };
      }
      return { ok: true, retryAfter: 0 };
    }
    const now = Date.now();
    const e = mem.get(key);
    if (!e || e.resetAt <= now) {
      mem.set(key, { count: 1, resetAt: now + windowSec * 1000 });
      return { ok: true, retryAfter: 0 };
    }
    e.count += 1;
    if (e.count > limit) return { ok: false, retryAfter: Math.ceil((e.resetAt - now) / 1000) };
    return { ok: true, retryAfter: 0 };
  } catch {
    return { ok: true, retryAfter: 0 }; // fail open — availability over strictness
  }
}

/** The caller's IP (Vercel sets x-forwarded-for), for per-client limits. */
export function clientIp(req: Request): string {
  return (req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || '').split(',')[0].trim() || 'unknown';
}

/** Enforce a limit or throw HTTP 429 (guard() turns it into {detail} + status). */
export async function enforceRateLimit(key: string, limit: number, windowSec: number): Promise<void> {
  const r = await rateLimit(key, limit, windowSec);
  if (!r.ok) throw new HttpError(429, `Too many requests — slow down and try again in ${r.retryAfter}s.`);
}

/** Test/dev helper. */
export function __resetRateLimit(): void {
  mem.clear();
}
