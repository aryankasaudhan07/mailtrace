/**
 * The tracking pixel. The RECIPIENT's mail client requests this when it renders
 * the email, so it is PUBLIC (no auth) and returns a 1x1 transparent GIF while
 * logging the open. We send aggressive no-cache headers to coax re-fetches on
 * re-open, though Gmail's image proxy caches regardless -- so the open COUNT is
 * best-effort (see the extension README).
 */
import { recordOpen } from '@/lib/track-store';
import { rateLimit } from '@/lib/ratelimit';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// 1x1 transparent GIF.
const GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const clean = (id || '').replace(/\.gif$/i, '');
  if (/^[A-Za-z0-9_-]{8,128}$/.test(clean)) {
    const ip = (req.headers.get('x-forwarded-for') || '').split(',')[0].trim() || 'unknown';
    const ua = (req.headers.get('user-agent') || '').slice(0, 300);
    // Soft limit: the pixel ALWAYS renders (never 429 a recipient's mail client),
    // but stop recording opens from an IP that is flooding us (abuse / log spam).
    const { ok } = await rateLimit(`pixel:${ip}`, 600, 60); // 600 opens / min per IP
    // fire and forget: never make the recipient wait on our storage
    if (ok) recordOpen(clean, { at: new Date().toISOString(), ua, ip }).catch(() => {});
  }
  return new Response(GIF as BodyInit, {
    status: 200,
    headers: {
      'content-type': 'image/gif',
      'content-length': String(GIF.length),
      'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
      pragma: 'no-cache',
      expires: '0',
      'access-control-allow-origin': '*',
    },
  });
}
