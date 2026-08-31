/**
 * GET /api/track/[id] -> full detail (open timeline) for one tracked email.
 * Auth'd and owner-scoped: you can only read your own tracks.
 */
import { getTrack } from '@/lib/track-store';
import { HttpError, verifyToken } from '@/lib/auth';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'authorization, content-type',
};
const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', ...CORS } });

export function OPTIONS() {
  return new Response(null, { status: 204, headers: CORS });
}

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const token = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '').trim();
    const owner = token ? verifyToken(token) : null;
    if (!owner) throw new HttpError(401, 'Not authenticated');
    const { id } = await ctx.params;
    const t = await getTrack(id);
    if (!t || t.owner !== owner) return json({ detail: 'not found' }, 404);
    return json({
      id: t.id, subject: t.subject, to: t.to, created_at: t.created_at,
      opens: t.count, last_open: t.last_open, opened: t.count > 0,
      events: t.opens.map((o) => ({ at: o.at, ua: o.ua })),
    });
  } catch (e) {
    if (e instanceof HttpError) return json({ detail: e.message }, e.status);
    return json({ detail: (e as Error).message ?? 'error' }, 500);
  }
}
