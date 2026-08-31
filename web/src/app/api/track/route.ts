/**
 * Open-tracking API for the Gmail extension.
 *   POST /api/track  { id, subject, to }  -> register a tracked email (auth'd)
 *   GET  /api/track                       -> your tracked emails + open counts
 *
 * CORS is open because the extension calls these cross-origin; the data is
 * owner-scoped by the Bearer token, so there is nothing sensitive to leak to an
 * origin that doesn't already hold the token.
 */
import { registerTrack, listTracks } from '@/lib/track-store';
import { HttpError, verifyToken } from '@/lib/auth';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'authorization, content-type',
};
const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', ...CORS } });

function user(req: Request): string {
  const token = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '').trim();
  const email = token ? verifyToken(token) : null;
  if (!email) throw new HttpError(401, 'Not authenticated');
  return email;
}

export function OPTIONS() {
  return new Response(null, { status: 204, headers: CORS });
}

export async function GET(req: Request) {
  try {
    const owner = user(req);
    const tracks = (await listTracks(owner)).map((t) => ({
      id: t.id,
      subject: t.subject,
      to: t.to,
      created_at: t.created_at,
      opens: t.count,
      last_open: t.last_open,
      opened: t.count > 0,
    }));
    return json({ total: tracks.length, tracks });
  } catch (e) {
    if (e instanceof HttpError) return json({ detail: e.message }, e.status);
    return json({ detail: (e as Error).message ?? 'error' }, 500);
  }
}

export async function POST(req: Request) {
  try {
    const owner = user(req);
    const body = (await req.json().catch(() => ({}))) as { id?: string; subject?: string; to?: string };
    const id = (body.id || '').trim();
    if (!/^[A-Za-z0-9_-]{8,128}$/.test(id)) return json({ detail: 'invalid tracking id' }, 400);
    const rec = await registerTrack(id, owner, (body.subject || '(no subject)').slice(0, 300), (body.to || '').slice(0, 300));
    return json({ id: rec.id, ok: true }, 201);
  } catch (e) {
    if (e instanceof HttpError) return json({ detail: e.message }, e.status);
    return json({ detail: (e as Error).message ?? 'error' }, 500);
  }
}
