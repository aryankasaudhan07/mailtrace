import { me } from '@/lib/auth';
import { json, guard } from '@/lib/http';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export async function GET(req: Request) {
  return guard(async () => {
    const token = (req.headers.get('authorization') || '').replace(/^Bearer /, '').trim();
    return json({ user: await me(token) });
  });
}
