import { updateProfile } from '@/lib/auth';
import { json, guard } from '@/lib/http';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export async function PATCH(req: Request) {
  return guard(async () => {
    const token = (req.headers.get('authorization') || '').replace(/^Bearer /, '').trim();
    const { name } = await req.json();
    return json({ user: await updateProfile(token, { name }) });
  });
}
