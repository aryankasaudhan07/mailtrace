import { resetRequest } from '@/lib/auth';
import { json, guard } from '@/lib/http';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export async function POST(req: Request) {
  return guard(async () => {
    const { email } = await req.json();
    return json(await resetRequest(email));
  });
}
