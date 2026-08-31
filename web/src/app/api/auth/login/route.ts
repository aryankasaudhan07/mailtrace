import { login } from '@/lib/auth';
import { json, guard } from '@/lib/http';
import { enforceRateLimit, clientIp } from '@/lib/ratelimit';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export async function POST(req: Request) {
  return guard(async () => {
    await enforceRateLimit(`login:${clientIp(req)}`, 20, 600); // 20 attempts / 10 min per IP
    const { email, password } = await req.json();
    return json(await login(email, password));
  });
}
