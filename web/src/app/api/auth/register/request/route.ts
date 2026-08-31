import { registerRequest } from '@/lib/auth';
import { json, guard } from '@/lib/http';
import { enforceRateLimit, clientIp } from '@/lib/ratelimit';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export async function POST(req: Request) {
  return guard(async () => {
    await enforceRateLimit(`reg:${clientIp(req)}`, 6, 600); // 6 OTP-email sends / 10 min per IP
    const { email, password, name } = await req.json();
    return json(await registerRequest(email, password, name), 202);
  });
}
