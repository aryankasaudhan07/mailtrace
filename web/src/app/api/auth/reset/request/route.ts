import { resetRequest } from '@/lib/auth';
import { json, guard } from '@/lib/http';
import { enforceRateLimit, clientIp } from '@/lib/ratelimit';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export async function POST(req: Request) {
  return guard(async () => {
    await enforceRateLimit(`reset:${clientIp(req)}`, 6, 600); // 6 reset-OTP sends / 10 min per IP
    const { email } = await req.json();
    return json(await resetRequest(email));
  });
}
