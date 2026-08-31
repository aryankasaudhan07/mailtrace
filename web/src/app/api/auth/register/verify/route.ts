import { registerVerify } from '@/lib/auth';
import { json, guard } from '@/lib/http';
import { enforceRateLimit, clientIp } from '@/lib/ratelimit';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export async function POST(req: Request) {
  return guard(async () => {
    const { email, otp } = await req.json();
    // Cap OTP guesses so the 6-digit code can't be brute-forced.
    await enforceRateLimit(`otp:reg:${clientIp(req)}:${String(email || '').toLowerCase()}`, 12, 600);
    return json(await registerVerify(email, otp), 201);
  });
}
