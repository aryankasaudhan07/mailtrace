import { resetVerify } from '@/lib/auth';
import { json, guard } from '@/lib/http';
import { enforceRateLimit, clientIp } from '@/lib/ratelimit';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export async function POST(req: Request) {
  return guard(async () => {
    const { email, otp, password } = await req.json();
    // Cap OTP guesses so the 6-digit reset code can't be brute-forced.
    await enforceRateLimit(`otp:reset:${clientIp(req)}:${String(email || '').toLowerCase()}`, 12, 600);
    return json(await resetVerify(email, otp, password));
  });
}
