import { resetVerify } from '@/lib/auth';
import { json, guard } from '@/lib/http';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export async function POST(req: Request) {
  return guard(async () => {
    const { email, otp, password } = await req.json();
    return json(await resetVerify(email, otp, password));
  });
}
