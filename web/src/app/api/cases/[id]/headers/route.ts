import { caseHeaders, getOwnedCase } from '@/lib/case-service';
import { json, notFound, guard, requireUser } from '@/lib/http';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  return guard(async () => {
    const owner = requireUser(req);
    const { id } = await ctx.params;
    const rec = await getOwnedCase(id, owner);
    return rec ? json(caseHeaders(rec)) : notFound();
  });
}
