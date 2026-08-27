import { caseEvidence, getCase } from '@/lib/case-service';
import { json, notFound, guard } from '@/lib/http';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  return guard(async () => {
    const { id } = await ctx.params;
    const rec = await getCase(id);
    return rec ? json(caseEvidence(rec)) : notFound();
  });
}
