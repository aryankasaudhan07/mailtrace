import { getCase } from '@/lib/case-service';
import type { CaseRecord } from '@/lib/case-service';
import { buildReportPdf } from '@/lib/report';
import { notFound, guard } from '@/lib/http';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  return guard(async () => {
    const { id } = await ctx.params;
    const rec = await getCase(id);
    if (!rec) return notFound();
    const pdf = await buildReportPdf(rec as CaseRecord);
    const subject = (rec as CaseRecord).subject || 'case';
    const safe = subject.replace(/[^a-z0-9]+/gi, '-').slice(0, 40).replace(/^-|-$/g, '') || 'case';
    return new Response(pdf as BodyInit, {
      status: 200,
      headers: {
        'content-type': 'application/pdf',
        'content-disposition': `attachment; filename="mailtrace-${safe}-${id.slice(0, 8)}.pdf"`,
      },
    });
  });
}
