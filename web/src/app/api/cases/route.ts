import { analyzeAndStore, caseListItem, listCases } from '@/lib/case-service';
import { json, guard } from '@/lib/http';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
// analysis runs six lanes (some do DNS/RDAP); give it headroom on Vercel.
export const maxDuration = 60;

export async function GET(req: Request) {
  return guard(async () => {
    const url = new URL(req.url);
    const limit = Number(url.searchParams.get('limit') ?? '200');
    const band = url.searchParams.get('band');
    let items = (await listCases(limit)).map(caseListItem);
    if (band) items = items.filter((i) => i.band === band);
    items.sort((a, b) => (a.analyzed_at < b.analyzed_at ? 1 : -1));
    return json({ total: items.length, items: items.slice(0, limit) });
  });
}

export async function POST(req: Request) {
  return guard(async () => {
    const form = await req.formData();
    const file = form.get('file');
    if (!(file instanceof File)) return json({ detail: 'empty upload' }, 400);
    const raw = Buffer.from(await file.arrayBuffer());
    if (!raw.length) return json({ detail: 'empty upload' }, 400);
    const result = await analyzeAndStore(raw, file.name || null);
    return json(result, 201);
  });
}
