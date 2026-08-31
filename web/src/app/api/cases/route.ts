import { analyzeAndStore, caseListItem, listCases } from '@/lib/case-service';
import { json, guard, requireUser } from '@/lib/http';
import { enforceRateLimit } from '@/lib/ratelimit';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
// analysis runs seven lanes (some do DNS/RDAP); give it headroom on Vercel.
export const maxDuration = 60;

export async function GET(req: Request) {
  return guard(async () => {
    const owner = requireUser(req);
    const url = new URL(req.url);
    const limit = Number(url.searchParams.get('limit') ?? '200');
    const band = url.searchParams.get('band');
    let items = (await listCases(limit, owner)).map(caseListItem);
    if (band) items = items.filter((i) => i.band === band);
    items.sort((a, b) => (a.analyzed_at < b.analyzed_at ? 1 : -1));
    return json({ total: items.length, items: items.slice(0, limit) });
  });
}

export async function POST(req: Request) {
  return guard(async () => {
    const owner = requireUser(req);
    await enforceRateLimit(`analyze:${owner}`, 60, 60); // 60 analyses / min per user (each runs 7 lanes + DNS/RDAP)
    const form = await req.formData();
    const file = form.get('file');
    if (!(file instanceof File)) return json({ detail: 'empty upload' }, 400);
    const raw = Buffer.from(await file.arrayBuffer());
    if (!raw.length) return json({ detail: 'empty upload' }, 400);
    const result = await analyzeAndStore(raw, file.name || null, owner);
    return json(result, 201);
  });
}
