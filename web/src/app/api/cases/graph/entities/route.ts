import { caseEntityGraph } from '@/lib/case-service';
import { json, guard, requireUser } from '@/lib/http';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  return guard(async () => {
    const owner = requireUser(req);
    const cases = new URL(req.url).searchParams.get('cases');
    const ids = cases ? cases.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
    return json(await caseEntityGraph(ids, owner));
  });
}
