import { campaignClusters } from '@/lib/case-service';
import { json, guard, requireUser } from '@/lib/http';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  return guard(async () => json(await campaignClusters(requireUser(req))));
}
