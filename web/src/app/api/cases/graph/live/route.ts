import { caseGraph } from '@/lib/case-service';
import { json, guard } from '@/lib/http';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  return guard(async () => json(await caseGraph()));
}
