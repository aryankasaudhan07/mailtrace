import { registry } from '@/lib/analyzers/index';
import { loadRules } from '@/lib/scoring/engine';
import { config } from '@/lib/config';
import { json } from '@/lib/http';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  const rules = loadRules();
  const emailConfigured = Boolean(process.env.BREVO_API_KEY);
  return json({
    status: 'ok',
    fixture_mode: config.fixtureMode(),
    scorer_version: rules.version,
    signals_defined: Object.keys(rules.signals).length,
    analyzers_registered: [...registry().keys()].sort(),
    email_configured: emailConfigured,
    email_transport: emailConfigured ? 'brevo' : 'none',
    // non-secret diagnostic: the MX hosts the trust boundary treats as our infra
    trusted_hosts: [...config.trustedHosts()],
  });
}
