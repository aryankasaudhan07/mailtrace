import { registry } from '@/lib/analyzers/index';
import { loadRules } from '@/lib/scoring/engine';
import { config } from '@/lib/config';
import { json } from '@/lib/http';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  const rules = loadRules();
  // SMTP (nodemailer) is the transport; MAIL_FROM falls back to SMTP_USER.
  const emailConfigured = Boolean(
    process.env.SMTP_USER && (process.env.SMTP_PASSWORD || process.env.SMTP_PASS),
  );
  return json({
    status: 'ok',
    fixture_mode: config.fixtureMode(),
    scorer_version: rules.version,
    signals_defined: Object.keys(rules.signals).length,
    analyzers_registered: [...registry().keys()].sort(),
    email_configured: emailConfigured,
    email_transport: emailConfigured ? 'smtp' : 'none',
    // non-secret diagnostic: the MX hosts the trust boundary treats as our infra
    trusted_hosts: [...config.trustedHosts()],
  });
}
