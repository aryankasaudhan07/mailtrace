/**
 * Settings, env-driven (ported from app/config.py, the parts used so far).
 * Deployments MUST override TRUSTED_MX_HOSTS / TRUSTED_MX_CIDRS with their real
 * receiving infrastructure; the default names the fixture/demo MX so the trust
 * boundary resolves out-of-the-box in fixture mode.
 */

function csv(v: string | undefined, fallback: string): string[] {
  return (v ?? fallback)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export const config = {
  trustedHosts(): Set<string> {
    return new Set(csv(process.env.TRUSTED_MX_HOSTS, 'mx.example.ac.in').map((s) => s.toLowerCase()));
  },
  trustedCidrs(): string[] {
    return csv(process.env.TRUSTED_MX_CIDRS, '');
  },
  geminiApiKey(): string {
    return process.env.GEMINI_API_KEY ?? process.env.LLM_API_KEY ?? '';
  },
  fixtureMode(): boolean {
    return (process.env.FIXTURE_MODE ?? '1') !== '0';
  },
};
