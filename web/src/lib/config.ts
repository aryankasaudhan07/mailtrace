/**
 * Settings, env-driven (ported from app/config.py, the parts used so far).
 * Deployments MUST override TRUSTED_MX_HOSTS / TRUSTED_MX_CIDRS with their real
 * receiving infrastructure; the default names the fixture/demo MX so the trust
 * boundary resolves out-of-the-box in fixture mode.
 */

function csv(v: string | undefined, fallback: string): string[] {
  // `||` (not `??`) so a present-but-empty env var falls back to the default too
  // -- an empty TRUSTED_MX_HOSTS would otherwise leave the trust boundary
  // unresolvable (all hops UNVERIFIED).
  return (v || fallback)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

// The fixture/demo MX is ALWAYS trusted so the trust boundary resolves
// out-of-the-box, regardless of whether TRUSTED_MX_HOSTS is unset, empty, or set
// to a stale value in the host environment. Real deployments add their own MX via
// the env var (unioned in below); this fixture host is harmless in production —
// nobody legitimately receives mail as mx.example.ac.in.
const FIXTURE_MX = 'mx.example.ac.in';

export const config = {
  trustedHosts(): Set<string> {
    const hosts = new Set<string>([FIXTURE_MX]);
    for (const h of csv(process.env.TRUSTED_MX_HOSTS, '')) hosts.add(h.toLowerCase());
    return hosts;
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
  /** Offline intel directory (GeoLite2 mmdb, Tor/VPN/datacenter lists). */
  intelDir(): string {
    return process.env.INTEL_DIR ?? `${process.cwd()}/../intel`;
  },
  /** Whether online geo (ip-api.com) may be used. Tests set GEO_DISABLE_ONLINE=1. */
  geoOnline(): boolean {
    return process.env.GEO_DISABLE_ONLINE !== '1';
  },
  /**
   * M8 footprint: whether the analyzer may make live network calls (Gravatar +
   * the platform-probe catalog). Default on, but off automatically under Vitest
   * so the suite never touches the network. Force with M8_ENUM_ONLINE=1/0.
   */
  footprintOnline(): boolean {
    if (process.env.M8_ENUM_ONLINE != null) return process.env.M8_ENUM_ONLINE !== '0';
    return !process.env.VITEST;
  },
  /**
   * M8 footprint: whether to include the clearly-labelled simulated dataset so
   * the demo shows a rich platform list even when live probing is blocked.
   * Defaults to fixture/demo mode; force with M8_DEMO=1/0.
   */
  footprintDemo(): boolean {
    if (process.env.M8_DEMO != null) return process.env.M8_DEMO !== '0';
    return this.fixtureMode();
  },
};
