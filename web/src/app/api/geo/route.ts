import { checkTorExit, checkVpn, checkDatacenter, geoipLookup } from '@/lib/analyzers/m5_network';
import { isUnroutableIp } from '@/lib/analyzers/ip';
import { ipApiLookup } from '@/lib/geo';
import { config } from '@/lib/config';
import { json, guard } from '@/lib/http';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const risk = (s: number) => (s >= 70 ? 'High' : s >= 35 ? 'Medium' : 'Low');

export async function GET(req: Request) {
  return guard(async () => {
    const ip = new URL(req.url).searchParams.get('ip')?.trim();
    if (!ip) return json({ detail: 'ip query param required' }, 400);

    // ip-api.com is the primary geo + reputation source (replaces MaxMind).
    const api = config.geoOnline() ? await ipApiLookup(ip) : null;

    // reputation: prefer ip-api's proxy/hosting flags; supplement with the
    // offline lists when present (dev), and always factor unroutable IPs.
    const tor = checkTorExit(ip);
    const vpn = checkVpn(ip) || (api?.proxy ?? false);
    const dc = checkDatacenter(ip) || (api?.hosting ?? false);
    const priv = isUnroutableIp(ip);
    const score = Math.min(95, 8 + (tor ? 62 : 0) + (vpn ? 24 : 0) + (dc ? 18 : 0) + (priv ? 40 : 0));

    // geo: ip-api first, then offline mmdb (dev), then null.
    let geo: { country: string | null; city: string | null; latitude: number | null; longitude: number | null } | null = null;
    let isp: string | null = null;
    let geoSource = 'unavailable';
    if (api) {
      geo = { country: api.country, city: api.city, latitude: api.latitude, longitude: api.longitude };
      isp = api.isp;
      geoSource = 'ip-api.com';
    } else {
      const mmdb = await geoipLookup(ip);
      if (mmdb) {
        geo = {
          country: (mmdb.country as string) ?? null,
          city: (mmdb.city as string) ?? null,
          latitude: (mmdb.latitude as number) ?? null,
          longitude: (mmdb.longitude as number) ?? null,
        };
        geoSource = 'offline GeoLite2';
      }
    }

    return json({
      ip,
      country: geo?.country ?? null,
      city: geo?.city ?? null,
      latitude: geo?.latitude ?? null,
      longitude: geo?.longitude ?? null,
      isp,
      geo_source: geoSource,
      reputation: {
        abuse_confidence: score,
        risk: risk(score),
        tor_exit: tor,
        vpn_proxy: vpn,
        hosting: dc,
        usage_type: dc ? 'Data center / hosting' : null,
        recent_abuse: score >= 70 ? 'High' : 'Low',
        source: api ? 'ip-api.com (proxy/hosting flags)' : 'heuristic (offline Tor/VPN/DC lists)',
      },
    });
  });
}
