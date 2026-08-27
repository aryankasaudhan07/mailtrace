import { checkTorExit, checkVpn, checkDatacenter, geoipLookup } from '@/lib/analyzers/m5_network';
import { isUnroutableIp } from '@/lib/analyzers/ip';
import { json, guard } from '@/lib/http';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const risk = (s: number) => (s >= 70 ? 'High' : s >= 35 ? 'Medium' : 'Low');

async function onlineGeo(ip: string) {
  try {
    const r = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return null;
    const d = (await r.json()) as {
      success?: boolean; country_code?: string; city?: string; latitude?: number; longitude?: number;
      connection?: { isp?: string; org?: string };
    };
    if (d.success === false) return null;
    return {
      country: d.country_code ?? null,
      city: d.city ?? null,
      latitude: d.latitude ?? null,
      longitude: d.longitude ?? null,
      isp: d.connection?.isp ?? d.connection?.org ?? null,
      geo_source: 'ipwho.is (live lookup)',
    };
  } catch {
    return null;
  }
}

export async function GET(req: Request) {
  return guard(async () => {
    const ip = new URL(req.url).searchParams.get('ip')?.trim();
    if (!ip) return json({ detail: 'ip query param required' }, 400);

    const tor = checkTorExit(ip);
    const vpn = checkVpn(ip);
    const dc = checkDatacenter(ip);
    const priv = isUnroutableIp(ip);
    const score = Math.min(95, 8 + (tor ? 62 : 0) + (vpn ? 24 : 0) + (dc ? 18 : 0) + (priv ? 40 : 0));

    let geo = await geoipLookup(ip);
    let geoSource = 'offline GeoLite2';
    let isp: string | null = null;
    if (!geo) {
      const online = await onlineGeo(ip);
      if (online) {
        geo = { country: online.country, city: online.city, latitude: online.latitude, longitude: online.longitude };
        geoSource = online.geo_source;
        isp = online.isp;
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
        source: 'heuristic (Tor/VPN/DC lists; add ABUSEIPDB_KEY for live scores)',
      },
    });
  });
}
