/**
 * IP geolocation via ip-api.com (replaces the MaxMind mmdb, which can't ship in
 * a serverless bundle). Free tier is HTTP-only and ~45 req/min; we call it
 * server-side (no browser mixed-content issue) and degrade to null on any error.
 * The `proxy` / `hosting` flags let M5 classify anonymized / datacenter origins
 * online, without the local Tor/VPN/datacenter lists.
 */

export interface GeoResult {
  country: string | null; // ISO 2-letter, matches the UI flag renderer
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  isp: string | null;
  proxy: boolean; // proxy / VPN / Tor exit
  hosting: boolean; // datacenter / hosting network
  source: string;
}

const FIELDS = 'status,message,countryCode,city,lat,lon,isp,org,proxy,hosting,query';

export async function ipApiLookup(ip: string, timeoutMs = 5000): Promise<GeoResult | null> {
  if (!ip) return null;
  try {
    const r = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${FIELDS}`, {
      signal: AbortSignal.timeout(timeoutMs),
      headers: { accept: 'application/json' },
    });
    if (!r.ok) return null;
    const d = (await r.json()) as {
      status?: string; countryCode?: string; city?: string; lat?: number; lon?: number;
      isp?: string; org?: string; proxy?: boolean; hosting?: boolean;
    };
    if (d.status !== 'success') return null;
    return {
      country: d.countryCode ?? null,
      city: d.city ?? null,
      latitude: typeof d.lat === 'number' ? d.lat : null,
      longitude: typeof d.lon === 'number' ? d.lon : null,
      isp: d.isp ?? d.org ?? null,
      proxy: Boolean(d.proxy),
      hosting: Boolean(d.hosting),
      source: 'ip-api.com',
    };
  } catch {
    return null;
  }
}
