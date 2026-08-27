/**
 * M5 -- network intelligence (ported from app/analyzers/m5_network.py).
 *
 * Offline-first: GeoLite2-City mmdb for country/city, Tor exit list and
 * VPN/datacenter ranges as set membership. Uses the AUTHENTICATED origin
 * (M2 trust boundary), not the forgeable bottom hop: the whole chain is scanned
 * for anonymizers, but a hit below the boundary is attacker-controllable and
 * reported at reduced confidence.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { open, type Reader, type CityResponse } from 'maxmind';
import { config } from '../config';
import { Analyzer, clear, triggered, unavailable, type Evidence } from '../schemas/evidence';
import type { Hop, ParsedEmail } from '../schemas/email';
import { register } from './base';
import { authenticatedOrigin } from './m2_headers';
import { isPublicIp, ipInCidrs, parseCidr } from './ip';

const WEBMAIL_PROVIDERS = new Set([
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com',
  'live.com', 'msn.com', 'yahoo.com', 'ymail.com', 'proton.me', 'protonmail.com',
]);

const intel = (f: string) => join(config.intelDir(), f);

function loadLines(filename: string): string[] {
  const p = intel(filename);
  if (!existsSync(p)) return [];
  try {
    return readFileSync(p, 'utf-8')
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
  } catch {
    return [];
  }
}

function ipInRangeSet(ip: string, ranges: string[]): boolean {
  const cidrs = ranges
    .map((r) => (r.includes('/') ? parseCidr(r) : parseCidr(`${r}/${r.includes(':') ? 128 : 32}`)))
    .filter((c): c is NonNullable<typeof c> => c !== null);
  return ipInCidrs(ip, cidrs);
}

const checkTorExit = (ip: string) => new Set(loadLines('tor-exits.txt')).has(ip);
const checkVpn = (ip: string) => ipInRangeSet(ip, loadLines('vpn-ipv4.txt'));
const checkDatacenter = (ip: string) => ipInRangeSet(ip, loadLines('datacenter-ipv4.txt'));

let _reader: Reader<CityResponse> | null = null;
let _readerTried = false;
async function geoipLookup(ip: string): Promise<Record<string, unknown> | null> {
  const p = intel('GeoLite2-City.mmdb');
  if (!existsSync(p)) return null;
  try {
    if (!_reader && !_readerTried) {
      _readerTried = true;
      _reader = await open<CityResponse>(p);
    }
    if (!_reader) return null;
    const r = _reader.get(ip);
    if (!r) return null;
    return {
      country: r.country?.iso_code ?? null,
      city: r.city?.names?.en ?? null,
      latitude: r.location?.latitude ?? null,
      longitude: r.location?.longitude ?? null,
    };
  } catch {
    return null;
  }
}

export async function analyze(caseId: string, email: ParsedEmail): Promise<Evidence[]> {
  const { boundary, hops } = authenticatedOrigin(email);
  const routable = hops.filter((h) => isPublicIp(h.from_ip));

  const hasGeoip = existsSync(intel('GeoLite2-City.mmdb'));
  const hasTor = existsSync(intel('tor-exits.txt'));
  const hasVpn = existsSync(intel('vpn-ipv4.txt'));
  const hasDatacenter = existsSync(intel('datacenter-ipv4.txt'));

  if (!hasGeoip && !hasTor && !hasVpn && !hasDatacenter) {
    return [unavailable(caseId, Analyzer.M5_NETWORK, 'origin_anonymized',
      'M5 unavailable: no intel data files in intel/.')];
  }

  if (!routable.length) {
    const fromDomain = (email.from_addr || '').split('@').pop()!.toLowerCase();
    if (WEBMAIL_PROVIDERS.has(fromDomain)) {
      return [triggered(caseId, Analyzer.M5_NETWORK, 'provider_withholds_origin', {
        provider: fromDomain,
        explanation:
          `${fromDomain} strips the sender's originating IP for webmail-composed mail; it is not recoverable ` +
          'from the headers. Geolocation confidence is zero. Lawful next step: a preservation request to the provider.',
      })];
    }
    return [clear(caseId, Analyzer.M5_NETWORK, 'origin_anonymized', {
      explanation: 'No routable source IP present in the relay chain.',
    })];
  }

  const originHop: Hop = boundary && isPublicIp(boundary.from_ip) ? boundary : routable[0];
  const trustConf = (hop: Hop): number => (boundary === null || hop.seq >= boundary.seq ? 1.0 : 0.7);

  const ev: Evidence[] = [];

  // anonymizer (Tor / VPN): scan the whole chain, report the lowest-seq hit
  let anon: { hop: Hop; kind: string } | null = null;
  for (const hop of routable) {
    if (hasTor && checkTorExit(hop.from_ip!)) { anon = { hop, kind: 'Tor exit node' }; break; }
    if (hasVpn && checkVpn(hop.from_ip!)) { anon = { hop, kind: 'known VPN range' }; break; }
  }
  if (anon) {
    const conf = trustConf(anon.hop);
    const region = conf === 1.0 ? 'authenticated origin' : 'unverified region below the trust boundary';
    ev.push(triggered(caseId, Analyzer.M5_NETWORK, 'origin_anonymized', {
      ip: anon.hop.from_ip,
      hop_seq: anon.hop.seq,
      classification: anon.kind,
      trust_region: region,
      explanation: `Relay hop ${anon.hop.seq} (${anon.hop.from_ip}) is a ${anon.kind} — the sender anonymized their origin. This hop is in the ${region}.`,
    }, conf));
  }

  // datacenter-hosted origin: test the authenticated origin only
  if (hasDatacenter && checkDatacenter(originHop.from_ip!)) {
    ev.push(triggered(caseId, Analyzer.M5_NETWORK, 'origin_datacenter_hosted', {
      ip: originHop.from_ip,
      hop_seq: originHop.seq,
      explanation: 'Authenticated origin is a datacenter range, not an eyeball/residential network.',
    }, trustConf(originHop)));
  }

  const geo = hasGeoip ? await geoipLookup(originHop.from_ip!) : null;

  if (!ev.length) {
    const detail: Record<string, unknown> = {
      ip: originHop.from_ip,
      hops_checked: routable.length,
      explanation: `No hop in the chain (${routable.length} routable) matches Tor, VPN or datacenter ranges.`,
    };
    if (geo) detail.geo = geo;
    ev.push(clear(caseId, Analyzer.M5_NETWORK, 'origin_anonymized', detail));
  }

  return ev;
}

register(Analyzer.M5_NETWORK, analyze);
