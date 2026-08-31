/**
 * IP classification (ported from the M2 header module's ipaddress logic).
 *
 * The subtlety that bit the Python version too: RFC 5737 documentation ranges
 * (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) must be treated
 * as PUBLIC. They stand in for real addresses in fixtures and sanitised corpora;
 * flagging them as injected makes every test sample look forged. Everything else
 * that could never carry public traffic (RFC 1918 private, CGNAT, loopback,
 * link-local, reserved, ...) is unroutable.
 */

import ipaddr from 'ipaddr.js';

const DOC_V4 = ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'].map((c) => ipaddr.parseCIDR(c));
const DOC_V6 = ipaddr.parseCIDR('2001:db8::/32');

// ipaddr.js range() names that cannot legitimately appear in public transit.
const UNROUTABLE = new Set([
  'loopback', 'linkLocal', 'unspecified', 'private',
  'carrierGradeNat', 'reserved', 'uniqueLocal', 'broadcast',
]);

function parse(ip: string): ipaddr.IPv4 | ipaddr.IPv6 | null {
  try {
    return ipaddr.parse(ip);
  } catch {
    return null;
  }
}

// An IPv6 address can EMBED an IPv4 address (IPv4-mapped ::ffff:a.b.c.d, 6to4
// 2002::/16, NAT64 64:ff9b::/96). ipaddr.js reports these as their own ranges
// ('ipv4Mapped'/'6to4'/'rfc6052'), none of which are in UNROUTABLE -- so a
// PRIVATE IPv4 wrapped this way (e.g. ::ffff:10.0.0.5) would slip through as
// "public" and defeat forged-hop / private-IP detection. Unwrap to the inner
// IPv4 and classify THAT (matches Python's ipaddress.is_private).
function embeddedV4(addr: ipaddr.IPv6): ipaddr.IPv4 | null {
  try {
    if (addr.isIPv4MappedAddress()) return addr.toIPv4Address();
  } catch { /* not mapped */ }
  const p = addr.parts; // 8 x 16-bit groups
  try {
    if (addr.range() === '6to4') {                 // 2002:AABB:CCDD::/48
      return new ipaddr.IPv4([(p[1] >> 8) & 0xff, p[1] & 0xff, (p[2] >> 8) & 0xff, p[2] & 0xff]);
    }
    if (addr.range() === 'rfc6052') {              // 64:ff9b::/96 (NAT64), v4 in last 32 bits
      return new ipaddr.IPv4([(p[6] >> 8) & 0xff, p[6] & 0xff, (p[7] >> 8) & 0xff, p[7] & 0xff]);
    }
  } catch { /* construction failed */ }
  return null;
}

function isDocumentation(addr: ipaddr.IPv4 | ipaddr.IPv6): boolean {
  if (addr.kind() === 'ipv4') return DOC_V4.some((c) => addr.match(c));
  return addr.match(DOC_V6);
}

/** Normalize a raw IP string, tolerating an "IPv6:" prefix. null if invalid. */
export function cleanIp(value: string | null | undefined): string | null {
  if (!value) return null;
  let v = value.trim().toLowerCase();
  if (v.startsWith('ipv6:')) v = v.slice(5);
  const addr = parse(v);
  return addr ? addr.toString() : null;
}

/** True when this address cannot legitimately appear in public transit. */
export function isUnroutableIp(ip: string | null | undefined): boolean {
  if (!ip) return false;
  const addr = parse(ip);
  if (!addr) return false;
  // Unwrap an IPv6-embedded IPv4 and classify the inner address.
  if (addr.kind() === 'ipv6') {
    const inner = embeddedV4(addr as ipaddr.IPv6);
    if (inner) return isUnroutableIp(inner.toString());
  }
  if (!UNROUTABLE.has(addr.range())) return false;
  if (isDocumentation(addr)) return false; // doc ranges stand in for public addresses
  return true;
}

/** Routable-or-documentation, i.e. acceptable in a relay chain. */
export function isPublicIp(ip: string | null | undefined): boolean {
  if (!ip || !parse(ip)) return false;
  return !isUnroutableIp(ip);
}

/** True if `ip` falls inside any of the given CIDRs (kind-matched). */
export function ipInCidrs(ip: string, cidrs: Array<[ipaddr.IPv4 | ipaddr.IPv6, number]>): boolean {
  const addr = parse(ip);
  if (!addr) return false;
  return cidrs.some(([net, bits]) => net.kind() === addr.kind() && addr.match(net, bits));
}

export function parseCidr(cidr: string): [ipaddr.IPv4 | ipaddr.IPv6, number] | null {
  try {
    return ipaddr.parseCIDR(cidr);
  } catch {
    return null;
  }
}
