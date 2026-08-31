/**
 * Shared domain helpers. Kept in its own module (not m7_graph) so header/auth
 * analyzers can use them without importing m7_graph, which imports back from
 * m2_headers (that would be a circular dependency).
 *
 * `registrableDomain` uses the bundled Public Suffix List (via tldts) with
 * PRIVATE suffixes enabled, so shared platforms are treated as separate
 * organisations: victim.herokuapp.com and other.herokuapp.com have DIFFERENT
 * registrable domains and therefore do NOT align. (DMARC record DISCOVERY still
 * uses the DNS lookups in m3_auth per RFC 7489/9989; this is the offline
 * organisational-domain comparison used for alignment/heuristics.)
 */
import { getDomain } from 'tldts';

/** The registrable ("organisational") domain, e.g. mail.brand.co.in -> brand.co.in,
 *  victim.herokuapp.com -> victim.herokuapp.com. null for a bare public suffix,
 *  an IP, or an unparseable host. */
export function registrableDomain(host: string | null | undefined): string | null {
  if (!host) return null;
  const clean = host.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  if (!clean) return null;
  return getDomain(clean, { allowPrivateDomains: true }) ?? null;
}

/** True when two hostnames belong to the same organisation. This is DMARC
 *  RELAXED alignment: identical, or the SAME registrable (organisational)
 *  domain. It deliberately does NOT treat "b is a subdomain of a" as aligned in
 *  general -- that would make a public/private suffix (herokuapp.com) align with
 *  every tenant beneath it. Same-org subdomains already share a registrable
 *  domain, so they still match. */
export function sameOrgDomain(a: string | null, b: string | null): boolean {
  if (!a || !b) return false;
  a = a.toLowerCase();
  b = b.toLowerCase();
  if (a === b) return true;
  const ra = registrableDomain(a);
  const rb = registrableDomain(b);
  return !!ra && !!rb && ra === rb;
}
