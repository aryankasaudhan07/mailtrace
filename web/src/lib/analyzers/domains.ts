/**
 * Shared domain helpers. Kept in its own module (not m7_graph) so header/auth
 * analyzers can use `registrableDomain` without importing m7_graph, which
 * imports back from m2_headers (that would be a circular dependency).
 *
 * NOTE: this is a small curated two-label-suffix list, not the full Public
 * Suffix List / RFC 9989 DNS Tree Walk. It is good enough for organisational
 * grouping of the domains we see; true PSL-grade alignment is a separate task.
 */
const TWO_LABEL_SUFFIXES = new Set([
  'co.in', 'ac.in', 'gov.in', 'org.in', 'net.in', 'edu.in', 'res.in', 'nic.in',
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'co.jp', 'com.br',
]);

/** The registrable ("organisational") domain, e.g. mail.brand.co.in -> brand.co.in. */
export function registrableDomain(host: string): string | null {
  const labels = host.toLowerCase().replace(/^\.+|\.+$/g, '').split('.');
  if (labels.length < 2) return null;
  const lastTwo = labels.slice(-2).join('.');
  const take = TWO_LABEL_SUFFIXES.has(lastTwo) ? 3 : 2;
  if (labels.length < take) return null;
  return labels.slice(-take).join('.');
}

/** True when two hostnames belong to the same organisation (registrable domain
 *  equal, or one is a subdomain of the other). */
export function sameOrgDomain(a: string | null, b: string | null): boolean {
  if (!a || !b) return false;
  a = a.toLowerCase();
  b = b.toLowerCase();
  if (a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`)) return true;
  const ra = registrableDomain(a);
  const rb = registrableDomain(b);
  return !!ra && ra === rb;
}
