/**
 * M2 -- header and relay forensics. THE headline module
 * (ported from app/analyzers/m2_headers.py).
 *
 * Received: headers are PREPENDED by each MTA, so raw order is reverse
 * transmission order. parse_hops reverses them: seq=0 is the claimed origin,
 * the highest seq is final delivery. The bottom-most IP is NOT the origin --
 * an attacker forges every hop below the first server we control, so we resolve
 * a trust boundary and report the earliest hop we can authenticate.
 */

import { config } from '../config';
import { Analyzer, clear, triggered, type Evidence } from '../schemas/evidence';
import { HopTrust, headerValues, type Hop, type ParsedEmail } from '../schemas/email';
import { register } from './base';
import { cleanIp, ipInCidrs, isUnroutableIp, parseCidr } from './ip';

const FROM_RE = /\bfrom\s+([A-Za-z0-9._-]+)?\s*(?:\((?:([A-Za-z0-9._-]+)\s*)?\[([0-9a-fA-F:.]+)\]\))?/i;
const BY_RE = /\bby\s+([A-Za-z0-9._-]+)/i;
const WITH_RE = /\bwith\s+([A-Za-z0-9]+)/i;
const BARE_IP_RE = /\[([0-9a-fA-F:.]+)\]/;
const REPLY_PREFIX_RE = /^\s*(re|fwd|fw)\s*(\[\d+\])?\s*:/i;

export function parseHops(email: ParsedEmail): Hop[] {
  const received = headerValues(email, 'received');
  const hops: Hop[] = [];

  [...received].reverse().forEach((raw, seq) => {
    const flat = raw.replace(/\s+/g, ' ').trim();

    let fromHost: string | null = null;
    let fromIp: string | null = null;
    let rdns: string | null = null;
    const m = FROM_RE.exec(flat);
    if (m) {
      fromHost = (m[1] || '').trim() || null;
      fromIp = m[3] || null;
      rdns = m[2] || null;
    }
    if (fromIp === null) {
      const seg = flat.includes(' by ') ? flat.split(' by ')[0] : flat;
      const bare = BARE_IP_RE.exec(seg);
      fromIp = bare ? bare[1] : null;
    }

    const by = BY_RE.exec(flat);
    const proto = WITH_RE.exec(flat);

    let ts: string | null = null;
    if (flat.includes(';')) {
      const d = new Date(flat.split(';').pop()!.trim());
      if (!Number.isNaN(d.getTime())) ts = d.toISOString();
    }

    const hop: Hop = {
      seq,
      raw,
      from_host: fromHost,
      from_ip: cleanIp(fromIp),
      by_host: by ? by[1] : null,
      by_ip: null,
      protocol: proto ? proto[1].toUpperCase() : null,
      timestamp: ts,
      trust: HopTrust.UNVERIFIED,
      anomalies: [],
      geo: null,
    };
    if (rdns && hop.from_host === null) hop.from_host = rdns;
    hops.push(hop);
  });

  return hops;
}

/**
 * Mark each hop TRUSTED / BOUNDARY / UNVERIFIED and return the boundary hop.
 * Walk from final delivery (highest seq) downwards through hosts we can
 * authenticate; the trusted run must be contiguous from the top. The lowest
 * trusted hop is the BOUNDARY -- the IP it received from is the defensible origin.
 */
export function resolveTrustBoundary(
  hops: Hop[],
  trustedHosts: Set<string>,
  trustedCidrs: string[],
): Hop | null {
  for (const h of hops) h.trust = HopTrust.UNVERIFIED;
  if (!hops.length) return null;

  const hosts = new Set([...trustedHosts].map((h) => h.trim().toLowerCase()).filter(Boolean));
  const nets = trustedCidrs.map(parseCidr).filter((n): n is NonNullable<typeof n> => n !== null);

  const trustworthy = (hop: Hop): boolean => {
    if (hop.by_host && hosts.has(hop.by_host.trim().toLowerCase())) return true;
    if (hop.from_ip) return ipInCidrs(hop.from_ip, nets);
    return false;
  };

  let boundary: Hop | null = null;
  for (const hop of [...hops].sort((a, b) => b.seq - a.seq)) {
    if (!trustworthy(hop)) break;
    hop.trust = HopTrust.TRUSTED;
    boundary = hop;
  }

  if (boundary === null) return null;
  boundary.trust = HopTrust.BOUNDARY;
  return boundary;
}

/** Parse the chain and resolve the boundary from configured infra. Shared by M3/M5/M7. */
export function authenticatedOrigin(email: ParsedEmail): { boundary: Hop | null; hops: Hop[] } {
  const hops = parseHops(email);
  const boundary = resolveTrustBoundary(hops, config.trustedHosts(), config.trustedCidrs());
  return { boundary, hops };
}

function domainOf(addr: string | null): string | null {
  if (!addr || !addr.includes('@')) return null;
  return addr.split('@').pop()!.trim().toLowerCase();
}

export async function analyze(caseId: string, email: ParsedEmail): Promise<Evidence[]> {
  const ev: Evidence[] = [];
  const hops = parseHops(email);
  const boundary = resolveTrustBoundary(hops, config.trustedHosts(), config.trustedCidrs());

  // forged Received hop below the boundary (unroutable IP = positive injection proof)
  const forgedSeqs = new Set<number>();
  if (boundary !== null) {
    const injected = hops.filter((h) => h.seq < boundary.seq && isUnroutableIp(h.from_ip));
    if (injected.length) {
      injected.forEach((h) => forgedSeqs.add(h.seq));
      const seqs = [...forgedSeqs].sort((a, b) => a - b);
      ev.push(
        triggered(caseId, Analyzer.M2_HEADERS, 'forged_received_hop', {
          injected_hops: seqs,
          boundary_seq: boundary.seq,
          authenticated_origin: boundary.from_ip,
          claimed_origin: hops[0]?.from_ip ?? null,
          explanation:
            `Hop(s) ${JSON.stringify(seqs)} sit below the trust boundary (hop ${boundary.seq}, the last relay ` +
            `we can authenticate) and carry unroutable IPs, so they were injected. The defensible origin is ` +
            `${boundary.from_ip} at hop ${boundary.seq}, not the claimed ${hops[0]?.from_ip ?? 'unknown'}.`,
        }),
      );
    }
  }
  if (!forgedSeqs.size) ev.push(clear(caseId, Analyzer.M2_HEADERS, 'forged_received_hop'));

  // private/reserved IP where a public relay should be (skip already-forged hops)
  const privateHit = hops.find((h) => isUnroutableIp(h.from_ip) && !forgedSeqs.has(h.seq));
  if (privateHit) {
    ev.push(
      triggered(caseId, Analyzer.M2_HEADERS, 'private_ip_in_public_chain', {
        hop: privateHit.seq,
        ip: privateHit.from_ip,
        explanation:
          'A private or reserved address cannot appear in legitimate public transit; this hop was almost certainly injected.',
      }),
    );
  } else {
    ev.push(clear(caseId, Analyzer.M2_HEADERS, 'private_ip_in_public_chain'));
  }

  // timestamps running backwards
  const stamped = hops.filter((h) => h.timestamp);
  let regressed: [Hop, Hop] | null = null;
  for (let i = 0; i + 1 < stamped.length; i++) {
    if (new Date(stamped[i + 1].timestamp!) < new Date(stamped[i].timestamp!)) {
      regressed = [stamped[i], stamped[i + 1]];
      break;
    }
  }
  if (regressed) {
    ev.push(
      triggered(caseId, Analyzer.M2_HEADERS, 'timestamp_regression', {
        hop: regressed[1].seq,
        after_hop: regressed[0].seq,
        explanation: 'A later hop is dated earlier than the hop before it, which is physically impossible.',
      }),
    );
  } else {
    ev.push(clear(caseId, Analyzer.M2_HEADERS, 'timestamp_regression'));
  }

  // BEC reply-diversion triangle
  const fromDom = domainOf(email.from_addr);
  const replyDom = domainOf(email.reply_to);
  if (fromDom && replyDom && fromDom !== replyDom) {
    ev.push(
      triggered(caseId, Analyzer.M2_HEADERS, 'reply_to_domain_mismatch', {
        from_domain: fromDom,
        reply_to_domain: replyDom,
        explanation: 'Replies would be delivered to a different domain than the apparent sender.',
      }),
    );
  } else {
    ev.push(clear(caseId, Analyzer.M2_HEADERS, 'reply_to_domain_mismatch'));
  }

  // a "Re:" that replies to nothing
  const subject = (email.subject || '').trim();
  if (REPLY_PREFIX_RE.test(subject)) {
    const names = new Set(email.headers.map(([k]) => k.toLowerCase()));
    if (!names.has('in-reply-to') && !names.has('references')) {
      ev.push(
        triggered(caseId, Analyzer.M2_HEADERS, 'fake_reply', {
          subject: subject.slice(0, 120),
          explanation:
            'Subject claims to be a reply/forward but the message carries no In-Reply-To or References header, so it replies to no real thread.',
        }),
      );
    } else {
      ev.push(clear(caseId, Analyzer.M2_HEADERS, 'fake_reply'));
    }
  } else {
    ev.push(clear(caseId, Analyzer.M2_HEADERS, 'fake_reply'));
  }

  return ev;
}

register(Analyzer.M2_HEADERS, analyze);
