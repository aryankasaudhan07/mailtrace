/**
 * M6 -- domain intelligence (ported from app/analyzers/m6_domain.py).
 *
 * Domain age is the single most predictive cheap feature in phishing. Uses RDAP
 * (over HTTPS) not port-43 WHOIS. Brand-lookalike detection folds Unicode
 * confusables and punycode to a Latin "skeleton" so homographs collapse onto the
 * brand they mimic; the fuzzy typosquat check uses a normalized-Indel ratio
 * equivalent to rapidfuzz.fuzz.ratio.
 */

import { resolveMx, resolve4 } from 'node:dns/promises';
import { domainToUnicode } from 'node:url';
import { Analyzer, clear, triggered, unavailable, type Evidence } from '../schemas/evidence';
import type { ParsedEmail } from '../schemas/email';
import { register } from './base';

const PROTECTED_BRANDS = [
  'aicte-india.org',
  'sbi.co.in',
  'onlinesbi.sbi',
  'incometax.gov.in',
  'npci.org.in',
];

// Unicode look-alikes folded to their Latin twin.
const CONFUSABLES: Record<string, string> = {
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', х: 'x', у: 'y',
  ѕ: 's', і: 'i', ј: 'j', н: 'h', к: 'k', м: 'm', т: 't', в: 'b',
  ο: 'o', α: 'a', ε: 'e', ρ: 'p', τ: 't', ν: 'v', ι: 'i', κ: 'k',
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't',
};

function fold(s: string): string {
  let out = '';
  for (const ch of s) out += CONFUSABLES[ch] ?? ch;
  return out;
}

function decodeIdna(domain: string): string {
  if (!domain.includes('xn--')) return domain;
  try {
    return domainToUnicode(domain) || domain;
  } catch {
    return domain;
  }
}

function skeleton(s: string): string {
  return fold(s.normalize('NFKC').toLowerCase());
}

function tokens(skel: string): Set<string> {
  const out = new Set<string>();
  for (const part of skel.replace(/-/g, '.').split('.')) {
    if (part.length >= 4) out.add(part);
  }
  return out;
}

/** rapidfuzz.fuzz.ratio == normalized Indel similarity == 200*LCS/(len1+len2). */
export function fuzzRatio(a: string, b: string): number {
  if (!a.length && !b.length) return 100;
  const m = a.length;
  const n = b.length;
  const dp = new Array(n + 1).fill(0);
  for (let i = 1; i <= m; i++) {
    let prev = 0;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      dp[j] = a[i - 1] === b[j - 1] ? prev + 1 : Math.max(dp[j], dp[j - 1]);
      prev = tmp;
    }
  }
  const lcs = dp[n];
  return (200 * lcs) / (m + n);
}

export function checkBrandLookalike(domain: string): [string, string] | null {
  const raw = domain.toLowerCase().replace(/^\.+|\.+$/g, '');

  for (const brand of PROTECTED_BRANDS) {
    const b = brand.toLowerCase();
    if (raw === b || raw.endsWith('.' + b)) return null; // is (a subdomain of) the real brand
  }

  const uni = decodeIdna(raw);
  const skel = skeleton(uni);
  const labels = skel.split('.');
  const nonTld = labels.length > 1 ? labels.slice(0, -1) : labels;
  const nonTldTokens = tokens(nonTld.join('.'));
  const sig = nonTld.reduce((a, b) => (b.length > a.length ? b : a), '');
  const homographed = uni !== raw || raw.includes('xn--') || [...raw].some((c) => c.charCodeAt(0) > 127);

  for (const brand of PROTECTED_BRANDS) {
    const b = brand.toLowerCase();
    const bSkel = skeleton(b);
    const bCore = bSkel.split('.')[0];

    if (skel === bSkel) return [brand, homographed ? 'homograph' : 'typosquat'];

    if (nonTld.includes(bCore) || nonTldTokens.has(bCore)) return [brand, 'brand-name-in-domain'];

    if (bCore.length >= 4) {
      if (fuzzRatio(sig, bCore) >= 82) return [brand, homographed ? 'homograph' : 'typosquat'];
      const brandTokens = tokens(bCore).size ? tokens(bCore) : new Set([bCore]);
      for (const bt of brandTokens) {
        if (bt.length >= 5 && [...nonTldTokens].some((t) => fuzzRatio(t, bt) >= 85)) {
          return [brand, 'typosquat'];
        }
      }
    }
  }
  return null;
}

// --- RDAP domain age ---------------------------------------------------------
export async function domainAgeDays(domain: string, timeoutMs = 4000): Promise<number | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      signal: ctrl.signal,
      headers: { accept: 'application/rdap+json' },
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { events?: Array<{ eventAction?: string; eventDate?: string }> };
    const reg = (data.events ?? []).find((e) => e.eventAction === 'registration');
    if (!reg?.eventDate) return null;
    const created = new Date(reg.eventDate);
    if (Number.isNaN(created.getTime())) return null;
    return Math.floor((Date.now() - created.getTime()) / 86_400_000);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function checkDns(domain: string): Promise<{ hasMx: boolean; hasA: boolean }> {
  let hasMx = false;
  let hasA = false;
  try {
    const mx = await resolveMx(domain);
    hasMx = mx.length > 0;
  } catch {
    /* no MX */
  }
  try {
    const a = await resolve4(domain);
    hasA = a.length > 0;
  } catch {
    /* no A */
  }
  return { hasMx, hasA };
}

export async function analyze(caseId: string, email: ParsedEmail): Promise<Evidence[]> {
  const ev: Evidence[] = [];
  const fromDomain = email.from_addr ? email.from_addr.split('@').pop()!.toLowerCase() : null;
  if (!fromDomain) {
    return [unavailable(caseId, Analyzer.M6_DOMAIN, 'domain_age_lt_30d', 'No From domain found')];
  }

  const age = await domainAgeDays(fromDomain);
  if (age !== null && age < 30) {
    ev.push(
      triggered(caseId, Analyzer.M6_DOMAIN, 'domain_age_lt_30d', {
        age_days: age,
        explanation: `Domain registered only ${age} days ago — common phishing pattern.`,
      }),
    );
  }

  const { hasMx, hasA } = await checkDns(fromDomain);
  if (!hasMx) {
    ev.push(
      triggered(caseId, Analyzer.M6_DOMAIN, 'domain_no_mx', {
        domain: fromDomain,
        explanation: 'No MX (mail server) records found — domain is not properly configured to send email.',
      }),
    );
  }
  if (!hasA) {
    ev.push(
      triggered(caseId, Analyzer.M6_DOMAIN, 'domain_does_not_resolve', {
        domain: fromDomain,
        explanation: 'Domain does not resolve (no A record) — possibly abandoned or spoofed.',
      }),
    );
  }

  const lookalike = checkBrandLookalike(fromDomain);
  if (lookalike) {
    const [brand, technique] = lookalike;
    const reasons: Record<string, string> = {
      homograph: `uses look-alike characters to imitate '${brand}'`,
      typosquat: `is a near-misspelling of protected brand '${brand}'`,
      'brand-name-in-domain': `places the protected brand '${brand}' in a domain it does not own`,
    };
    ev.push(
      triggered(caseId, Analyzer.M6_DOMAIN, 'brand_lookalike_domain', {
        domain: fromDomain,
        similar_to: brand,
        technique,
        explanation: `Domain '${fromDomain}' ${reasons[technique] ?? 'imitates a protected brand'}.`,
      }),
    );
  }

  if (!ev.length) {
    ev.push(
      clear(caseId, Analyzer.M6_DOMAIN, 'domain_age_lt_30d', {
        domain: fromDomain,
        explanation: 'Domain appears legitimate (not new, has MX records, resolves, not a lookalike).',
      }),
    );
  }

  return ev;
}

register(Analyzer.M6_DOMAIN, analyze);
