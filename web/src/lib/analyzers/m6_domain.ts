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
  // Exact hyphen/underscore/dot-delimited parts, NOT length-filtered -- so a
  // short brand core like "sbi" (3 chars, dropped by tokens()) is still caught
  // as an exact standalone token, e.g. sbi-secure-login.com.
  const nonTldParts = new Set(nonTld.join('.').replace(/[-_]/g, '.').split('.').filter(Boolean));
  const sig = nonTld.reduce((a, b) => (b.length > a.length ? b : a), '');
  const homographed = uni !== raw || raw.includes('xn--') || [...raw].some((c) => c.charCodeAt(0) > 127);

  for (const brand of PROTECTED_BRANDS) {
    const b = brand.toLowerCase();
    const bSkel = skeleton(b);
    const bCore = bSkel.split('.')[0];

    if (skel === bSkel) return [brand, homographed ? 'homograph' : 'typosquat'];

    if (nonTld.includes(bCore) || nonTldTokens.has(bCore) || (bCore.length >= 3 && nonTldParts.has(bCore))) {
      return [brand, 'brand-name-in-domain'];
    }

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

const DNS_NET_ERRORS = new Set(['EAI_AGAIN', 'ETIMEOUT', 'ETIMEDOUT', 'ESERVFAIL', 'ECONNREFUSED', 'ECONNRESET', 'ENETUNREACH', 'ENOTIMP']);
function isDnsNetworkError(e: unknown): boolean {
  const code = (e as { code?: string })?.code;
  return code ? DNS_NET_ERRORS.has(code) : false;
}

// --- RDAP domain age ---------------------------------------------------------
// `unavailable` = we could not reach RDAP (offline / timeout / server error),
// so age is unknown and MUST surface as UNAVAILABLE, not as a silent "not new".
// A definitive 404 (domain not in RDAP / unsupported TLD) is `ageDays: null`
// WITHOUT unavailable — age simply unknown, no network fault.
export interface DomainAge { ageDays: number | null; unavailable: boolean }

export async function domainAgeDays(domain: string, timeoutMs = 4000): Promise<DomainAge> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      signal: ctrl.signal,
      headers: { accept: 'application/rdap+json' },
    });
    if (res.status >= 500) return { ageDays: null, unavailable: true }; // RDAP server error
    if (!res.ok) return { ageDays: null, unavailable: false };          // 404 etc: age simply unknown
    const data = (await res.json()) as { events?: Array<{ eventAction?: string; eventDate?: string }> };
    const reg = (data.events ?? []).find((e) => e.eventAction === 'registration');
    if (!reg?.eventDate) return { ageDays: null, unavailable: false };
    const created = new Date(reg.eventDate);
    if (Number.isNaN(created.getTime())) return { ageDays: null, unavailable: false };
    return { ageDays: Math.floor((Date.now() - created.getTime()) / 86_400_000), unavailable: false };
  } catch {
    return { ageDays: null, unavailable: true }; // network error / abort (timeout): unreachable
  } finally {
    clearTimeout(timer);
  }
}

// `dnsDown` = the resolver itself was unreachable (offline / transient), which is
// NOT the same as a domain that genuinely has no A/MX records.
async function checkDns(domain: string): Promise<{ hasMx: boolean; hasA: boolean; dnsDown: boolean }> {
  let hasMx = false;
  let hasA = false;
  let dnsDown = false;
  try {
    hasMx = (await resolveMx(domain)).length > 0;
  } catch (e) {
    if (isDnsNetworkError(e)) dnsDown = true; // else: genuinely no MX
  }
  try {
    hasA = (await resolve4(domain)).length > 0;
  } catch (e) {
    if (isDnsNetworkError(e)) dnsDown = true; // else: genuinely no A
  }
  return { hasMx, hasA, dnsDown };
}

export async function analyze(caseId: string, email: ParsedEmail): Promise<Evidence[]> {
  const ev: Evidence[] = [];
  const fromDomain = email.from_addr ? email.from_addr.split('@').pop()!.toLowerCase() : null;
  if (!fromDomain) {
    return [unavailable(caseId, Analyzer.M6_DOMAIN, 'domain_age_lt_30d', 'No From domain found')];
  }

  const { ageDays, unavailable: ageDown } = await domainAgeDays(fromDomain);
  if (ageDown) {
    ev.push(unavailable(caseId, Analyzer.M6_DOMAIN, 'domain_age_lt_30d',
      `Registration age for ${fromDomain} could not be retrieved (RDAP unreachable) — a newly-registered domain cannot be ruled out.`));
  } else if (ageDays !== null && ageDays < 30) {
    ev.push(
      triggered(caseId, Analyzer.M6_DOMAIN, 'domain_age_lt_30d', {
        age_days: ageDays,
        explanation: `Domain registered only ${ageDays} days ago — common phishing pattern.`,
      }),
    );
  }

  const { hasMx, hasA, dnsDown } = await checkDns(fromDomain);
  if (dnsDown) {
    // Resolver unreachable (offline / transient): do NOT fabricate no-MX /
    // does-not-resolve for every domain (that was flagging even the benign
    // control offline). Surface it as UNAVAILABLE, not a definite finding.
    ev.push(unavailable(caseId, Analyzer.M6_DOMAIN, 'domain_does_not_resolve',
      `DNS for ${fromDomain} could not be resolved (resolver unreachable) — resolve/MX state unknown.`));
  } else {
    if (!hasMx) {
      ev.push(
        triggered(caseId, Analyzer.M6_DOMAIN, 'domain_no_mx', {
          domain: fromDomain,
          explanation: 'No MX (mail server) records found — domain is not configured to receive email.',
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
    // Reached only when nothing triggered AND nothing was unavailable, i.e. the
    // checks actually ran. Don't assert "not new" unless age was determined.
    const ageNote = ageDays !== null ? `${ageDays}d old` : 'age not in RDAP';
    ev.push(
      clear(caseId, Analyzer.M6_DOMAIN, 'domain_age_lt_30d', {
        domain: fromDomain,
        explanation: `Domain resolves with a valid MX record and is not a brand lookalike (${ageNote}).`,
      }),
    );
  }

  return ev;
}

register(Analyzer.M6_DOMAIN, analyze);
