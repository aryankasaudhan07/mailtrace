/**
 * M3 -- SPF / DKIM / DMARC re-verification (ported from app/analyzers/m3_auth.py).
 *
 * Do NOT trust the Authentication-Results header -- below the trust boundary it
 * is attacker-supplied. Re-verify from rawBytes (kept by M1). DKIM is verified
 * cryptographically (offline-capable); SPF and DMARC need DNS and degrade to
 * "not checked" when unreachable, never to a guess.
 *
 * DMARC is a PASS/FAIL of alignment, never of policy strength: dmarc_fail_strict
 * fires only when auth actually fails alignment AND the domain published p=reject
 * or p=quarantine.
 */

import { resolveTxt } from 'node:dns/promises';
import { dkimVerify } from 'mailauth/lib/dkim/verify';
import { spf as mailauthSpf } from 'mailauth/lib/spf';
import { Analyzer, clear, triggered, type Evidence } from '../schemas/evidence';
import { headerValues, type ParsedEmail } from '../schemas/email';
import { register } from './base';
import { authenticatedOrigin } from './m2_headers';
import { DKIM_DEMO_KEYS } from './dkim_demo_keys';

// Resolver for DKIM key lookups: serve bundled demo keys locally (so the
// self-contained signed samples verify without DNS), else use real DNS.
export async function dkimResolver(name: string, rr: string): Promise<string[][]> {
  if (rr !== 'TXT') return [];
  // normalize: some runtimes hand the resolver an FQDN with a trailing dot / mixed case
  const key = name.replace(/\.$/, '').toLowerCase();
  if (DKIM_DEMO_KEYS[key]) return [[DKIM_DEMO_KEYS[key]]];
  try {
    return await resolveTxt(key);
  } catch {
    return [];
  }
}

const DMARC_P_RE = /[;\s]p\s*=\s*(\w+)/i;
const DKIM_D_RE = /[;\s]d\s*=\s*([^;]+)/i;

export type TxtResolver = (name: string) => Promise<string[][]>;

function domainOf(addr: string | null): string {
  if (!addr || !addr.includes('@')) return '';
  return addr.split('@').pop()!.trim().toLowerCase().replace(/>$/, '');
}

/** Relaxed alignment: same domain, or one is the other's organizational parent. */
export function aligned(a: string, b: string): boolean {
  if (!a || !b) return false;
  a = a.toLowerCase();
  b = b.toLowerCase();
  return a === b || a.endsWith('.' + b) || b.endsWith('.' + a);
}

export function dkimSigningDomains(email: ParsedEmail): string[] {
  const out: string[] = [];
  for (const v of headerValues(email, 'dkim-signature')) {
    const m = DKIM_D_RE.exec(v);
    if (m) out.push(m[1].trim().toLowerCase());
  }
  return out;
}

// --- DKIM --------------------------------------------------------------------
export async function verifyDkim(
  caseId: string,
  email: ParsedEmail,
  resolver?: (name: string, rr: string) => Promise<string[][]>,
): Promise<{ ev: Evidence | null; pass: boolean }> {
  if (!email.rawBytes || !email.rawBytes.length) return { ev: null, pass: false };
  const sigDomains = dkimSigningDomains(email);
  if (!sigDomains.length) return { ev: null, pass: false }; // unsigned: not scored

  let ok = false;
  try {
    const res = await dkimVerify(email.rawBytes, resolver ? { resolver } : {});
    const results = (res?.results ?? []) as Array<{ status?: { result?: string } }>;
    ok = results.some((r) => r.status?.result === 'pass');
  } catch {
    ok = false;
  }

  const d = sigDomains[0];
  const fromDomain = domainOf(email.from_addr);
  const isAligned = aligned(d, fromDomain);

  if (ok && isAligned) {
    return {
      ev: triggered(caseId, Analyzer.M3_AUTH, 'dkim_valid_aligned', {
        domain: d,
        explanation: `DKIM signature valid and d=${d} aligns with the From domain.`,
      }),
      pass: true,
    };
  }
  if (!ok) {
    return {
      ev: triggered(caseId, Analyzer.M3_AUTH, 'dkim_fail', {
        domain: d,
        explanation: `DKIM signature (d=${d}) failed cryptographic verification — content was altered or the signature was forged.`,
      }),
      pass: false,
    };
  }
  return { ev: null, pass: false }; // valid but not aligned: no credit, no penalty
}

// --- SPF ---------------------------------------------------------------------
export async function verifySpf(
  caseId: string,
  email: ParsedEmail,
  clientIp: string | null,
): Promise<{ ev: Evidence | null; pass: boolean }> {
  if (!clientIp) return { ev: null, pass: false };
  const mailFromDomain = domainOf(email.return_path) || domainOf(email.from_addr);
  if (!mailFromDomain) return { ev: null, pass: false };
  try {
    const res = await mailauthSpf({
      ip: clientIp,
      helo: mailFromDomain,
      sender: `user@${mailFromDomain}`,
      mta: 'mailtrace',
    });
    const result = (res?.status?.result ?? '').toLowerCase();
    const alignedPass = result === 'pass' && aligned(mailFromDomain, domainOf(email.from_addr));
    if (result === 'fail') {
      return {
        ev: triggered(caseId, Analyzer.M3_AUTH, 'spf_fail_hard', {
          ip: clientIp,
          domain: mailFromDomain,
          explanation: 'SPF hard fail: this IP is not authorized to send for the envelope-sender domain.',
        }),
        pass: alignedPass,
      };
    }
    return { ev: null, pass: alignedPass };
  } catch {
    return { ev: null, pass: false };
  }
}

// --- DMARC -------------------------------------------------------------------
export async function dmarcPolicy(domain: string, txt: TxtResolver = defaultTxt): Promise<string | null> {
  if (!domain) return null;
  const labels = domain.split('.');
  for (let i = 0; i < labels.length - 1; i++) {
    const candidate = labels.slice(i).join('.');
    try {
      const records = await txt(`_dmarc.${candidate}`);
      for (const rr of records) {
        const s = rr.join('');
        if (s.toLowerCase().startsWith('v=dmarc1')) {
          const m = DMARC_P_RE.exec(s);
          return m ? m[1].toLowerCase() : 'none';
        }
      }
    } catch {
      // continue walking up
    }
  }
  return null;
}

async function defaultTxt(name: string): Promise<string[][]> {
  return resolveTxt(name);
}

export async function verifyDmarc(
  caseId: string,
  email: ParsedEmail,
  authenticated: boolean,
  txt: TxtResolver = defaultTxt,
): Promise<Evidence | null> {
  const fromDomain = domainOf(email.from_addr);
  if (!fromDomain) return null;
  const policy = await dmarcPolicy(fromDomain, txt);
  if (policy === null) return null; // no policy reachable/published: not a failure by itself
  if ((policy === 'reject' || policy === 'quarantine') && !authenticated) {
    return triggered(caseId, Analyzer.M3_AUTH, 'dmarc_fail_strict', {
      domain: fromDomain,
      policy,
      explanation:
        `Neither SPF nor DKIM aligned with the From domain, and the domain's DMARC policy is p=${policy} — ` +
        'this message violates a policy the domain owner explicitly published.',
    });
  }
  return null;
}

export async function analyze(caseId: string, email: ParsedEmail): Promise<Evidence[]> {
  const ev: Evidence[] = [];

  const { boundary } = authenticatedOrigin(email);
  const clientIp = boundary?.from_ip ?? null;

  let spfPass = false;
  let dkimPass = false;

  try {
    const spfR = await verifySpf(caseId, email, clientIp);
    if (spfR.ev) ev.push(spfR.ev);
    spfPass = spfR.pass;
  } catch {
    /* SPF is best-effort; ignore */
  }

  const dkimR = await verifyDkim(caseId, email, dkimResolver);
  if (dkimR.ev) ev.push(dkimR.ev);
  dkimPass = dkimR.pass;

  try {
    const dmarcEv = await verifyDmarc(caseId, email, spfPass || dkimPass);
    if (dmarcEv) ev.push(dmarcEv);
  } catch {
    /* DMARC DNS best-effort */
  }

  const triggeredFindings = ev.filter((e) => e.signal !== 'dkim_valid_aligned');
  if (!triggeredFindings.length) {
    ev.push(
      clear(caseId, Analyzer.M3_AUTH, 'auth_verification_passed', {
        explanation:
          'No SPF/DKIM/DMARC alignment failures detected (re-verified from raw bytes; DNS-dependent checks skipped when unreachable).',
      }),
    );
  }

  return ev;
}

register(Analyzer.M3_AUTH, analyze);
