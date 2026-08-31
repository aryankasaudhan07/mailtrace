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
import { arc as arcVerify } from 'mailauth/lib/arc';
import { Analyzer, Status, clear, triggered, unavailable, type Evidence } from '../schemas/evidence';
import { registrableDomain, sameOrgDomain } from './domains';
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
const DMARC_SP_RE = /[;\s]sp\s*=\s*(\w+)/i;
const DKIM_D_RE = /[;\s]d\s*=\s*([^;]+)/i;

export type TxtResolver = (name: string) => Promise<string[][]>;

function domainOf(addr: string | null): string {
  if (!addr || !addr.includes('@')) return '';
  return addr.split('@').pop()!.trim().toLowerCase().replace(/>$/, '');
}

/** DMARC relaxed alignment: identical, or the same registrable (organisational)
 *  domain per the Public Suffix List. Uses PSL private suffixes, so a signature
 *  from a shared platform (d=herokuapp.com) does NOT align with a tenant
 *  (From @victim.herokuapp.com) -- the naive suffix match used to. */
export function aligned(a: string, b: string): boolean {
  return sameOrgDomain(a, b);
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

  const fromDomain = domainOf(email.from_addr);
  let results: Array<{ signingDomain?: string; status?: { result?: string } }> = [];
  let threw = false;
  try {
    const res = await dkimVerify(email.rawBytes, resolver ? { resolver } : {});
    results = (res?.results ?? []) as Array<{ signingDomain?: string; status?: { result?: string } }>;
  } catch {
    threw = true;
  }

  // Only a signature whose d= ALIGNS with the From domain can authenticate this
  // message. A valid signature from an unrelated domain (attacker.com) must NOT
  // credit a From: victim.com message -- that was the cross-domain forgery gap.
  const domOf = (r: { signingDomain?: string }) => (r.signingDomain || '').toLowerCase();
  const alignedResults = results.filter((r) => aligned(domOf(r), fromDomain));
  const alignedHas = (result: string) => alignedResults.some((r) => r.status?.result === result);
  const alignedDom =
    alignedResults.find((r) => domOf(r))?.signingDomain
    ?? sigDomains.find((d) => aligned(d, fromDomain))
    ?? sigDomains[0];
  const alignedSigExists = sigDomains.some((d) => aligned(d, fromDomain));

  if (alignedHas('pass')) {
    return {
      ev: triggered(caseId, Analyzer.M3_AUTH, 'dkim_valid_aligned', {
        domain: alignedDom,
        explanation: `DKIM signature valid and d=${alignedDom} aligns with the From domain.`,
      }),
      pass: true,
    };
  }
  if (alignedSigExists) {
    // An aligned signature that could NOT be verified because the key/DNS lookup
    // failed (offline, temperror, or the whole verify threw, or mailauth produced
    // no result for it) is evidence-UNAVAILABLE -- never a silent fail or pass.
    if (threw || alignedHas('temperror') || alignedResults.length === 0) {
      return {
        ev: unavailable(caseId, Analyzer.M3_AUTH, 'dkim_unavailable',
          `DKIM for d=${alignedDom} could not be verified (offline or DNS/key lookup failed).`),
        pass: false,
      };
    }
    // Aligned signature present and evaluated, but not 'pass' (fail / neutral /
    // permerror = broken body hash or forged/altered signature): an integrity fail.
    return {
      ev: triggered(caseId, Analyzer.M3_AUTH, 'dkim_fail', {
        domain: alignedDom,
        explanation: `DKIM signature (d=${alignedDom}) failed verification — content was altered or the signature was forged.`,
      }),
      pass: false,
    };
  }
  return { ev: null, pass: false }; // only NON-aligned signatures (e.g. a valid attacker.com sig on a victim.com From): no credit, no penalty
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
    if (result === 'temperror' || result === 'permerror') {
      return {
        ev: unavailable(caseId, Analyzer.M3_AUTH, 'spf_unavailable',
          `SPF for ${mailFromDomain} could not be evaluated (${result} — DNS unreachable).`),
        pass: false,
      };
    }
    return { ev: null, pass: alignedPass };
  } catch (e) {
    if (isDnsNetworkError(e)) {
      return {
        ev: unavailable(caseId, Analyzer.M3_AUTH, 'spf_unavailable', 'SPF could not be evaluated (DNS unreachable).'),
        pass: false,
      };
    }
    return { ev: null, pass: false };
  }
}

// --- ARC ---------------------------------------------------------------------
// Verify the Authenticated Received Chain. cv=pass means each ARC hop validated
// the previous one, so the authentication results recorded before forwarding are
// trustworthy -- the legitimate reason a forwarded message fails SPF at the final
// hop. 'unavailable' = the ARC keys/DNS could not be reached (offline), so we
// must NOT use it to excuse an SPF failure.
export type ArcStatus = 'pass' | 'fail' | 'none' | 'unavailable';

export async function verifyArc(email: ParsedEmail, resolver?: (name: string, rr: string) => Promise<string[][]>): Promise<ArcStatus> {
  if (!email.rawBytes?.length) return 'none';
  try {
    const dk = await dkimVerify(email.rawBytes, resolver ? { resolver } : {});
    const chain = (dk as { arc?: { chain?: unknown[] } })?.arc;
    if (!chain || !Array.isArray(chain.chain) || chain.chain.length === 0) return 'none';
    const res = await arcVerify(chain as Parameters<typeof arcVerify>[0], resolver ? { resolver } : {});
    const r = (res as { status?: { result?: string } })?.status?.result;
    return r === 'pass' || r === 'fail' || r === 'none' ? r : 'none';
  } catch {
    return 'unavailable'; // ARC key lookup / DNS failed -- cannot confirm, so do not excuse SPF
  }
}

// --- DMARC -------------------------------------------------------------------
// A DNS resolver error that means "couldn't reach DNS" (offline / transient),
// as opposed to a definitive "no such record" (ENOTFOUND / ENODATA). The former
// must surface as UNAVAILABLE so a policy violation is never silently masked.
const DNS_NET_ERRORS = new Set(['EAI_AGAIN', 'ETIMEOUT', 'ETIMEDOUT', 'ESERVFAIL', 'ECONNREFUSED', 'ECONNRESET', 'ENETUNREACH', 'ENOTIMP']);
function isDnsNetworkError(e: unknown): boolean {
  const code = (e as { code?: string })?.code;
  return code ? DNS_NET_ERRORS.has(code) : false;
}

export interface DmarcLookup { policy: string | null; unavailable: boolean }

async function lookupDmarc(domain: string, txt: TxtResolver): Promise<{ found: boolean; p: string | null; sp: string | null; netErr: boolean }> {
  try {
    const records = await txt(`_dmarc.${domain}`);
    for (const rr of records) {
      const s = rr.join('');
      if (s.toLowerCase().startsWith('v=dmarc1')) {
        const pm = DMARC_P_RE.exec(s);
        const spm = DMARC_SP_RE.exec(s);
        return { found: true, p: pm ? pm[1].toLowerCase() : 'none', sp: spm ? spm[1].toLowerCase() : null, netErr: false };
      }
    }
    return { found: false, p: null, sp: null, netErr: false };
  } catch (e) {
    return { found: false, p: null, sp: null, netErr: isDnsNetworkError(e) };
  }
}

// DMARC record discovery per RFC 7489 / 9989: the EXACT From domain, then the
// organisational domain. A subdomain with no record of its own is governed by
// the org domain's sp= (subdomain policy) when present, else its p=. (No walk of
// arbitrary intermediate labels, which real DMARC does not consult.)
export async function dmarcPolicy(domain: string, txt: TxtResolver = defaultTxt): Promise<DmarcLookup> {
  if (!domain) return { policy: null, unavailable: false };
  const exact = await lookupDmarc(domain, txt);
  if (exact.found) return { policy: exact.p, unavailable: false };
  let netErr = exact.netErr;
  const org = registrableDomain(domain);
  if (org && org !== domain) {
    const orgRec = await lookupDmarc(org, txt);
    if (orgRec.found) return { policy: orgRec.sp ?? orgRec.p, unavailable: false };
    netErr = netErr || orgRec.netErr;
  }
  // No policy found. If DNS was actually unreachable we cannot conclude "no
  // policy"; report unavailable so the caller emits UNAVAILABLE, not a clean pass.
  return { policy: null, unavailable: netErr };
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
  const { policy, unavailable: dmarcDown } = await dmarcPolicy(fromDomain, txt);
  if (dmarcDown) {
    return unavailable(caseId, Analyzer.M3_AUTH, 'dmarc_unavailable',
      `DMARC policy for ${fromDomain} could not be retrieved (DNS unreachable) — a policy violation cannot be ruled out.`);
  }
  if (policy === null) return null; // no policy published: not a failure by itself
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
    spfPass = spfR.pass;
    if (spfR.ev?.signal === 'spf_fail_hard' && spfR.ev.status === Status.TRIGGERED) {
      // A hard SPF fail is the expected symptom of legitimate forwarding. Only
      // penalise it if a valid ARC chain does NOT vouch for the pre-forward auth.
      const arc = await verifyArc(email, dkimResolver);
      if (arc === 'pass') {
        ev.push(
          triggered(caseId, Analyzer.M3_AUTH, 'arc_authenticated', {
            explanation:
              'SPF failed at the receiving hop, but a valid ARC chain (cv=pass) shows the message was ' +
              'authenticated before it was forwarded — legitimate forwarding, not spoofing. SPF penalty suppressed.',
          }),
        );
      } else {
        ev.push(spfR.ev); // no valid ARC to excuse it — keep the SPF-fail penalty
      }
    } else if (spfR.ev) {
      ev.push(spfR.ev);
    }
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
