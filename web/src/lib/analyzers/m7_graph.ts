/**
 * M7 -- correlation and campaign clustering (ported from app/analyzers/m7_graph.py).
 *
 * An edge exists when two cases share an indicator; connected components are
 * campaigns. Correlate ONLY on attack infrastructure the attacker provisions and
 * reuses -- the authenticated origin IP, URL hosts/registrable domains, and
 * attachment hashes -- NEVER the sender's own domain (every org reuses its
 * sending domain, which would make all its mail look like one campaign).
 */

import { Analyzer, clear, triggered, unavailable, type Evidence } from '../schemas/evidence';
import type { ParsedEmail } from '../schemas/email';
import { register } from './base';
import { authenticatedOrigin } from './m2_headers';
import { isPublicIp } from './ip';
import { findRelatedCases, storeIndicators, type Indicators } from '../store';

const PUBLIC_PROVIDERS = new Set([
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com',
  'msn.com', 'yahoo.com', 'ymail.com', 'proton.me', 'protonmail.com',
  'icloud.com', 'me.com', 'aol.com', 'zoho.com', 'gmx.com', 'mail.com',
]);
const TWO_LABEL_SUFFIXES = new Set([
  'co.in', 'ac.in', 'gov.in', 'org.in', 'net.in', 'edu.in', 'res.in', 'nic.in',
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'co.jp', 'com.br',
]);

export function registrableDomain(host: string): string | null {
  const labels = host.toLowerCase().replace(/^\.+|\.+$/g, '').split('.');
  if (labels.length < 2) return null;
  const lastTwo = labels.slice(-2).join('.');
  const take = TWO_LABEL_SUFFIXES.has(lastTwo) ? 3 : 2;
  if (labels.length < take) return null;
  return labels.slice(-take).join('.');
}

export function extractIndicators(email: ParsedEmail): Indicators {
  const ind: Indicators = { ip: new Set(), url: new Set(), urlreg: new Set(), hash: new Set() };

  // authenticated origin only (the one relay IP an attacker cannot forge);
  // fall back to every routable hop when no boundary resolves.
  const { boundary, hops } = authenticatedOrigin(email);
  if (boundary && isPublicIp(boundary.from_ip)) {
    ind.ip.add(boundary.from_ip!);
  } else {
    for (const h of hops) if (isPublicIp(h.from_ip)) ind.ip.add(h.from_ip!);
  }

  for (const u of email.urls) {
    if (u.domain) {
      const host = u.domain.toLowerCase();
      ind.url.add(host);
      const reg = registrableDomain(host);
      if (reg && !PUBLIC_PROVIDERS.has(reg)) ind.urlreg.add(reg);
    }
  }

  for (const a of email.attachments) if (a.sha256) ind.hash.add(a.sha256);

  // drop empty kinds
  const out: Indicators = {};
  for (const [kind, values] of Object.entries(ind)) if (values.size) out[kind] = values;
  return out;
}

export async function analyze(caseId: string, email: ParsedEmail): Promise<Evidence[]> {
  try {
    const indicators = extractIndicators(email);
    const extracted = Object.values(indicators).reduce((n, s) => n + s.size, 0);

    if (!extracted) {
      return [clear(caseId, Analyzer.M7_GRAPH, 'campaign_infrastructure_reuse', {
        summary: 'No indicators extracted from email.',
      })];
    }

    const related = await findRelatedCases(indicators); // query BEFORE storing self
    delete related[caseId]; // a case never correlates with its own prior indicators (safe re-analysis)
    const counts = Object.values(related);
    const ev: Evidence[] = [];

    if (counts.length) {
      const shared = Math.max(...counts);
      ev.push(
        triggered(caseId, Analyzer.M7_GRAPH, 'campaign_infrastructure_reuse', {
          summary: `Shared ${shared} indicators with prior case(s).`,
          related_cases: Object.keys(related).length,
          shared_indicator_count: shared,
          indicators_extracted: extracted,
        }, Math.min(1.0, shared / 5.0)),
      );
    } else {
      ev.push(clear(caseId, Analyzer.M7_GRAPH, 'campaign_infrastructure_reuse', {
        summary: 'No shared indicators with prior cases.',
        indicators_extracted: extracted,
      }));
    }

    await storeIndicators(caseId, indicators);
    return ev;
  } catch (e) {
    const err = e as Error;
    return [unavailable(caseId, Analyzer.M7_GRAPH, 'campaign_infrastructure_reuse', `Store unavailable: ${err?.name ?? 'Error'}`)];
  }
}

register(Analyzer.M7_GRAPH, analyze);
