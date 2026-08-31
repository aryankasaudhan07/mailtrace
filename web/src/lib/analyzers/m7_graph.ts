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
// Common link/ESP/CDN hosts (registrable domains) that many unrelated messages
// legitimately point at — correlating on these manufactures false "campaigns".
const COMMON_LINK_HOSTS = new Set([
  // shorteners / redirectors
  'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'buff.ly', 'lnkd.in', 'rebrand.ly', 'cutt.ly',
  // big platforms / CDNs
  'google.com', 'youtube.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
  'twitter.com', 'linkedin.com', 'github.com', 'dropbox.com', 'notion.so', 'slack.com', 'zoom.us',
  // ESP / bulk-mail link + tracking hosts
  'sendgrid.net', 'mailchimp.com', 'list-manage.com', 'sparkpostmail.com', 'amazonses.com',
  'mandrillapp.com', 'hubspotemail.net', 'cmail1.com', 'cmail2.com', 'rs6.net', 'mailgun.org',
  'klaviyomail.com', 'sendgrid.com', 'exct.net', 'mcsv.net',
]);

import { registrableDomain } from './domains';
export { registrableDomain }; // re-exported for back-compat (m4_content imports it from here)

export function extractIndicators(email: ParsedEmail): Indicators {
  const ind: Indicators = { ip: new Set(), url: new Set(), urlreg: new Set(), hash: new Set() };

  // authenticated origin only (the one relay IP an attacker cannot forge).
  // When no boundary resolves, correlate on ONLY the earliest routable hop (the
  // claimed origin) -- adding every hop would link unrelated mail that merely
  // transited a shared provider/relay IP (Google/Microsoft outbound) as a "campaign".
  const { boundary, hops } = authenticatedOrigin(email);
  if (boundary && isPublicIp(boundary.from_ip)) {
    ind.ip.add(boundary.from_ip!);
  } else {
    const originHop = hops.find((h) => isPublicIp(h.from_ip));
    if (originHop) ind.ip.add(originHop.from_ip!);
  }

  for (const u of email.urls) {
    if (!u.domain) continue;
    const host = u.domain.toLowerCase();
    const reg = registrableDomain(host);
    // Skip shorteners, CDNs, big platforms and ESP link/tracking hosts: many
    // unrelated messages point at these, so correlating on them is a false campaign.
    if (reg && (PUBLIC_PROVIDERS.has(reg) || COMMON_LINK_HOSTS.has(reg))) continue;
    ind.url.add(host);
    if (reg) ind.urlreg.add(reg);
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
