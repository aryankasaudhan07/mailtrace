/**
 * Case service: the upload -> parse -> run all analyzers -> score -> persist
 * pipeline (mirrors app/api/cases.py create_case), plus serializers that emit
 * the exact JSON shapes the frontend already consumes.
 */

import { createHash, randomUUID } from 'node:crypto';
import { runAll } from './analyzers/index';
import { parseHops, resolveTrustBoundary } from './analyzers/m2_headers';
import { isPublicIp } from './analyzers/ip';
import { config } from './config';
import { parseEmail } from './ingest/parser';
import { scoreCase } from './scoring/engine';
import type { Evidence } from './schemas/evidence';
import type { Attachment, ExtractedUrl, Hop, ParsedEmail } from './schemas/email';
import type { Verdict } from './schemas/verdict';
import { caseIdBySha, getCase, indexSha, listCases, saveCase, type StoredCase } from './store';

export interface CaseRecord extends StoredCase {
  filename: string | null;
  sha256: string;
  size_bytes: number;
  subject: string | null;
  from_addr: string | null;
  from_display_name: string | null;
  reply_to: string | null;
  return_path: string | null;
  to_addrs: string[];
  message_id: string | null;
  date: string | null;
  body_format: string;
  headers: Array<[string, string]>;
  urls: ExtractedUrl[];
  attachments: Attachment[];
  hops: Hop[];
  evidence: Evidence[];
  verdict: Verdict;
  raw: string;
}

function toRecord(caseId: string, email: ParsedEmail, hops: Hop[], evidence: Evidence[], verdict: Verdict, filename: string | null): CaseRecord {
  return {
    case_id: caseId,
    analyzed_at: new Date().toISOString(),
    filename,
    sha256: email.sha256,
    size_bytes: email.rawBytes.length,
    subject: email.subject,
    from_addr: email.from_addr,
    from_display_name: email.from_display_name,
    reply_to: email.reply_to,
    return_path: email.return_path,
    to_addrs: email.to_addrs,
    message_id: email.message_id,
    date: email.date,
    body_format: email.body_html ? 'HTML' : 'Plain text',
    headers: email.headers,
    urls: email.urls,
    attachments: email.attachments,
    hops,
    evidence,
    verdict,
    raw: email.rawBytes.toString('utf-8').slice(0, 20000),
  };
}

/** Analyze a raw email, persist the case, and return the POST /api/cases body. */
export async function analyzeAndStore(raw: Buffer, filename: string | null): Promise<{ case_id: string; filename: string | null; sha256: string; verdict: Verdict }> {
  // Idempotency: identical bytes -> the same case/verdict every time. This makes
  // re-analysis deterministic and stops a file from self-correlating as a
  // campaign with its own prior uploads (and freezes any network-lane wobble).
  const sha = createHash('sha256').update(raw).digest('hex');
  const existingId = await caseIdBySha(sha);
  if (existingId) {
    const prior = await getCase(existingId);
    if (prior) {
      const r = prior as CaseRecord;
      return { case_id: r.case_id, filename: r.filename, sha256: sha, verdict: r.verdict };
    }
  }

  const caseId = randomUUID();
  const email = await parseEmail(raw);
  const evidence = await runAll(caseId, email);
  const verdict = scoreCase(caseId, evidence);

  const hops = parseHops(email);
  resolveTrustBoundary(hops, config.trustedHosts(), config.trustedCidrs());

  await saveCase(toRecord(caseId, email, hops, evidence, verdict, filename));
  await indexSha(sha, caseId);
  return { case_id: caseId, filename, sha256: email.sha256, verdict };
}

// --- serializers (match app/api/cases.py) -----------------------------------

const rec = (c: StoredCase) => c as CaseRecord;

export function caseDetail(c: StoredCase) {
  const r = rec(c);
  const stamped = r.hops.map((h) => h.timestamp).filter((t): t is string => !!t);
  const receivedAt = stamped.length ? stamped.reduce((a, b) => (a > b ? a : b)) : null;
  return {
    case_id: r.case_id,
    sha256: r.sha256,
    subject: r.subject,
    from_addr: r.from_addr,
    from_display_name: r.from_display_name,
    reply_to: r.reply_to,
    return_path: r.return_path,
    to_addr: r.to_addrs[0] ?? null,
    message_id: r.message_id,
    size_bytes: r.size_bytes,
    body_format: r.body_format,
    received_at: receivedAt,
    url_count: r.urls.length,
    attachment_count: r.attachments.length,
    verdict: r.verdict,
    // M8 sender-footprint detail (informational CLEAR evidence, so it never
    // reaches the frontend via scored contributions -- surface it here).
    footprint: (r.evidence.find((e) => e.signal === 'sender_email_footprint' || e.signal === 'sender_no_footprint')?.detail ?? null) as Record<string, unknown> | null,
  };
}

export function caseTrace(c: StoredCase) {
  const r = rec(c);
  return {
    case_id: r.case_id,
    hops: r.hops,
    boundary_seq: r.hops.find((h) => h.trust === 'BOUNDARY')?.seq ?? null,
  };
}

export function caseEvidence(c: StoredCase) {
  const r = rec(c);
  return { case_id: r.case_id, records: r.evidence };
}

export function caseHeaders(c: StoredCase) {
  const r = rec(c);
  const byRaw = new Map<string, Hop>(r.hops.map((h) => [h.raw, h]));
  // Received values carry only the value part; match against hop.raw which holds
  // the full folded header line as parsed.
  return {
    case_id: r.case_id,
    headers: r.headers.map(([name, value]) => {
      const hop = [...byRaw.values()].find((h) => h.raw.includes(value) && name.toLowerCase() === 'received');
      return { name, value, hop: hop?.seq ?? null, trust: hop?.trust ?? null };
    }),
  };
}

export function caseArtifacts(c: StoredCase) {
  const r = rec(c);
  const ips: Array<{ ip: string; hop: number; trust: string }> = [];
  const seen = new Set<string>();
  for (const h of r.hops) {
    if (h.from_ip && !seen.has(h.from_ip)) {
      seen.add(h.from_ip);
      ips.push({ ip: h.from_ip, hop: h.seq, trust: h.trust });
    }
  }
  const fromDomain = r.from_addr?.split('@').pop()?.toLowerCase() ?? null;
  const urlDomains = r.urls.map((u) => u.domain).filter((d): d is string => !!d);
  const domains = [...new Set([...urlDomains, ...(fromDomain ? [fromDomain] : [])])].sort();
  const emails = [...new Set([r.from_addr, r.reply_to, r.return_path].filter((x): x is string => !!x))].sort();
  const attachments = r.attachments;
  return {
    case_id: r.case_id,
    ips,
    domains,
    urls: r.urls.map((u) => ({ url: u.url, domain: u.domain, display: u.display_text, shortened: u.is_shortened, mismatched: u.mismatched_anchor })),
    emails,
    hashes: attachments.map((a) => a.sha256),
    attachments,
    raw: r.raw,
  };
}

export function caseListItem(c: StoredCase) {
  const r = rec(c);
  // authenticated origin (boundary hop), else the earliest routable hop
  const boundaryHop = r.hops.find((h) => h.trust === 'BOUNDARY');
  const originIp =
    boundaryHop && isPublicIp(boundaryHop.from_ip)
      ? boundaryHop.from_ip
      : r.hops.find((h) => isPublicIp(h.from_ip))?.from_ip ?? null;
  return {
    case_id: r.case_id,
    subject: r.subject || r.filename || '(no subject)',
    from_addr: r.from_addr,
    score: r.verdict.score,
    band: r.verdict.band,
    confidence: r.verdict.confidence,
    analyzed_at: r.analyzed_at,
    attachments: r.attachments.length,
    urls: r.urls.length,
    origin_ip: originIp,
  };
}

// --- stats (match app/api/insights.py) --------------------------------------

const TYPE: Record<string, string> = {
  payment_diversion_intent: 'BEC', executive_impersonation: 'BEC',
  credential_harvest_intent: 'Phishing', classifier_phishing_high: 'Phishing',
  brand_lookalike_domain: 'Phishing', fake_reply: 'Phishing',
  hidden_text_mismatch: 'Injection',
  forged_received_hop: 'Spoofing', private_ip_in_public_chain: 'Spoofing',
  spf_fail_hard: 'Spoofing', dmarc_fail_strict: 'Spoofing',
  origin_anonymized: 'Anonymized', campaign_infrastructure_reuse: 'Campaign',
};
const BUCKET: Record<string, string> = { CRITICAL: 'critical', HIGH_RISK: 'high', SUSPICIOUS: 'medium', BENIGN: 'low' };

function threatType(v: Verdict): string {
  const pos = v.contributions.filter((c) => c.points > 0).sort((a, b) => b.points - a.points);
  for (const c of pos) if (TYPE[c.signal]) return TYPE[c.signal];
  return pos.length ? 'Suspicious' : 'Clean';
}

export async function buildStats() {
  const cases = (await listCases(1000)).map(rec);
  const total = cases.length;
  const bands: Record<string, number> = {};
  const buckets: Record<string, number> = {};
  const types: Record<string, number> = {};
  for (const c of cases) {
    bands[c.verdict.band] = (bands[c.verdict.band] ?? 0) + 1;
    const b = BUCKET[c.verdict.band] ?? 'low';
    buckets[b] = (buckets[b] ?? 0) + 1;
    if (c.verdict.score > 0) {
      const t = threatType(c.verdict);
      types[t] = (types[t] ?? 0) + 1;
    }
  }

  const day = (iso: string) => iso.slice(0, 10);
  const today = new Date();
  const trendDays: string[] = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(today);
    d.setUTCDate(d.getUTCDate() - i);
    trendDays.push(d.toISOString().slice(0, 10));
  }
  const trend = trendDays.map((d) => ({ day: d, critical: 0, high: 0, medium: 0, low: 0 }));
  const trendByDay = new Map(trend.map((t) => [t.day, t]));
  for (const c of cases) {
    const t = trendByDay.get(day(c.analyzed_at));
    if (t) t[(BUCKET[c.verdict.band] ?? 'low') as 'critical' | 'high' | 'medium' | 'low'] += 1;
  }

  const recent = [...cases]
    .sort((a, b) => (a.analyzed_at < b.analyzed_at ? 1 : -1))
    .slice(0, 6)
    .map((c) => ({ case_id: c.case_id, subject: c.subject || c.filename || '(no subject)', band: c.verdict.band, score: c.verdict.score, analyzed_at: c.analyzed_at }));

  const threat_types = Object.entries(types).sort((a, b) => b[1] - a[1]);
  return { total, buckets, bands, threat_types, trend, recent };
}

export { getCase, listCases };
