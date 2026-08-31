/**
 * Case service: the upload -> parse -> run all analyzers -> score -> persist
 * pipeline (mirrors app/api/cases.py create_case), plus serializers that emit
 * the exact JSON shapes the frontend already consumes.
 */

import { createHash, randomUUID } from 'node:crypto';
import { runAll } from './analyzers/index';
import { parseHops, resolveTrustBoundary } from './analyzers/m2_headers';
import { isPublicIp } from './analyzers/ip';
import { registrableDomain } from './analyzers/m7_graph';
import { config } from './config';
import { parseEmail } from './ingest/parser';
import { loadRules, scoreCase } from './scoring/engine';
import type { Evidence } from './schemas/evidence';
import type { Attachment, ExtractedUrl, Hop, ParsedEmail } from './schemas/email';
import type { Verdict } from './schemas/verdict';
import { allIndicators, caseIdBySha, getCase, indexSha, listCases, saveCase, type StoredCase } from './store';
import { DEFAULT_OWNER, runAsOwner } from './owner-context';

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

function toRecord(caseId: string, email: ParsedEmail, hops: Hop[], evidence: Evidence[], verdict: Verdict, filename: string | null, owner: string): CaseRecord {
  return {
    case_id: caseId,
    analyzed_at: new Date().toISOString(),
    owner,
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

/** Analyze a raw email, persist the case, and return the POST /api/cases body.
 *  All storage and M7 correlation is scoped to `owner` (the uploading user). */
export async function analyzeAndStore(raw: Buffer, filename: string | null, owner: string = DEFAULT_OWNER): Promise<{ case_id: string; filename: string | null; sha256: string; verdict: Verdict }> {
  return runAsOwner(owner, async () => {
    // Idempotency: identical bytes -> the same case/verdict every time, WITHIN
    // this owner. This makes re-analysis deterministic and stops a file from
    // self-correlating as a campaign with its own prior uploads (and freezes any
    // network-lane wobble). A different user's identical upload is independent.
    const sha = createHash('sha256').update(raw).digest('hex');
    const currentVersion = loadRules().version;
    let caseId: string = randomUUID();
    const existingId = await caseIdBySha(sha, owner);
    if (existingId) {
      const prior = await getCase(existingId);
      if (prior) {
        const r = prior as CaseRecord;
        // Return the cache only when it was scored by the CURRENT rules. A version
        // mismatch (e.g. a case stored before a new analyzer/weight shipped) is
        // stale, so re-analyze it in place -- reusing the same case_id keeps links
        // stable and avoids a duplicate History entry.
        if (r.verdict.scorer_version === currentVersion) {
          return { case_id: r.case_id, filename: r.filename, sha256: sha, verdict: r.verdict };
        }
        caseId = existingId;
      }
    }

    const email = await parseEmail(raw);
    const evidence = await runAll(caseId, email); // M7 correlates within `owner` via ALS
    const verdict = scoreCase(caseId, evidence);

    const hops = parseHops(email);
    resolveTrustBoundary(hops, config.trustedHosts(), config.trustedCidrs());

    await saveCase(toRecord(caseId, email, hops, evidence, verdict, filename, owner));
    await indexSha(sha, caseId, owner);
    return { case_id: caseId, filename, sha256: email.sha256, verdict };
  });
}

/** Fetch a case only if it belongs to `owner`; otherwise null (isolation). */
export async function getOwnedCase(id: string, owner: string): Promise<StoredCase | null> {
  const c = await getCase(id);
  if (!c) return null;
  const o = (c as CaseRecord).owner;
  return o === owner ? c : null;
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

export async function buildStats(owner: string = DEFAULT_OWNER) {
  const cases = (await listCases(1000, owner)).map(rec);
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

// ---- graph / campaign correlation (ported from app/api/cases.py graph routes
//      + app/graph/relationships.py) --------------------------------------------

/** Case <-> indicator graph for the Threat Intelligence dashboard. */
export async function caseGraph(owner: string = DEFAULT_OWNER) {
  const cases = (await listCases(1000, owner)).map((c) => {
    const r = rec(c);
    return {
      case_id: r.case_id,
      score: r.verdict.score,
      band: r.verdict.band,
      confidence: r.verdict.confidence,
      subject: r.subject,
      from_addr: r.from_addr,
    };
  });
  const edges = await allIndicators(owner);
  return { cases, edges };
}

// Relationship strength by indicator kind (mirrors relationships.py).
const IND_WEIGHT: Record<string, number> = { ip: 0.8, urlreg: 0.5, url: 0.4, hash: 0.3 };

/** Campaign clusters: connected components of cases sharing infrastructure. */
export async function campaignClusters(owner: string = DEFAULT_OWNER) {
  const edges = await allIndicators(owner);

  // case -> set of "kind:value" indicators
  const indForCase = new Map<string, Set<string>>();
  // "kind:value" -> set of case ids
  const casesForInd = new Map<string, Set<string>>();
  for (const e of edges) {
    const key = `${e.kind}:${e.value}`;
    (indForCase.get(e.case_id) ?? indForCase.set(e.case_id, new Set()).get(e.case_id)!).add(key);
    (casesForInd.get(key) ?? casesForInd.set(key, new Set()).get(key)!).add(e.case_id);
  }

  // adjacency: two cases are linked if they share any indicator
  const adj = new Map<string, Set<string>>();
  for (const cids of casesForInd.values()) {
    if (cids.size < 2) continue;
    const arr = [...cids];
    for (const a of arr) {
      const set = adj.get(a) ?? adj.set(a, new Set()).get(a)!;
      for (const b of arr) if (a !== b) set.add(b);
    }
  }

  const kindOf = (ind: string) => ind.slice(0, ind.indexOf(':'));
  const valOf = (ind: string) => ind.slice(ind.indexOf(':') + 1);

  const visited = new Set<string>();
  const clusters: Array<{ cluster_id: string; size: number; cases: string[]; core_indicators: Record<string, string[]>; cohesion_score: string }> = [];
  let cid = 0;

  for (const start of adj.keys()) {
    if (visited.has(start)) continue;
    // BFS connected component
    const comp: string[] = [];
    const queue = [start];
    visited.add(start);
    while (queue.length) {
      const cur = queue.shift()!;
      comp.push(cur);
      for (const nb of adj.get(cur) ?? []) if (!visited.has(nb)) { visited.add(nb); queue.push(nb); }
    }
    if (comp.length < 2) continue;

    // core indicators = union across the cluster
    const core: Record<string, Set<string>> = {};
    for (const c of comp) for (const ind of indForCase.get(c) ?? []) {
      (core[kindOf(ind)] ??= new Set()).add(valOf(ind));
    }
    // cohesion = mean pairwise shared-indicator strength
    let strengthSum = 0, pairs = 0;
    for (let i = 0; i < comp.length; i++) for (let j = i + 1; j < comp.length; j++) {
      const A = indForCase.get(comp[i]) ?? new Set<string>();
      const B = indForCase.get(comp[j]) ?? new Set<string>();
      const shared = [...A].filter((x) => B.has(x));
      if (shared.length) {
        strengthSum += Math.min(1, shared.reduce((s, ind) => s + (IND_WEIGHT[kindOf(ind)] ?? 0.1), 0) / 2);
        pairs += 1;
      }
    }
    const cohesion = pairs ? strengthSum / pairs : 0;
    clusters.push({
      cluster_id: `campaign_${cid++}`,
      size: comp.length,
      cases: comp.sort(),
      core_indicators: Object.fromEntries(Object.entries(core).map(([k, v]) => [k, [...v]])),
      cohesion_score: cohesion.toFixed(2),
    });
  }
  clusters.sort((a, b) => b.size - a.size);
  return { cluster_count: clusters.length, clusters };
}

/**
 * Typed entity-relationship graph for the Graph tab: links cases to their
 * sender domains, IP addresses, email aliases (from / reply-to / return-path),
 * shared infrastructure (URL domains, attachment hashes) and reply chains
 * (In-Reply-To / References -> a prior case's Message-ID). Two cases touching
 * the same entity node are visibly related.
 */
export async function caseEntityGraph(caseIds?: string[], owner: string = DEFAULT_OWNER) {
  const pick = caseIds && caseIds.length ? new Set(caseIds) : null;
  const cases = (await listCases(5000, owner)).map(rec).filter((r) => !pick || pick.has(r.case_id));
  const nodes = new Map<string, { id: string; type: string; label: string; score?: number; band?: string }>();
  const links: Array<{ source: string; target: string; rel: string }> = [];

  const addNode = (id: string, type: string, label: string, extra: { score?: number; band?: string } = {}) => {
    if (!nodes.has(id)) nodes.set(id, { id, type, label, ...extra });
    return id;
  };
  const domainOf = (a: string | null) => (a && a.includes('@') ? a.split('@').pop()!.toLowerCase() : null);
  const headerVal = (r: CaseRecord, name: string) =>
    (r.headers || []).find(([k]) => k.toLowerCase() === name)?.[1] || '';

  // message-id -> case, for reply-chain edges
  const midToCase = new Map<string, string>();
  for (const r of cases) if (r.message_id) midToCase.set(r.message_id.trim(), r.case_id);

  for (const r of cases) {
    const cid = addNode(r.case_id, 'case', r.subject || '(no subject)', { score: r.verdict.score, band: r.verdict.band });

    const alias = (addr: string | null, rel: string) => {
      if (!addr) return;
      const a = `alias:${addr.toLowerCase()}`;
      addNode(a, 'alias', addr.toLowerCase());
      links.push({ source: cid, target: a, rel });
      const d = domainOf(addr);
      if (d) { const dn = `domain:${d}`; addNode(dn, 'domain', d); links.push({ source: a, target: dn, rel: 'domain' }); }
    };
    alias(r.from_addr, 'from');
    alias(r.reply_to, 'reply-to');
    alias(r.return_path, 'return-path');

    for (const h of r.hops || []) {
      if (h.from_ip && isPublicIp(h.from_ip)) {
        const ip = `ip:${h.from_ip}`;
        addNode(ip, 'ip', h.from_ip);
        links.push({ source: cid, target: ip, rel: h.trust === 'BOUNDARY' ? 'origin' : 'relay' });
      }
    }
    for (const u of r.urls || []) {
      const host = (u.domain || '').toLowerCase();
      if (!host) continue;
      const reg = registrableDomain(host) || host;
      const n = `infra:${reg}`;
      addNode(n, 'infra', reg);
      links.push({ source: cid, target: n, rel: 'link' });
    }
    for (const at of r.attachments || []) {
      if (!at.sha256) continue;
      const n = `hash:${at.sha256}`;
      addNode(n, 'hash', at.filename || at.sha256.slice(0, 10));
      links.push({ source: cid, target: n, rel: 'attachment' });
    }
    // reply chains
    const refs = `${headerVal(r, 'in-reply-to')} ${headerVal(r, 'references')}`.match(/<[^>]+>/g) || [];
    for (const mid of refs) {
      const other = midToCase.get(mid.trim());
      if (other && other !== r.case_id) links.push({ source: cid, target: other, rel: 'reply-chain' });
    }
  }

  // dedupe links
  const seen = new Set<string>();
  const uniq = links.filter((l) => {
    const k = `${l.source}|${l.target}|${l.rel}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return { nodes: [...nodes.values()], links: uniq };
}

export { getCase, listCases };
