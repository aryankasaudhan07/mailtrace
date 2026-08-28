import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { __resetStore, saveCase } from './store';
import {
  analyzeAndStore, getCase, caseDetail, caseTrace, caseEvidence, caseArtifacts, caseListItem, buildStats, listCases,
  type CaseRecord,
} from './case-service';

const bec = () => readFileSync(join(process.cwd(), 'test/fixtures/bec.eml'));

beforeAll(() => {
  process.env.INTEL_DIR = join(process.cwd(), 'test/fixtures/intel');
  process.env.GEO_DISABLE_ONLINE = '1'; // keep the pipeline offline in tests
});
beforeEach(() => __resetStore());

describe('case-service pipeline', () => {
  it('analyzes, persists, and serializes a case', async () => {
    const res = await analyzeAndStore(bec(), 'bec.eml');
    expect(res.case_id).toBeTruthy();
    expect(res.sha256).toHaveLength(64);
    expect(res.verdict.score).toBeGreaterThanOrEqual(50); // M2 forged hop + reply-to mismatch
    expect(res.verdict.band === 'HIGH_RISK' || res.verdict.band === 'CRITICAL').toBe(true);

    const rec = await getCase(res.case_id);
    expect(rec).not.toBeNull();

    const detail = caseDetail(rec!);
    expect(detail.subject).toContain('vendor bank details');
    expect(detail.verdict.contributions.length).toBeGreaterThan(0);

    const trace = caseTrace(rec!);
    expect(trace.boundary_seq).toBe(2);
    expect(trace.hops).toHaveLength(4);

    const ev = caseEvidence(rec!);
    expect(ev.records.some((r) => r.signal === 'forged_received_hop' && r.status === 'TRIGGERED')).toBe(true);

    const art = caseArtifacts(rec!);
    expect(art.ips.some((i) => i.ip === '139.59.1.1')).toBe(true);
    expect(art.urls[0]).toHaveProperty('display');

    const item = caseListItem(rec!);
    expect(item.score).toBe(res.verdict.score);
  }, 20000);

  it('is idempotent: same bytes -> same case, same verdict, no self-correlation', async () => {
    const raw = bec();
    const a = await analyzeAndStore(raw, 'bec.eml');
    const b = await analyzeAndStore(raw, 'bec.eml');
    expect(b.case_id).toBe(a.case_id); // replayed, not re-created
    expect(b.verdict.score).toBe(a.verdict.score); // deterministic
    // a re-upload must not add a second case or fire campaign reuse against itself
    const list = await listCases(50);
    expect(list.length).toBe(1);
    const reuse = a.verdict.contributions.find((c) => c.signal === 'campaign_infrastructure_reuse');
    expect(reuse).toBeUndefined();
  }, 20000);

  it('re-analyzes in place when the cached verdict is from an older scorer version', async () => {
    const raw = bec();
    const a = await analyzeAndStore(raw, 'bec.eml');
    // doctor the stored case so it looks scored by an older ruleset
    const stored = (await getCase(a.case_id)) as unknown as CaseRecord;
    stored.verdict = { ...stored.verdict, scorer_version: '0.0.1', score: 999 };
    await saveCase(stored);
    const b = await analyzeAndStore(raw, 'bec.eml');
    expect(b.case_id).toBe(a.case_id); // re-analyzed in place, same id
    expect(b.verdict.scorer_version).not.toBe('0.0.1'); // re-scored with current rules
    expect(b.verdict.score).toBe(a.verdict.score); // real score, not the doctored 999
    const list = await listCases(50);
    expect(list.length).toBe(1); // no duplicate History entry
  }, 20000);

  it('buildStats aggregates stored cases', async () => {
    await analyzeAndStore(bec(), 'bec.eml');
    const stats = await buildStats();
    expect(stats.total).toBe(1);
    expect(stats.trend).toHaveLength(7);
    expect(stats.recent.length).toBe(1);
  }, 20000);
});
