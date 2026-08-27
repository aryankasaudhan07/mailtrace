import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { __resetStore } from './store';
import {
  analyzeAndStore, getCase, caseDetail, caseTrace, caseEvidence, caseArtifacts, caseListItem, buildStats,
} from './case-service';

const bec = () => readFileSync(join(process.cwd(), 'test/fixtures/bec.eml'));

beforeAll(() => { process.env.INTEL_DIR = join(process.cwd(), 'test/fixtures/intel'); });
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
    expect(art.ips.some((i) => i.ip === '203.0.113.44')).toBe(true);
    expect(art.urls[0]).toHaveProperty('display');

    const item = caseListItem(rec!);
    expect(item.score).toBe(res.verdict.score);
  }, 20000);

  it('buildStats aggregates stored cases', async () => {
    await analyzeAndStore(bec(), 'bec.eml');
    const stats = await buildStats();
    expect(stats.total).toBe(1);
    expect(stats.trend).toHaveLength(7);
    expect(stats.recent.length).toBe(1);
  }, 20000);
});
