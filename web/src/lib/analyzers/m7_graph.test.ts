import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseEmail } from '../ingest/parser';
import { Status } from '../schemas/evidence';
import { __resetStore } from '../store';
import { analyze, extractIndicators, registrableDomain } from './m7_graph';

const fixture = (name: string) => readFileSync(join(process.cwd(), 'test/fixtures', name));

beforeEach(() => __resetStore());

describe('M7 correlation', () => {
  it('eTLD+1 handles two-label public suffixes', () => {
    expect(registrableDomain('login.mail.evil.co.in')).toBe('evil.co.in');
    expect(registrableDomain('a.b.evil.com')).toBe('evil.com');
    expect(registrableDomain('localhost')).toBeNull();
  });

  it('correlates on the authenticated origin IP, not the sender domain', async () => {
    const email = await parseEmail(fixture('bec.eml'));
    const ind = extractIndicators(email);
    expect(ind.ip).toContain('203.0.113.44'); // boundary origin, not the claimed 10.0.0.5
    expect(ind.ip).not.toContain('10.0.0.5');
  });

  it('first case is clean; a second case sharing infrastructure is flagged', async () => {
    const a = await parseEmail(fixture('bec.eml'));
    const first = await analyze('case-1', a);
    expect(first.find((e) => e.signal === 'campaign_infrastructure_reuse')?.status).toBe(Status.CLEAR);

    const b = await parseEmail(fixture('bec.eml')); // same infrastructure
    const second = await analyze('case-2', b);
    const reuse = second.find((e) => e.signal === 'campaign_infrastructure_reuse');
    expect(reuse?.status).toBe(Status.TRIGGERED);
    expect(reuse!.detail.shared_indicator_count as number).toBeGreaterThanOrEqual(1);
  });

  it('unrelated cases do not correlate', async () => {
    await analyze('case-1', await parseEmail(fixture('bec.eml')));
    const benign = await analyze('case-2', await parseEmail(fixture('benign.eml')));
    const reuse = benign.find((e) => e.signal === 'campaign_infrastructure_reuse');
    // benign shares no attack infrastructure with the BEC case
    expect(reuse?.status).toBe(Status.CLEAR);
  });
});
