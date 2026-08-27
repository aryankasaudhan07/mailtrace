import { describe, it, expect } from 'vitest';
import { Analyzer, Status, triggered, type Evidence } from '../schemas/evidence';
import type { ParsedEmail } from '../schemas/email';
import { register, runAll } from './base';

const email = { from_addr: 'x@y.example' } as unknown as ParsedEmail;

describe('analyzer framework', () => {
  it('flattens evidence from all lanes and converts failures to evidence', async () => {
    register(Analyzer.M2_HEADERS, async (cid) => [triggered(cid, Analyzer.M2_HEADERS, 'forged_received_hop')]);
    register(Analyzer.M3_AUTH, async () => {
      throw new Error('boom');
    });
    register(Analyzer.M4_CONTENT, async (): Promise<Evidence[]> => {
      await new Promise((r) => setTimeout(r, 500));
      return [];
    });

    const ev = await runAll('c1', email, 60); // 60ms timeout forces M4 to time out

    const m2 = ev.find((e) => e.analyzer === Analyzer.M2_HEADERS);
    expect(m2?.status).toBe(Status.TRIGGERED);

    const m3 = ev.find((e) => e.analyzer === Analyzer.M3_AUTH);
    expect(m3?.status).toBe(Status.ERROR); // a thrown lane -> ERROR, never breaks the run

    const m4 = ev.find((e) => e.analyzer === Analyzer.M4_CONTENT);
    expect(m4?.status).toBe(Status.UNAVAILABLE); // a slow lane -> UNAVAILABLE
    expect(m4?.signal).toBe('lane_timeout');
  });
});
