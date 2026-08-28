import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { analyze } from './m8_footprint';
import { Analyzer, Status } from '../schemas/evidence';
import type { ParsedEmail } from '../schemas/email';

// Minimal ParsedEmail stub — M8 only reads from_addr.
function email(from: string | null): ParsedEmail {
  return { from_addr: from } as unknown as ParsedEmail;
}

const CID = 'case-m8';

beforeEach(() => {
  // deterministic + offline: no network, use the labelled simulated dataset
  process.env.M8_ENUM_ONLINE = '0';
  process.env.M8_DEMO = '1';
});
afterEach(() => {
  delete process.env.M8_ENUM_ONLINE;
  delete process.env.M8_DEMO;
});

describe('M8 sender email footprint', () => {
  it('flags a disposable / temp-mail sender domain (TRIGGERED, scored)', async () => {
    const ev = await analyze(CID, email('attacker@mailinator.com'));
    const disp = ev.find((e) => e.signal === 'disposable_sender_domain');
    expect(disp?.status).toBe(Status.TRIGGERED);
    expect(disp?.analyzer).toBe(Analyzer.M8_FOOTPRINT);
    expect((disp?.detail as { domain: string }).domain).toBe('mailinator.com');
  });

  it('does not flag a normal webmail sender as disposable', async () => {
    const ev = await analyze(CID, email('alice@gmail.com'));
    expect(ev.some((e) => e.signal === 'disposable_sender_domain')).toBe(false);
  });

  it('produces a footprint with the (labelled) simulated dataset', async () => {
    const ev = await analyze(CID, email('alice@gmail.com'));
    const foot = ev.find((e) => e.signal === 'sender_email_footprint');
    expect(foot?.status).toBe(Status.CLEAR);
    const d = foot!.detail as { registered_count: number; platforms: string[]; includes_simulated: boolean };
    expect(d.registered_count).toBeGreaterThan(0);
    expect(d.includes_simulated).toBe(true);
    expect(Array.isArray(d.platforms)).toBe(true);
  });

  it('is deterministic — same address yields the same simulated footprint', async () => {
    const a = await analyze(CID, email('someone@example.com'));
    const b = await analyze(CID, email('someone@example.com'));
    const pa = (a.find((e) => e.signal === 'sender_email_footprint')!.detail as { platforms: string[] }).platforms;
    const pb = (b.find((e) => e.signal === 'sender_email_footprint')!.detail as { platforms: string[] }).platforms;
    expect(pa).toEqual(pb);
  });

  it('returns UNAVAILABLE when offline and the demo dataset is disabled', async () => {
    process.env.M8_DEMO = '0';
    const ev = await analyze(CID, email('alice@gmail.com'));
    const foot = ev.find((e) => e.analyzer === Analyzer.M8_FOOTPRINT);
    expect(foot?.status).toBe(Status.UNAVAILABLE);
  });

  it('is UNAVAILABLE when there is no sender address', async () => {
    const ev = await analyze(CID, email(null));
    expect(ev).toHaveLength(1);
    expect(ev[0].status).toBe(Status.UNAVAILABLE);
  });

  it('never throws — always returns evidence', async () => {
    await expect(analyze(CID, email('weird-no-at-sign'))).resolves.toBeInstanceOf(Array);
  });
});
