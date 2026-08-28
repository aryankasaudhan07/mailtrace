import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { analyze, breachPlatforms } from './m8_footprint';
import { Analyzer, Status } from '../schemas/evidence';
import type { ParsedEmail } from '../schemas/email';

// Minimal ParsedEmail stub — M8 only reads from_addr.
function email(from: string | null): ParsedEmail {
  return { from_addr: from } as unknown as ParsedEmail;
}

const CID = 'case-m8';

beforeEach(() => {
  // offline: no network. M8 uses only REAL sources, so with no network there is
  // no footprint to report (the disposable check still runs offline).
  process.env.M8_ENUM_ONLINE = '0';
});
afterEach(() => {
  delete process.env.M8_ENUM_ONLINE;
});

describe('M8 sender email footprint (real sources only)', () => {
  it('flags a disposable / temp-mail sender domain (offline, scored)', async () => {
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

  it('stays NEUTRAL (CLEAR, no fabricated footprint) when there is no network', async () => {
    const ev = await analyze(CID, email('alice@gmail.com'));
    const foot = ev.find((e) => e.signal === 'sender_email_footprint' || e.signal === 'sender_no_footprint');
    expect(foot?.status).toBe(Status.CLEAR); // neutral -> never lowers confidence / adds points
    // and M8 emits no UNAVAILABLE (which would penalise confidence)
    expect(ev.some((e) => e.status === Status.UNAVAILABLE)).toBe(false);
  });

  it('grants NO legitimacy credit without real evidence (offline)', async () => {
    const ev = await analyze(CID, email('alice@gmail.com'));
    expect(ev.some((e) => ['established_sender_identity', 'known_footprint_sender'].includes(e.signal))).toBe(false);
  });

  it('stays NEUTRAL (CLEAR) when there is no sender address', async () => {
    const ev = await analyze(CID, email(null));
    expect(ev).toHaveLength(1);
    expect(ev[0].status).toBe(Status.CLEAR);
    expect(ev[0].signal).toBe('sender_no_footprint');
  });

  it('never throws — always returns evidence', async () => {
    await expect(analyze(CID, email('weird-no-at-sign'))).resolves.toBeInstanceOf(Array);
  });
});

describe('breachPlatforms — real breach names become platform registrations', () => {
  it('keeps real platforms and drops combolist / data-broker dumps', () => {
    const hits = breachPlatforms([
      'LinkedIn', 'Adobe', 'Canva', 'Collection1', 'AntiPublic',
      'People Data Labs', 'Dropbox', 'LinkedIn', 'Naz.API', 'Twitter',
    ]);
    const platforms = hits.map((h) => h.platform);
    expect(platforms).toContain('LinkedIn');
    expect(platforms).toContain('Adobe');
    expect(platforms).toContain('Dropbox');
    expect(platforms).toContain('Twitter');
    // aggregators excluded
    expect(platforms).not.toContain('Collection1');
    expect(platforms).not.toContain('AntiPublic');
    expect(platforms).not.toContain('People Data Labs');
    expect(platforms).not.toContain('Naz.API');
    // de-duplicated + all real
    expect(platforms.filter((p) => p === 'LinkedIn')).toHaveLength(1);
    expect(hits.every((h) => h.simulated === false && h.status === 'registered')).toBe(true);
  });
});
