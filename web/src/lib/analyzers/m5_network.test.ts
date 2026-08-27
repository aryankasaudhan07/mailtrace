import { describe, it, expect, beforeAll } from 'vitest';
import { join } from 'node:path';
import { parseEmail } from '../ingest/parser';
import { Status } from '../schemas/evidence';
import { analyze } from './m5_network';

beforeAll(() => {
  process.env.INTEL_DIR = join(process.cwd(), 'test/fixtures/intel');
});

// single hop received by the trusted fixture MX -> boundary = that hop
const withOrigin = (ip: string, from = 'sender@corp.example') =>
  Buffer.from(
    `From: ${from}\r\n` +
      'Subject: hi\r\n' +
      `Received: from relay.example ([${ip}]) by mx.example.ac.in with ESMTPS; Tue, 26 Aug 2026 10:00:00 +0000\r\n` +
      '\r\nhello\r\n',
  );

describe('M5 network intelligence (offline fixture intel)', () => {
  it('flags a Tor exit at the authenticated origin (confidence 1.0)', async () => {
    const email = await parseEmail(withOrigin('185.220.101.1'));
    const ev = await analyze('c', email);
    const anon = ev.find((e) => e.signal === 'origin_anonymized' && e.status === Status.TRIGGERED);
    expect(anon).toBeTruthy();
    expect(anon!.detail.classification).toBe('Tor exit node');
    expect(anon!.confidence).toBe(1.0);
  });

  it('flags a datacenter-hosted origin', async () => {
    const email = await parseEmail(withOrigin('45.55.1.2'));
    const ev = await analyze('c', email);
    expect(ev.find((e) => e.signal === 'origin_datacenter_hosted')?.status).toBe(Status.TRIGGERED);
  });

  it('records provider_withholds_origin for webmail with no routable hop', async () => {
    const email = await parseEmail(Buffer.from('From: someone@gmail.com\r\nSubject: hi\r\n\r\nhello\r\n'));
    const ev = await analyze('c', email);
    const p = ev.find((e) => e.signal === 'provider_withholds_origin');
    expect(p?.status).toBe(Status.TRIGGERED);
    expect(p?.detail.provider).toBe('gmail.com');
  });

  it('a clean public origin yields a CLEAR', async () => {
    const email = await parseEmail(withOrigin('203.0.113.44')); // doc range, public, not tor/dc
    const ev = await analyze('c', email);
    expect(ev.find((e) => e.signal === 'origin_anonymized')?.status).toBe(Status.CLEAR);
  });
});
