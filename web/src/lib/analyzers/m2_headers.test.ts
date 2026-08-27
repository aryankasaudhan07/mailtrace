import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseEmail } from '../ingest/parser';
import { Status } from '../schemas/evidence';
import { HopTrust } from '../schemas/email';
import { isUnroutableIp, isPublicIp } from './ip';
import { parseHops, resolveTrustBoundary, authenticatedOrigin, analyze } from './m2_headers';

const fixture = (name: string) => readFileSync(join(process.cwd(), 'test/fixtures', name));

describe('IP classification (documentation ranges must pass as public)', () => {
  it('RFC 1918 / CGNAT / loopback are unroutable', () => {
    expect(isUnroutableIp('10.0.0.5')).toBe(true);
    expect(isUnroutableIp('192.168.1.9')).toBe(true);
    expect(isUnroutableIp('172.16.4.4')).toBe(true);
    expect(isUnroutableIp('100.64.0.1')).toBe(true);
    expect(isUnroutableIp('127.0.0.1')).toBe(true);
  });
  it('RFC 5737 documentation ranges are treated as public', () => {
    expect(isUnroutableIp('198.51.100.77')).toBe(false);
    expect(isUnroutableIp('203.0.113.44')).toBe(false);
    expect(isUnroutableIp('192.0.2.1')).toBe(false);
    expect(isPublicIp('203.0.113.44')).toBe(true);
  });
  it('real public and invalid inputs', () => {
    expect(isPublicIp('8.8.8.8')).toBe(true);
    expect(isUnroutableIp('not-an-ip')).toBe(false);
    expect(isUnroutableIp(null)).toBe(false);
  });
});

describe('M2 trust boundary on bec.eml', () => {
  it('reverses hops so seq 0 is the claimed origin', async () => {
    const email = await parseEmail(fixture('bec.eml'));
    const hops = parseHops(email);
    expect(hops.length).toBe(4);
    expect(hops[0].from_ip).toBe('10.0.0.5'); // claimed origin, injected private IP
    expect(hops[3].by_host).toBe('mx.example.ac.in'); // final delivery
  });

  it('resolves the boundary to the last hop received by trusted infra', async () => {
    const email = await parseEmail(fixture('bec.eml'));
    const hops = parseHops(email);
    const boundary = resolveTrustBoundary(hops, new Set(['mx.example.ac.in']), []);
    expect(boundary).not.toBeNull();
    expect(boundary!.seq).toBe(2);
    expect(boundary!.from_ip).toBe('203.0.113.44'); // defensible origin
    expect(boundary!.trust).toBe(HopTrust.BOUNDARY);
    expect(hops[3].trust).toBe(HopTrust.TRUSTED);
    expect(hops[0].trust).toBe(HopTrust.UNVERIFIED); // below the boundary
  });

  it('returns null boundary when no hop is received by trusted infra', async () => {
    const email = await parseEmail(fixture('bec.eml'));
    const hops = parseHops(email);
    expect(resolveTrustBoundary(hops, new Set(['not-our-mx.example']), [])).toBeNull();
  });

  it('analyze: names the forged hop and the defensible origin', async () => {
    const email = await parseEmail(fixture('bec.eml'));
    const ev = await analyze('c', email);
    const forged = ev.find((e) => e.signal === 'forged_received_hop');
    expect(forged?.status).toBe(Status.TRIGGERED);
    expect(forged?.detail.authenticated_origin).toBe('203.0.113.44');
    expect(forged?.detail.boundary_seq).toBe(2);
    expect(forged?.detail.injected_hops).toContain(0);

    // the doc-range hop (198.51.100.77) must NOT be double-counted as private
    const priv = ev.find((e) => e.signal === 'private_ip_in_public_chain');
    expect(priv?.status).toBe(Status.CLEAR);

    // reply-to diverges from From
    const reply = ev.find((e) => e.signal === 'reply_to_domain_mismatch');
    expect(reply?.status).toBe(Status.TRIGGERED);
  });

  it('authenticatedOrigin uses configured infra (default fixture MX)', async () => {
    const email = await parseEmail(fixture('bec.eml'));
    const { boundary } = authenticatedOrigin(email);
    expect(boundary?.from_ip).toBe('203.0.113.44');
  });
});

describe('M2 on benign.eml stays clean', () => {
  it('no forgery / private-IP / reply mismatch on the control', async () => {
    const email = await parseEmail(fixture('benign.eml'));
    const ev = await analyze('c', email);
    for (const sig of ['forged_received_hop', 'private_ip_in_public_chain', 'reply_to_domain_mismatch']) {
      const e = ev.find((x) => x.signal === sig);
      expect(e?.status, sig).toBe(Status.CLEAR);
    }
  });
});
