import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { dkimSign } from 'mailauth/lib/dkim/sign';
import { parseEmail } from '../ingest/parser';
import { Status } from '../schemas/evidence';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { aligned, dkimSigningDomains, verifyDkim, dmarcPolicy, verifyDmarc, dkimResolver } from './m3_auth';

describe('M3 demo DKIM samples (bundled public key, no DNS)', () => {
  const sample = (n: string) => readFileSync(join(process.cwd(), 'public/samples', n));

  it('dkim-pass.eml verifies -> dkim_valid_aligned', async () => {
    const email = await parseEmail(sample('dkim-pass.eml'));
    const { ev, pass } = await verifyDkim('c', email, dkimResolver);
    expect(pass).toBe(true);
    expect(ev?.signal).toBe('dkim_valid_aligned');
  });

  it('dkim-fail.eml (tampered body) -> dkim_fail', async () => {
    const email = await parseEmail(sample('dkim-fail.eml'));
    const { ev, pass } = await verifyDkim('c', email, dkimResolver);
    expect(pass).toBe(false);
    expect(ev?.signal).toBe('dkim_fail');
  });
});

describe('M3 alignment + signing-domain parsing', () => {
  it('relaxed alignment', () => {
    expect(aligned('acme.example', 'acme.example')).toBe(true);
    expect(aligned('mail.acme.example', 'acme.example')).toBe(true);
    expect(aligned('acme.example', 'evil.example')).toBe(false);
    expect(aligned('', 'acme.example')).toBe(false);
  });
});

describe('M3 DKIM crypto (sign -> verify, offline via injected resolver)', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const pubB64 = (publicKey as unknown as Buffer).toString('base64');
  const selector = 'sel';
  const domain = 'acme.example';

  const body = [
    'From: CEO <ceo@acme.example>',
    'To: cfo@acme.example',
    'Subject: Q3 numbers',
    'Date: Tue, 26 Aug 2026 10:00:00 +0000',
    'Message-ID: <a@acme.example>',
    '',
    'Please review the attached figures.',
    '',
  ].join('\r\n');

  const resolver = async (name: string, rr: string): Promise<string[][]> => {
    if (rr === 'TXT' && name === `${selector}._domainkey.${domain}`) {
      return [[`v=DKIM1; k=rsa; p=${pubB64}`]];
    }
    throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
  };

  async function sign(raw: string): Promise<Buffer> {
    // mailauth accepts multi-signature `signatureData` at runtime; its published
    // type only describes the single-signature form, so cast the options.
    const opts = {
      canonicalization: 'relaxed/relaxed',
      signTime: new Date('2026-08-26T10:00:05Z'),
      signatureData: [{ signingDomain: domain, selector, privateKey: privateKey as unknown as string }],
    } as unknown as Parameters<typeof dkimSign>[1];
    const res = await dkimSign(raw, opts);
    return Buffer.concat([Buffer.from(res.signatures as string), Buffer.from(raw)]);
  }

  it('a valid aligned signature yields dkim_valid_aligned', async () => {
    const signed = await sign(body);
    const email = await parseEmail(signed);
    expect(dkimSigningDomains(email)).toContain(domain);
    const { ev, pass } = await verifyDkim('c', email, resolver);
    expect(pass).toBe(true);
    expect(ev?.signal).toBe('dkim_valid_aligned');
    expect(ev?.status).toBe(Status.TRIGGERED);
  });

  it('a tampered body fails verification -> dkim_fail', async () => {
    const signed = await sign(body);
    const tampered = Buffer.from(
      signed.toString('utf-8').replace('review the attached', 'WIRE money to acct 55'),
    );
    const email = await parseEmail(tampered);
    const { ev, pass } = await verifyDkim('c', email, resolver);
    expect(pass).toBe(false);
    expect(ev?.signal).toBe('dkim_fail');
  });

  it('no signature -> no evidence, no score', async () => {
    const email = await parseEmail(Buffer.from(body));
    const { ev, pass } = await verifyDkim('c', email, resolver);
    expect(ev).toBeNull();
    expect(pass).toBe(false);
  });
});

describe('M3 DMARC decision (offline via injected TXT resolver)', () => {
  const email = async () =>
    parseEmail(Buffer.from('From: ceo@acme.example\r\nSubject: hi\r\n\r\nx\r\n'));

  it('reject policy + not authenticated -> dmarc_fail_strict', async () => {
    const txt = async (name: string) =>
      name === '_dmarc.acme.example' ? [['v=DMARC1; p=reject']] : Promise.reject(new Error('nx'));
    expect((await dmarcPolicy('acme.example', txt)).policy).toBe('reject');
    const ev = await verifyDmarc('c', await email(), false, txt);
    expect(ev?.signal).toBe('dmarc_fail_strict');
  });

  it('reject policy + authenticated -> no finding (policy strength is not a failure)', async () => {
    const txt = async (name: string) =>
      name === '_dmarc.acme.example' ? [['v=DMARC1; p=reject']] : Promise.reject(new Error('nx'));
    const ev = await verifyDmarc('c', await email(), true, txt);
    expect(ev).toBeNull();
  });

  it('no published policy -> no finding', async () => {
    const txt = async () => Promise.reject(new Error('nx'));
    expect((await dmarcPolicy('acme.example', txt)).policy).toBeNull();
    const ev = await verifyDmarc('c', await email(), false, txt);
    expect(ev).toBeNull();
  });
});
