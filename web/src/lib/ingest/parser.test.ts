import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { parseEmail } from './parser';
import { headerValues } from '../schemas/email';

const ATTACH = 'hello world';
const ATTACH_B64 = Buffer.from(ATTACH).toString('base64');

const RAW = [
  'From: "CEO" <CEO@Acme.example>',
  'Reply-To: attacker@evil.example',
  'To: cfo@acme.example',
  'Subject: Invoice 2291',
  'Message-ID: <a@acme.example>',
  'Date: Tue, 26 Aug 2026 10:00:00 +0000',
  'Received: from relay.acme.example (relay.acme.example [203.0.113.9]) by mx.acme.example with ESMTPS; Tue, 26 Aug 2026 10:00:02 +0000',
  'Received: from sketchy.example ([198.51.100.7]) by relay.acme.example with ESMTP; Tue, 26 Aug 2026 10:00:01 +0000',
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="b1"',
  '',
  '--b1',
  'Content-Type: text/html; charset=utf-8',
  '',
  '<html><body><p>Hi</p><a href="http://evil.example/login">https://paypal.com/verify</a></body></html>',
  '--b1',
  'Content-Type: application/octet-stream; name="doc.bin"',
  'Content-Transfer-Encoding: base64',
  'Content-Disposition: attachment; filename="doc.bin"',
  '',
  ATTACH_B64,
  '--b1--',
  '',
].join('\r\n');

describe('parser (M1)', () => {
  it('parses core headers and addresses (lowercased)', async () => {
    const e = await parseEmail(Buffer.from(RAW));
    expect(e.from_addr).toBe('ceo@acme.example');
    expect(e.from_display_name).toBe('CEO');
    expect(e.reply_to).toBe('attacker@evil.example');
    expect(e.subject).toBe('Invoice 2291');
    expect(e.message_id).toBe('<a@acme.example>');
    expect(e.to_addrs).toContain('cfo@acme.example');
    expect(e.sha256).toHaveLength(64);
  });

  it('preserves Received order and duplicates (transmission path)', async () => {
    const e = await parseEmail(Buffer.from(RAW));
    const received = headerValues(e, 'received');
    expect(received).toHaveLength(2);
    // top-most (prepended last) is written first in the raw block
    expect(received[0]).toContain('relay.acme.example');
    expect(received[1]).toContain('sketchy.example');
  });

  it('detects anchor-text/href domain mismatch', async () => {
    const e = await parseEmail(Buffer.from(RAW));
    const u = e.urls.find((x) => x.url.startsWith('http://evil.example'));
    expect(u).toBeTruthy();
    expect(u!.domain).toBe('evil.example');
    expect(u!.mismatched_anchor).toBe(true);
    expect(u!.display_text).toContain('paypal.com');
  });

  it('derives body_text from HTML when no plain part', async () => {
    const e = await parseEmail(Buffer.from(RAW));
    expect(e.body_html).toContain('paypal.com/verify');
    expect(e.body_text).toContain('Hi');
    expect(e.body_text).not.toContain('<a'); // tags stripped
  });

  it('extracts attachment with a sha256 of its content', async () => {
    const e = await parseEmail(Buffer.from(RAW));
    expect(e.attachments).toHaveLength(1);
    const a = e.attachments[0];
    expect(a.filename).toBe('doc.bin');
    expect(a.sha256).toBe(createHash('sha256').update(ATTACH).digest('hex'));
  });
});
