// Generates two demo samples with REAL DKIM signatures:
//   dkim-pass.eml  -> valid aligned signature (verifies)
//   dkim-fail.eml  -> same signature, body tampered after signing (fails)
// The public key is printed so it can be bundled into the demo key registry;
// the private key is used only here and never committed.
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dkimSign } from 'mailauth/lib/dkim/sign.js';

const DOMAIN = 'trusted-corp.example';
const SELECTOR = 'demo';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'der' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const pubB64 = publicKey.toString('base64');

const base = [
  `From: "Finance Team" <finance@${DOMAIN}>`,
  'To: ap@acme.example',
  'Subject: Payment confirmation for invoice 8841',
  'Date: Wed, 27 Aug 2026 10:00:00 +0000',
  `Message-ID: <pass-8841@${DOMAIN}>`,
  `Received: from mail.${DOMAIN} ([203.0.113.10]) by mx.example.ac.in with ESMTPS; Wed, 27 Aug 2026 10:00:02 +0000`,
  'MIME-Version: 1.0',
  'Content-Type: text/plain; charset=utf-8',
  '',
  'Hello, your payment for invoice 8841 has been processed successfully. No action is needed on your part.',
  '',
].join('\r\n');

const opts = {
  canonicalization: 'relaxed/relaxed',
  signTime: new Date('2026-08-27T10:00:05Z'),
  signatureData: [{ signingDomain: DOMAIN, selector: SELECTOR, privateKey }],
};
const res = await dkimSign(base, opts);
const signed = Buffer.concat([Buffer.from(res.signatures), Buffer.from(base)]).toString('utf-8');

// tampered: alter the body after signing -> body hash no longer matches
const tampered = signed.replace(
  'No action is needed on your part.',
  'URGENT: wire 50,000 USD to account 99887766 today to avoid penalties.',
);

mkdirSync('public/samples', { recursive: true });
writeFileSync('public/samples/dkim-pass.eml', signed);
writeFileSync('public/samples/dkim-fail.eml', tampered);

console.log('WROTE public/samples/dkim-pass.eml and dkim-fail.eml');
console.log(`DKIM_DNS_NAME=${SELECTOR}._domainkey.${DOMAIN}`);
console.log(`DKIM_TXT=v=DKIM1; k=rsa; p=${pubB64}`);
