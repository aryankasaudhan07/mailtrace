/**
 * Bundled DKIM public keys for the self-contained demo samples.
 *
 * These let dkim-pass.eml / dkim-fail.eml verify with REAL cryptography without
 * needing a published DNS TXT record (we can't publish to a domain we don't
 * own). Only PUBLIC keys live here; the private key was used once, offline, in
 * scripts/gen-dkim-samples.mjs and is never committed. Real emails still resolve
 * their keys from live DNS.
 */
export const DKIM_DEMO_KEYS: Record<string, string> = {
  'demo._domainkey.trusted-corp.example':
    'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3fev54VBz6YTmoAG0SE67OdgVO5C0YeeaLzw4owWC7PN3JfkLLAh90RO/7VR48jJ3VF7ICs12rrpzVfZIB0JFtOqboCIKZbgfu5afwdmnhlouEF5pKuQiF52o7bNpoQ9qAnU/ZpUZe+MHbVZqrJ7mBSE7Ill6Hxo1NbTG6SLhl6Jwx2kCB/prSbPHB/lw7FIgaDqngOp6xIrEdAKhK6dvmh+8SlOU2Do6NC0JeEdkSNAAeVZC8m5ut6eFL1qYRd9GkNZLMT7RIVx5H7MxjgO/PBtXB9KaYxR4MEwqogqh/tVjRXjNWwRQDM7Cp1Y7aSLZIzALt7D2d1IkNjGj/18aQIDAQAB',
};
