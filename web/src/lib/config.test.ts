import { describe, it, expect, afterEach } from 'vitest';
import { config } from './config';

const orig = process.env.TRUSTED_MX_HOSTS;
afterEach(() => { if (orig === undefined) delete process.env.TRUSTED_MX_HOSTS; else process.env.TRUSTED_MX_HOSTS = orig; });

describe('config trust hosts default', () => {
  it('falls back to the fixture MX when unset', () => {
    delete process.env.TRUSTED_MX_HOSTS;
    expect(config.trustedHosts().has('mx.example.ac.in')).toBe(true);
  });
  it('falls back when present-but-empty (the Vercel bug)', () => {
    process.env.TRUSTED_MX_HOSTS = '';
    expect(config.trustedHosts().has('mx.example.ac.in')).toBe(true);
  });
  it('uses a real override when provided', () => {
    process.env.TRUSTED_MX_HOSTS = 'mx.corp.example, mx2.corp.example';
    const h = config.trustedHosts();
    expect(h.has('mx.corp.example')).toBe(true);
    expect(h.has('mx.example.ac.in')).toBe(false);
  });
});
