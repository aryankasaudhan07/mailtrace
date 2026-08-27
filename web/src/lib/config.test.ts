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
  it('unions a real override with the always-trusted fixture MX', () => {
    process.env.TRUSTED_MX_HOSTS = 'mx.corp.example, mx2.corp.example';
    const h = config.trustedHosts();
    expect(h.has('mx.corp.example')).toBe(true);
    expect(h.has('mx2.corp.example')).toBe(true);
    // fixture MX is always present so the boundary resolves regardless of env
    expect(h.has('mx.example.ac.in')).toBe(true);
  });

  it('a wrong/stale env value cannot break the fixture boundary', () => {
    process.env.TRUSTED_MX_HOSTS = 'some-wrong-host.example';
    expect(config.trustedHosts().has('mx.example.ac.in')).toBe(true);
  });
});
