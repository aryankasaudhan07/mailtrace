import { describe, it, expect } from 'vitest';
import { fuzzRatio, checkBrandLookalike } from './m6_domain';

describe('M6 fuzzRatio (rapidfuzz-equivalent)', () => {
  it('identical strings score 100', () => {
    expect(fuzzRatio('paypal', 'paypal')).toBe(100);
  });
  it('paypa1 vs paypal is a near-match (>=82)', () => {
    expect(fuzzRatio('paypa1', 'paypal')).toBeGreaterThanOrEqual(82);
  });
  it('unrelated strings score low', () => {
    expect(fuzzRatio('google', 'sbi')).toBeLessThan(50);
  });
});

describe('M6 brand lookalike', () => {
  it('the real brand (or a subdomain of it) is not flagged', () => {
    expect(checkBrandLookalike('sbi.co.in')).toBeNull();
    expect(checkBrandLookalike('retail.sbi.co.in')).toBeNull();
  });

  it('brand name placed in a domain it does not own', () => {
    const r = checkBrandLookalike('sbi.co.in.secure-login.tk');
    expect(r).not.toBeNull();
    expect(r![0]).toBe('sbi.co.in');
    expect(r![1]).toBe('brand-name-in-domain');
  });

  it('homograph collision via Cyrillic folding', () => {
    // "аicte-india.org" with a Cyrillic 'а' folds to the real skeleton
    const r = checkBrandLookalike('аicte-india.org');
    expect(r).not.toBeNull();
    expect(r![0]).toBe('aicte-india.org');
    expect(r![1]).toBe('homograph');
  });

  it('npci brand token in a hyphenated lookalike', () => {
    const r = checkBrandLookalike('npci-refund.tk');
    expect(r).not.toBeNull();
    expect(r![0]).toBe('npci.org.in');
  });

  it('an unrelated legitimate domain is not flagged', () => {
    expect(checkBrandLookalike('example-institute.example')).toBeNull();
  });
});
