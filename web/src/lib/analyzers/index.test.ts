import { describe, it, expect } from 'vitest';
import { Analyzer } from '../schemas/evidence';
import { registry } from './index';

describe('analyzer registry', () => {
  it('all six lanes register when the barrel is imported', () => {
    const reg = registry();
    for (const id of [
      Analyzer.M2_HEADERS, Analyzer.M3_AUTH, Analyzer.M4_CONTENT,
      Analyzer.M5_NETWORK, Analyzer.M6_DOMAIN, Analyzer.M7_GRAPH,
    ]) {
      expect(reg.has(id), id).toBe(true);
    }
    expect(reg.size).toBe(6);
  });
});
