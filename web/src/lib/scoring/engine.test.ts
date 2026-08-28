/** Ported from tests/test_scoring.py — the scorer is the integration point. */
import { describe, it, expect } from 'vitest';
import { Analyzer, Status, triggered, clear, type Evidence } from '../schemas/evidence';
import { Band } from '../schemas/verdict';
import { loadRules, scoreCase } from './engine';

const cid = 'test-case';

describe('scoring engine parity', () => {
  it('every signal has weight, label, rationale, analyzer', () => {
    const rules = loadRules();
    for (const [name, rule] of Object.entries(rules.signals)) {
      expect(Number.isInteger(rule.weight), name).toBe(true);
      expect(rule.label, `${name} has no label`).toBeTruthy();
      expect(rule.rationale, `${name} has no rationale`).toBeTruthy();
      expect(rule.analyzer, `${name} has no analyzer`).toBeTruthy();
    }
  });

  it('no evidence is benign', () => {
    const v = scoreCase(cid, []);
    expect(v.score).toBe(0);
    expect(v.band).toBe(Band.BENIGN);
  });

  it('additive and capped at 100', () => {
    const ev = [
      triggered(cid, Analyzer.M2_HEADERS, 'forged_received_hop'),
      triggered(cid, Analyzer.M3_AUTH, 'dmarc_fail_strict'),
      triggered(cid, Analyzer.M6_DOMAIN, 'brand_lookalike_domain'),
      triggered(cid, Analyzer.M2_HEADERS, 'reply_to_domain_mismatch'),
      triggered(cid, Analyzer.M3_AUTH, 'spf_fail_hard'),
    ];
    const v = scoreCase(cid, ev);
    expect(v.score).toBe(100);
    expect(v.band).toBe(Band.CRITICAL);
  });

  it('dkim pulls the score down (no deception present)', () => {
    const base: Evidence[] = [
      triggered(cid, Analyzer.M3_AUTH, 'spf_fail_hard'),
      triggered(cid, Analyzer.M5_NETWORK, 'obfuscated_url'),
    ];
    const without = scoreCase(cid, base).score;
    const withDkim = scoreCase(cid, [...base, triggered(cid, Analyzer.M3_AUTH, 'dkim_valid_aligned')]).score;
    expect(withDkim).toBeLessThan(without);
  });

  it('confidence scales points', () => {
    const full = scoreCase(cid, [triggered(cid, Analyzer.M4_CONTENT, 'classifier_phishing_high', {}, 1.0)]).score;
    const half = scoreCase(cid, [triggered(cid, Analyzer.M4_CONTENT, 'classifier_phishing_high', {}, 0.5)]).score;
    expect(half).toBeLessThan(full);
  });

  it('clear records do not score', () => {
    const v = scoreCase(cid, [
      clear(cid, Analyzer.M2_HEADERS, 'forged_received_hop'),
      clear(cid, Analyzer.M3_AUTH, 'dmarc_fail_strict'),
    ]);
    expect(v.score).toBe(0);
  });

  it('unavailable lane lowers confidence, not score', () => {
    const v = scoreCase(cid, [
      triggered(cid, Analyzer.M2_HEADERS, 'forged_received_hop'),
      { case_id: cid, analyzer: Analyzer.M5_NETWORK, signal: 'x', status: Status.UNAVAILABLE, confidence: 0, detail: {}, raw: {}, observed_at: '' },
      { case_id: cid, analyzer: Analyzer.M6_DOMAIN, signal: 'y', status: Status.UNAVAILABLE, confidence: 0, detail: {}, raw: {}, observed_at: '' },
    ]);
    expect(v.score).toBe(30);
    expect(v.confidence).toBeLessThan(1.0);
    expect(v.lanes_unavailable).toContain(Analyzer.M5_NETWORK);
  });

  it('duplicate signal counted once', () => {
    const v = scoreCase(cid, [
      triggered(cid, Analyzer.M2_HEADERS, 'forged_received_hop'),
      triggered(cid, Analyzer.M2_HEADERS, 'forged_received_hop'),
    ]);
    expect(v.score).toBe(30);
  });

  it('M8 identity credit survives a content flag but is cancelled by sender forgery', () => {
    // established identity (-28) + a content heuristic (+14): content does NOT
    // suppress the identity credit, so the credit wins -> clamps to 0 (CLEAN).
    const legit = scoreCase(cid, [
      triggered(cid, Analyzer.M4_CONTENT, 'credential_harvest_intent'),
      triggered(cid, Analyzer.M8_FOOTPRINT, 'established_sender_identity'),
    ]);
    expect(legit.score).toBe(0);
    expect(legit.band).toBe(Band.BENIGN);

    // established identity (-28) + spoofing: the credit IS suppressed, so the
    // positive spoofing signal scores and the message is NOT whitewashed.
    const spoofed = scoreCase(cid, [
      triggered(cid, Analyzer.M3_AUTH, 'spf_fail_hard'),
      triggered(cid, Analyzer.M8_FOOTPRINT, 'established_sender_identity'),
    ]);
    expect(spoofed.score).toBeGreaterThan(0);
  });

  it('unknown signal is ignored, not fatal', () => {
    const v = scoreCase(cid, [triggered(cid, Analyzer.M2_HEADERS, 'signal_that_does_not_exist')]);
    expect(v.score).toBe(0);
  });

  it('error status does not score', () => {
    const v = scoreCase(cid, [
      { case_id: cid, analyzer: Analyzer.M2_HEADERS, signal: 'forged_received_hop', status: Status.ERROR, confidence: 0, detail: {}, raw: {}, observed_at: '' },
    ]);
    expect(v.score).toBe(0);
  });

  it('contributions ranked by magnitude', () => {
    const v = scoreCase(cid, [
      triggered(cid, Analyzer.M5_NETWORK, 'obfuscated_url'),
      triggered(cid, Analyzer.M2_HEADERS, 'forged_received_hop'),
    ]);
    expect(v.contributions[0].signal).toBe('forged_received_hop');
  });

  it('every contribution carries its explanation', () => {
    const v = scoreCase(cid, [triggered(cid, Analyzer.M2_HEADERS, 'forged_received_hop')]);
    expect(v.contributions[0].rationale).toBeTruthy();
    expect(v.contributions[0].label).toBeTruthy();
    expect(v.scorer_version).toBeTruthy();
  });

  // --- v1.1.0 negative-weight suppression ---

  it('valid dkim still reduces score on a clean message', () => {
    const without = scoreCase(cid, [triggered(cid, Analyzer.M5_NETWORK, 'obfuscated_url')]).score;
    const withDkim = scoreCase(cid, [
      triggered(cid, Analyzer.M5_NETWORK, 'obfuscated_url'),
      triggered(cid, Analyzer.M3_AUTH, 'dkim_valid_aligned'),
    ]).score;
    expect(withDkim).toBeLessThan(without);
  });

  it('valid dkim cannot mask a forged hop', () => {
    const v = scoreCase(cid, [
      triggered(cid, Analyzer.M2_HEADERS, 'forged_received_hop'),
      triggered(cid, Analyzer.M3_AUTH, 'dkim_valid_aligned'),
    ]);
    expect(v.score).toBe(30);
    expect(v.suppressed_negatives).toContain('dkim_valid_aligned');
    expect(v.suppressed_by).toContain('forged_received_hop');
  });

  it('known correspondent cannot mask impersonation', () => {
    const v = scoreCase(cid, [
      triggered(cid, Analyzer.M6_DOMAIN, 'brand_lookalike_domain'),
      triggered(cid, Analyzer.M7_GRAPH, 'known_correspondent'),
    ]);
    expect(v.score).toBe(26);
    expect(v.suppressed_negatives).toContain('known_correspondent');
  });

  it('suppression is reported, not silent', () => {
    const v = scoreCase(cid, [
      triggered(cid, Analyzer.M2_HEADERS, 'reply_to_domain_mismatch'),
      triggered(cid, Analyzer.M3_AUTH, 'dkim_valid_aligned'),
    ]);
    expect(v.suppressed_negatives.length).toBeGreaterThan(0);
    expect(v.suppressed_by.length).toBeGreaterThan(0);
    expect(v.summary).toContain('authenticated correctly');
  });

  it('every suppressor is a real positive signal', () => {
    const rules = loadRules();
    for (const name of rules.suppressors) {
      expect(rules.signals[name], `suppressor ${name} is not a defined signal`).toBeTruthy();
      expect(rules.signals[name].weight, `suppressor ${name} is not positive`).toBeGreaterThan(0);
    }
  });

  it('no deception means no suppression', () => {
    const v = scoreCase(cid, [triggered(cid, Analyzer.M3_AUTH, 'dkim_valid_aligned')]);
    expect(v.suppressed_negatives).toEqual([]);
    expect(v.suppressed_by).toEqual([]);
  });
});
