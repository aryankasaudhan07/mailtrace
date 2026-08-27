import { describe, it, expect } from 'vitest';
import { canonical, stripInvisible, mixedScriptWords, obfuscationReport } from './text_norm';

describe('text_norm de-obfuscation', () => {
  it('folds Cyrillic homoglyphs back to Latin', () => {
    // "urgеnt" with a Cyrillic 'е' (U+0435)
    expect(canonical('URGеNT')).toBe('urgent');
    // "pа" with Cyrillic 'а'
    expect(canonical('Pаssword')).toBe('password');
  });

  it('strips zero-width characters between letters', () => {
    expect(stripInvisible('ver​ify')).toBe('verify');
    expect(canonical('ver​ify')).toBe('verify');
  });

  it('detects mixed-script words', () => {
    const mixed = mixedScriptWords('please URGеNT verify'); // Cyrillic е inside a Latin word
    expect(mixed.length).toBe(1);
  });

  it('obfuscationReport flags disguise and stays quiet on clean text', () => {
    const dirty = obfuscationReport('URGеNT wire tr​ansfer now');
    expect(dirty.obfuscated).toBe(true);
    expect(dirty.mixed_script_count).toBeGreaterThanOrEqual(1);
    expect(dirty.invisible_runs).toBeGreaterThanOrEqual(1);

    const clean = obfuscationReport('please review the invoice and confirm payment');
    expect(clean.obfuscated).toBe(false);
  });
});
