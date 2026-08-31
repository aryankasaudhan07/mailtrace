/**
 * Text de-obfuscation shared by the content analyzer
 * (ported from app/ingest/text_norm.py).
 *
 * Attackers disguise words so keyword matching misses them: homoglyphs (Latin-
 * looking letters from other scripts) and invisible characters (zero-width /
 * soft-hyphen) inserted between letters. canonical() reverses both; the detector
 * reports when either technique was used, which is itself a strong evasion signal.
 */

// Non-Latin letters that look like Latin ones -> their Latin twin.
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', х: 'x', у: 'y',
  ѕ: 's', і: 'i', ј: 'j', һ: 'h', к: 'k', м: 'm', т: 't',
  в: 'b', н: 'h', д: 'd', г: 'r', п: 'n', л: 'n',
  // Greek
  ο: 'o', α: 'a', ε: 'e', ρ: 'p', τ: 't', ν: 'v', ι: 'i',
  κ: 'k', χ: 'x', υ: 'u', μ: 'u',
};

// Zero-width / directional / soft-hyphen / mongolian-vowel-separator.
const INVISIBLE = '​‌‍⁠﻿­‎‏᠎';
const INVIS_RE = new RegExp(`[${INVISIBLE}]`, 'g');
// \w is ASCII-only in JS; use a Unicode letter/number class so invisible chars
// inserted BETWEEN non-Latin letters (Cyrillic/Greek homoglyph words) are still
// counted as an obfuscation run — not just between Latin letters.
const INVIS_IN_WORD_RE = new RegExp(`(?<=[\\p{L}\\p{N}_])[${INVISIBLE}]+(?=[\\p{L}\\p{N}_])`, 'gu');

const RE_CYRILLIC = /\p{Script=Cyrillic}/u;
const RE_GREEK = /\p{Script=Greek}/u;
const RE_LATIN = /\p{Script=Latin}/u;

function fold(s: string): string {
  let out = '';
  for (const ch of s) out += CONFUSABLES[ch] ?? ch;
  return out;
}

export function stripInvisible(text: string): string {
  return (text || '').replace(INVIS_RE, '');
}

/** NFKC-fold, remove invisibles, map homoglyphs to Latin, lowercase. */
export function canonical(text: string): string {
  const t = (text || '').normalize('NFKC').replace(INVIS_RE, '');
  return fold(t).toLowerCase();
}

function scriptOf(ch: string): 'CYRILLIC' | 'GREEK' | 'LATIN' | 'OTHER' | null {
  if (!/\p{L}/u.test(ch)) return null;
  if (RE_CYRILLIC.test(ch)) return 'CYRILLIC';
  if (RE_GREEK.test(ch)) return 'GREEK';
  if (RE_LATIN.test(ch)) return 'LATIN';
  return 'OTHER';
}

/** Words that mix scripts within a single token (e.g. Latin + Cyrillic). */
export function mixedScriptWords(text: string): string[] {
  const out: string[] = [];
  for (const word of (text || '').split(/\s+/).filter(Boolean)) {
    const scripts = new Set<string>();
    for (const c of word) {
      const s = scriptOf(c);
      if (s === 'LATIN' || s === 'CYRILLIC' || s === 'GREEK') scripts.add(s);
    }
    if (scripts.size > 1) out.push(word);
  }
  return out;
}

export interface ObfuscationReport {
  mixed_script_words: string[];
  mixed_script_count: number;
  invisible_runs: number;
  obfuscated: boolean;
}

export function obfuscationReport(text: string): ObfuscationReport {
  const mixed = mixedScriptWords(text);
  const invisRuns = ((text || '').match(INVIS_IN_WORD_RE) || []).length;
  return {
    mixed_script_words: mixed.slice(0, 5),
    mixed_script_count: mixed.length,
    invisible_runs: invisRuns,
    obfuscated: mixed.length > 0 || invisRuns >= 1,
  };
}
