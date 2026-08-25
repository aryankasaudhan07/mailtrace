"""
Text de-obfuscation shared by the content analyzer.

Attackers disguise words so keyword/regex matching misses them:
  1. Homoglyphs — Latin-looking letters from other scripts ("urgеnt" with a
     Cyrillic 'е'). Same glyph to a human, different code point to a computer.
  2. Invisible characters — zero-width / soft-hyphen unicode inserted between
     letters ("ver​ify") to break word boundaries.

`canonical()` reverses both so matching sees the real word; the detectors report
when either technique was used, which is itself a strong evasion signal.
"""

from __future__ import annotations

import re
import unicodedata

# Non-Latin letters that look like Latin ones -> their Latin twin.
_CONFUSABLES = str.maketrans({
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "һ": "h", "к": "k", "м": "m", "т": "t",
    "в": "b", "н": "h", "д": "d", "г": "r", "п": "n", "л": "n",
    # Greek
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "τ": "t", "ν": "v", "ι": "i",
    "κ": "k", "χ": "x", "υ": "u", "μ": "u",
})

# Zero-width / directional / soft-hyphen characters used to split words.
_INVISIBLE = "​‌‍⁠﻿­‎‏᠎"
_INVIS_RE = re.compile(f"[{_INVISIBLE}]")
# an invisible char sitting *between* two letters — i.e. splitting a word
_INVIS_IN_WORD_RE = re.compile(f"(?<=\\w)[{_INVISIBLE}]+(?=\\w)")


def strip_invisible(text: str) -> str:
    return _INVIS_RE.sub("", text or "")


def canonical(text: str) -> str:
    """NFKC-fold, remove invisibles, map homoglyphs to Latin, lowercase."""
    t = unicodedata.normalize("NFKC", text or "")
    t = _INVIS_RE.sub("", t)
    return t.translate(_CONFUSABLES).lower()


def _script(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    if "CYRILLIC" in name:
        return "CYRILLIC"
    if "GREEK" in name:
        return "GREEK"
    if "LATIN" in name:
        return "LATIN"
    return "OTHER"


def mixed_script_words(text: str) -> list[str]:
    """Words that mix scripts within a single token (e.g. Latin + Cyrillic)."""
    out = []
    for word in re.findall(r"\S+", text or ""):
        scripts = {s for s in (_script(c) for c in word) if s in ("LATIN", "CYRILLIC", "GREEK")}
        if len(scripts) > 1:
            out.append(word)
    return out


def obfuscation_report(text: str) -> dict:
    """Summarise disguise techniques found in `text`."""
    mixed = mixed_script_words(text)
    invis_runs = len(_INVIS_IN_WORD_RE.findall(text or ""))
    return {
        "mixed_script_words": mixed[:5],
        "mixed_script_count": len(mixed),
        "invisible_runs": invis_runs,
        "obfuscated": bool(mixed) or invis_runs >= 1,
    }
