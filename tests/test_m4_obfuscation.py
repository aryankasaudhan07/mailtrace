"""M4 evasion detection: homoglyphs, invisible chars, image-only links."""
from __future__ import annotations

import asyncio
from uuid import uuid4

from app.analyzers import m4_content
from app.ingest.parser import parse_email
from app.ingest.text_norm import canonical, obfuscation_report
from app.schemas.evidence import Status

CYR_E = "е"  # Cyrillic small 'е' — looks identical to Latin 'e'
ZWSP = "​"   # zero-width space


def test_canonical_folds_homoglyphs_and_invisibles():
    assert canonical(f"urg{CYR_E}nt") == "urgent"
    assert canonical(f"ver{ZWSP}ify") == "verify"


def test_report_flags_mixed_script_and_clean():
    assert obfuscation_report(f"urg{CYR_E}nt action")["obfuscated"] is True
    assert obfuscation_report(f"ver{ZWSP}ify now")["obfuscated"] is True
    assert obfuscation_report("please verify your account")["obfuscated"] is False


def test_heuristic_matches_disguised_keyword():
    # A Cyrillic-disguised "urgent"/"password" must still trip the keyword
    # heuristic once folded — and must NOT match while still disguised.
    disguised = f"this is urg{CYR_E}nt, confirm your passw{CYR_E}rd"
    assert m4_content._heuristic_analysis("hi", disguised)["classifier_phishing_high"] > 0
    # sanity: the raw disguised bytes don't contain the ASCII keyword
    assert "urgent" not in disguised and "password" not in disguised


def _signals(raw: bytes, monkeypatch) -> dict:
    async def _no_gemini(subject, body):
        return None  # force the offline path; keeps the test hermetic
    monkeypatch.setattr(m4_content, "_call_gemini", _no_gemini)
    ev = asyncio.run(m4_content.analyze(uuid4(), parse_email(raw)))
    return {e.signal: e.status for e in ev}


def test_obfuscated_text_triggers(monkeypatch):
    raw = f"From: x@a.tk\r\nSubject: notice\r\n\r\nurg{CYR_E}nt: verify your account now\r\n".encode()
    assert _signals(raw, monkeypatch).get("obfuscated_text") is Status.TRIGGERED


def test_image_only_link_triggers(monkeypatch):
    raw = (
        b"From: x@a.tk\r\nSubject: hi\r\nContent-Type: text/html\r\n\r\n"
        b'<a href="http://evil-phish.tk/login"><img src="cid:banner"></a>\r\n'
    )
    assert _signals(raw, monkeypatch).get("links_no_text") is Status.TRIGGERED


def test_benign_is_clear(monkeypatch):
    raw = b"From: x@example.ac.in\r\nSubject: Meeting notes\r\n\r\nPlease find the committee notes attached, thanks.\r\n"
    sig = _signals(raw, monkeypatch)
    assert sig.get("obfuscated_text") is Status.CLEAR
    assert sig.get("links_no_text") is Status.CLEAR
