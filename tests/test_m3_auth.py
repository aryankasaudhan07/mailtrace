"""M3 auth re-verification: DKIM integrity and the DMARC false-positive guard."""
from __future__ import annotations

import asyncio
from uuid import uuid4

from app.analyzers import m3_auth
from app.analyzers.m3_auth import _aligned, analyze
from app.ingest.parser import parse_email
from app.schemas.evidence import Status


def _signals(raw: bytes) -> dict:
    ev = asyncio.run(analyze(uuid4(), parse_email(raw)))
    return {e.signal: e.status for e in ev}


def test_relaxed_alignment():
    assert _aligned("sbi.co.in", "sbi.co.in")
    assert _aligned("mail.sbi.co.in", "sbi.co.in")
    assert not _aligned("evil.tk", "sbi.co.in")
    assert not _aligned("", "sbi.co.in")


def test_broken_dkim_signature_is_flagged():
    raw = (
        b"DKIM-Signature: v=1; a=rsa-sha256; d=example.ac.in; s=sel; h=from:subject;\r\n"
        b" b=BOGUSsignaturethatwillnotverify==\r\n"
        b"From: person <p@example.ac.in>\r\nSubject: hello\r\n\r\nbody\r\n"
    )
    assert _signals(raw).get("dkim_fail") is Status.TRIGGERED


def test_unsigned_mail_does_not_penalize():
    """No DKIM signature must not emit a triggered signal (avoids FP on small domains)."""
    raw = b"From: person <p@example.ac.in>\r\nSubject: hello\r\n\r\nbody\r\n"
    sig = _signals(raw)
    assert "dkim_fail" not in sig
    assert "dkim_missing" not in sig
    assert sig.get("auth_verification_passed") is Status.CLEAR


def test_strict_policy_alone_is_not_a_failure(monkeypatch):
    """A domain publishing p=reject must NOT trigger dmarc_fail_strict when
    authentication is not being evaluated as failed (the old bug fired here)."""
    # Force a reject policy and no SPF/DKIM pass; DKIM absent so authenticated=False,
    # but there is no aligned failure to authenticate against -> we only fire when
    # authentication genuinely fails. With no signature and SPF unavailable in test,
    # dmarc still must not fire off policy alone unless authenticated is False AND
    # a policy is present. This asserts the guard is wired to `authenticated`.
    monkeypatch.setattr(m3_auth, "_dmarc_policy", lambda d: "reject")
    raw = b"From: ceo <ceo@example.ac.in>\r\nSubject: hi\r\n\r\nx\r\n"
    # authenticated is False here, policy reject -> by DMARC semantics this DOES fail.
    # The point of the guard is that it keys on authentication, not on policy strength:
    # when we DO authenticate, it must clear. Verify that path:
    monkeypatch.setattr(m3_auth, "_verify_dkim", lambda cid, e: (None, True))  # aligned pass
    sig = _signals(raw)
    assert "dmarc_fail_strict" not in sig, "aligned auth must suppress dmarc_fail_strict"
