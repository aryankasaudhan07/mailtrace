"""M2 fake-reply signal: a 'Re:' subject with no thread history."""
from __future__ import annotations

import asyncio
from uuid import uuid4

from app.analyzers.m2_headers import analyze
from app.ingest.parser import parse_email
from app.schemas.evidence import Status


def _run(raw: bytes):
    email = parse_email(raw)
    ev = asyncio.run(analyze(uuid4(), email))
    return {e.signal: e.status for e in ev if e.signal == "fake_reply"}


def test_fake_reply_triggered():
    """'Re:' subject, but no In-Reply-To and no References -> forged thread."""
    raw = (
        b"From: CEO <ceo@example.ac.in>\r\n"
        b"Subject: Re: Q3 invoice approval\r\n"
        b"Message-ID: <a@example.ac.in>\r\n\r\n"
        b"Please wire the amount today.\r\n"
    )
    assert _run(raw)["fake_reply"] is Status.TRIGGERED


def test_genuine_reply_is_clear():
    """A 'Re:' with References is a real reply -> CLEAR."""
    raw = (
        b"From: colleague <c@example.ac.in>\r\n"
        b"Subject: Re: Q3 invoice approval\r\n"
        b"In-Reply-To: <orig@example.ac.in>\r\n"
        b"References: <orig@example.ac.in>\r\n"
        b"Message-ID: <b@example.ac.in>\r\n\r\n"
        b"Approved.\r\n"
    )
    assert _run(raw)["fake_reply"] is Status.CLEAR


def test_non_reply_subject_is_clear():
    """A subject that does not claim to be a reply -> CLEAR."""
    raw = (
        b"From: person <p@example.ac.in>\r\n"
        b"Subject: Meeting notes\r\n"
        b"Message-ID: <c@example.ac.in>\r\n\r\n"
        b"Notes attached.\r\n"
    )
    assert _run(raw)["fake_reply"] is Status.CLEAR
