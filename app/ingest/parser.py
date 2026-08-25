"""
M1 -- ingestion and normalization. Working, not a stub.

Takes raw RFC 5322 bytes from any source and produces the one canonical
ParsedEmail object every downstream analyzer reads. Add a new ingestion path
(IMAP, webhook, SMTP hook) by feeding bytes in here; nothing downstream changes.

Owner: Track A
"""

from __future__ import annotations

import hashlib
import re
from email import message_from_bytes, policy
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime
from urllib.parse import urlparse

from app.schemas.email import Attachment, ExtractedUrl, ParsedEmail

# Deliberately conservative: we would rather miss an exotic URL than corrupt
# the header block with a greedy match.
URL_RE = re.compile(r"""https?://[^\s<>"'\)\]\},]+""", re.IGNORECASE)
ANCHOR_RE = re.compile(
    r"""<a\s[^>]*href\s*=\s*["']?(?P<href>[^"'\s>]+)["']?[^>]*>(?P<text>.*?)</a>""",
    re.IGNORECASE | re.DOTALL,
)
TAG_RE = re.compile(r"<[^>]+>")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id",
    "lnkd.in", "bl.ink", "shorte.st", "adf.ly", "t.ly",
}


def _decode(value: str | None) -> str | None:
    """RFC 2047 decode a header value, tolerating malformed encodings."""
    if value is None:
        return None
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _domain_of(addr: str | None) -> str | None:
    if not addr or "@" not in addr:
        return None
    return addr.rsplit("@", 1)[1].strip().lower().rstrip(">").strip()


def parse_email(raw: bytes) -> ParsedEmail:
    """
    Parse raw bytes into a ParsedEmail.

    Two things here are load-bearing and easy to get wrong:

    1. `headers` preserves original order AND duplicates. Received: headers are
       prepended by each MTA, so their order IS the transmission path. A dict
       would silently destroy the evidence M2 depends on.
    2. `raw_bytes` is kept on the object because DKIM verification (M3) must
       hash the original bytes -- any re-serialization breaks the signature.
    """
    msg = message_from_bytes(raw, policy=policy.default)

    headers: list[tuple[str, str]] = [(k, str(v)) for k, v in msg.items()]

    from_display, from_addr = None, None
    raw_from = msg.get("From")
    if raw_from:
        pairs = getaddresses([_decode(raw_from) or ""])
        if pairs:
            from_display = (pairs[0][0] or "").strip() or None
            from_addr = (pairs[0][1] or "").strip().lower() or None

    reply_to = None
    if msg.get("Reply-To"):
        pairs = getaddresses([_decode(msg.get("Reply-To")) or ""])
        if pairs:
            reply_to = (pairs[0][1] or "").strip().lower() or None

    return_path = (msg.get("Return-Path") or "").strip().strip("<>").lower() or None

    to_addrs = [
        a.lower()
        for _, a in getaddresses([_decode(msg.get("To")) or ""])
        if a
    ]

    date = None
    if msg.get("Date"):
        try:
            date = parsedate_to_datetime(msg.get("Date"))
        except (TypeError, ValueError):
            date = None

    body_text, body_html = _extract_bodies(msg)
    attachments = _extract_attachments(msg)
    urls = _extract_urls(body_text, body_html)

    return ParsedEmail(
        sha256=hashlib.sha256(raw).hexdigest(),
        raw_bytes=raw,
        headers=headers,
        message_id=(msg.get("Message-ID") or "").strip() or None,
        subject=_decode(msg.get("Subject")),
        date=date,
        from_display_name=from_display,
        from_addr=from_addr,
        reply_to=reply_to,
        return_path=return_path,
        to_addrs=to_addrs,
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        attachments=attachments,
    )


def _extract_bodies(msg) -> tuple[str, str | None]:
    text_parts: list[str] = []
    html_parts: list[str] = []

    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_filename():  # an attachment, not a body
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError, TypeError):
            continue
        (text_parts if ctype == "text/plain" else html_parts).append(decoded)

    html = "\n".join(html_parts) if html_parts else None
    text = "\n".join(text_parts).strip()
    if not text and html:
        # No plain part. Strip tags so the M4 classifier has something to read.
        text = TAG_RE.sub(" ", html)
        text = re.sub(r"\s+", " ", text).strip()
    return text, html


def _extract_attachments(msg) -> list[Attachment]:
    out: list[Attachment] = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        disposition = (part.get("Content-Disposition") or "").lower()
        if not filename and "attachment" not in disposition:
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        out.append(
            Attachment(
                filename=_decode(filename),
                content_type=part.get_content_type(),
                size_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    return out


def _extract_urls(body_text: str, body_html: str | None) -> list[ExtractedUrl]:
    found: dict[str, ExtractedUrl] = {}

    def add(url: str, display: str | None = None, mismatched: bool = False) -> None:
        url = url.strip().rstrip(".,;:)")
        if not url or url in found:
            return
        host = (urlparse(url).hostname or "").lower()
        found[url] = ExtractedUrl(
            url=url,
            domain=host or None,
            display_text=display,
            is_shortened=host in SHORTENERS,
            mismatched_anchor=mismatched,
        )

    if body_html:
        for m in ANCHOR_RE.finditer(body_html):
            href = m.group("href")
            text = re.sub(r"\s+", " ", TAG_RE.sub("", m.group("text"))).strip()
            if not href.lower().startswith("http"):
                continue
            href_host = (urlparse(href).hostname or "").lower()
            # Does the visible text itself name a *different* domain?
            mismatch = False
            for tm in URL_RE.finditer(text):
                text_host = (urlparse(tm.group(0)).hostname or "").lower()
                if text_host and href_host and text_host != href_host:
                    mismatch = True
            add(href, display=text or None, mismatched=mismatch)

    for m in URL_RE.finditer(body_text or ""):
        add(m.group(0))

    return list(found.values())
