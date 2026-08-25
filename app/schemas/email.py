"""
The canonical parsed-email object and the relay hop model.

M1 (ingestion) is the only thing that builds a ParsedEmail. Everything
downstream reads it and never re-parses raw bytes -- except M3, which needs
the original bytes for DKIM verification, so we keep them on the object.

Owner: Track A
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class HopTrust(str, Enum):
    """
    Where a hop sits relative to the trust boundary.

    See the architecture doc, section 03. Received headers are prepended, so
    the chain reads bottom-to-top in transmission order, and an attacker can
    forge every hop below the first server we control. We walk down from the
    top through hosts we can authenticate and stop at the last one we trust:
    the IP that hop received *from* is the highest-confidence origin.
    """

    TRUSTED = "TRUSTED"        # our infrastructure or an authenticated provider
    BOUNDARY = "BOUNDARY"      # the earliest trustworthy hop -- report this origin
    UNVERIFIED = "UNVERIFIED"  # below the boundary; attacker could have written it


class Hop(BaseModel):
    """One Received: header, parsed."""

    seq: int = Field(..., description="0 = bottom of the header block = claimed origin.")
    raw: str = Field(..., description="The original header line, unmodified.")

    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    by_ip: str | None = None
    protocol: str | None = Field(None, description="e.g. ESMTPS, ESMTPSA, SMTP")
    timestamp: datetime | None = None

    trust: HopTrust = HopTrust.UNVERIFIED
    anomalies: list[str] = Field(
        default_factory=list,
        description="Signal keys raised against this specific hop, e.g. "
        "['private_ip_in_public_chain', 'rdns_mismatch'].",
    )

    # Filled by M5 (Track D). Left empty when intel is unavailable.
    geo: dict[str, Any] | None = None


class Attachment(BaseModel):
    filename: str | None = None
    content_type: str | None = None
    size_bytes: int = 0
    sha256: str


class ExtractedUrl(BaseModel):
    url: str
    domain: str | None = None
    display_text: str | None = None
    is_shortened: bool = False
    mismatched_anchor: bool = Field(
        False,
        description="True when the visible link text names a different domain "
        "than the href. A classic phishing tell.",
    )


class ParsedEmail(BaseModel):
    """
    The canonical internal representation. One ingestion path or ten, every
    analyzer sees only this.
    """

    sha256: str = Field(..., description="Hash of the original raw bytes. "
                                        "Goes in the forensic report as the evidence identifier.")
    raw_bytes: bytes = Field(..., repr=False, exclude=True)

    # ordered exactly as they appeared, duplicates preserved -- order is evidence
    headers: list[tuple[str, str]] = Field(default_factory=list)

    message_id: str | None = None
    subject: str | None = None
    date: datetime | None = None

    from_display_name: str | None = None
    from_addr: str | None = None
    reply_to: str | None = None
    return_path: str | None = None
    to_addrs: list[str] = Field(default_factory=list)

    body_text: str = ""
    body_html: str | None = None

    urls: list[ExtractedUrl] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)

    def header_values(self, name: str) -> list[str]:
        """All values for a header name, in original order. Case-insensitive."""
        low = name.lower()
        return [v for k, v in self.headers if k.lower() == low]

    def first_header(self, name: str) -> str | None:
        vals = self.header_values(name)
        return vals[0] if vals else None
