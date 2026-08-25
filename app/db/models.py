"""
The eight tables. Two rules that are not negotiable:

  1. `evidence` is APPEND-ONLY. Never UPDATE, never DELETE. An analyst override
     is a new row in audit_log, not an edit to a finding.
  2. `audit_log` chains hashes: each row stores the previous row's entry_hash.
     That is what makes the custody record tamper-evident, and it is what the
     problem statement means by chain of custody.

Owner: Track A (schema) / Track E (audit_log + campaigns)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True,
                                          default=uuid.uuid4)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    status: Mapped[str] = mapped_column(String(24), default="QUEUED")  # QUEUED|SCORED|REVIEWED
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    band: Mapped[str | None] = mapped_column(String(16), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    scorer_version: Mapped[str | None] = mapped_column(String(24), nullable=True)
    campaign_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("campaigns.id"), nullable=True
    )

    message: Mapped[Message] = relationship(back_populates="case", uselist=False)
    hops: Mapped[list[HopRow]] = relationship(back_populates="case")
    evidence: Mapped[list[EvidenceRow]] = relationship(back_populates="case")


class Message(Base):
    __tablename__ = "messages"

    case_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True),
                                              ForeignKey("cases.id"), primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    raw_bytes: Mapped[bytes] = mapped_column(LargeBinary)  # the evidence itself
    from_addr: Mapped[str | None] = mapped_column(String(320), index=True)
    from_display_name: Mapped[str | None] = mapped_column(String(320))
    reply_to: Mapped[str | None] = mapped_column(String(320))
    subject: Mapped[str | None] = mapped_column(Text)
    message_id: Mapped[str | None] = mapped_column(String(512), index=True)

    case: Mapped[Case] = relationship(back_populates="message")


class HopRow(Base):
    __tablename__ = "hops"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("cases.id"))
    seq: Mapped[int] = mapped_column(Integer)
    raw: Mapped[str] = mapped_column(Text)
    from_host: Mapped[str | None] = mapped_column(String(255))
    from_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    by_host: Mapped[str | None] = mapped_column(String(255))
    protocol: Mapped[str | None] = mapped_column(String(24))
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trust: Mapped[str] = mapped_column(String(16), default="UNVERIFIED")
    anomalies: Mapped[dict] = mapped_column(JSON, default=list)
    geo: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    case: Mapped[Case] = relationship(back_populates="hops")
    __table_args__ = (UniqueConstraint("case_id", "seq"),)


class EvidenceRow(Base):
    """APPEND-ONLY. No UPDATE, no DELETE, ever."""

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("cases.id"))
    analyzer: Mapped[str] = mapped_column(String(4))
    signal: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    case: Mapped[Case] = relationship(back_populates="evidence")


class Indicator(Base):
    """The graph edge table. Shared value between two cases = an edge."""

    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("cases.id"))
    kind: Mapped[str] = mapped_column(String(12))  # ip|domain|url|hash|asn
    value: Mapped[str] = mapped_column(String(512), index=True)

    __table_args__ = (UniqueConstraint("case_id", "kind", "value"),)


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True,
                                          default=uuid.uuid4)
    label: Mapped[str] = mapped_column(String(128))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    case_count: Mapped[int] = mapped_column(Integer, default=0)


class AuditLog(Base):
    """
    Tamper-evident action log. entry_hash = sha256(prev_hash + canonical(row)).
    Break the chain and the report's custody section fails validation -- which
    is exactly the property that makes it worth showing a judge.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True),
                                                      ForeignKey("cases.id"), nullable=True)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str] = mapped_column(String(64))
    is_override: Mapped[bool] = mapped_column(Boolean, default=False)
