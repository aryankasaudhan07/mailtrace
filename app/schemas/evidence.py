"""
THE CONTRACT.

Every analyzer in Mailtrace emits a list of Evidence records and nothing else.
No analyzer returns a score. No analyzer returns a verdict. No analyzer talks
to another analyzer. The scorer (app/scoring/engine.py) is the only component
that reads the full evidence set and decides what it means.

Changing anything in this file is a whole-team decision, because all six tracks
build against it. Discuss before you edit.

Owner: Track A
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class Analyzer(str, Enum):
    """Which module produced a record. Matches the module IDs in the plan."""

    M1_INGEST = "M1"
    M2_HEADERS = "M2"
    M3_AUTH = "M3"
    M4_CONTENT = "M4"
    M5_NETWORK = "M5"
    M6_DOMAIN = "M6"
    M7_GRAPH = "M7"


class Status(str, Enum):
    """
    The four states an analyzer may report. UNAVAILABLE is load-bearing:
    when a lane cannot run (no network, rate limited, timeout) it says so
    rather than raising, and the scorer lowers confidence instead of failing
    the request. This is what keeps the demo alive when the venue Wi-Fi dies.
    """

    TRIGGERED = "TRIGGERED"      # the signal is present
    CLEAR = "CLEAR"              # the analyzer checked, the signal is absent
    UNAVAILABLE = "UNAVAILABLE"  # could not check (offline, rate limited, timeout)
    ERROR = "ERROR"              # the analyzer broke; a bug, not a verdict


class Evidence(BaseModel):
    """
    One observation about one email, from one analyzer.

    `signal` is the join key against app/scoring/weights.yaml. If you invent a
    new signal in an analyzer, add it to weights.yaml in the same commit or the
    scorer will ignore it (and log a warning, so you will notice).
    """

    model_config = ConfigDict(frozen=True)  # evidence is never mutated, only appended

    case_id: UUID
    analyzer: Analyzer
    signal: str = Field(
        ...,
        description="Stable snake_case key. MUST exist in weights.yaml.",
        examples=["forged_received_hop", "dmarc_fail_strict", "domain_age_lt_30d"],
    )
    status: Status
    confidence: float = Field(
        1.0,
        ge=0.0,
        le=1.0,
        description="This analyzer's certainty in its own observation. "
        "Deterministic checks report 1.0; ML and heuristics report less.",
    )
    detail: dict[str, Any] = Field(
        default_factory=dict,
        description="Human-readable specifics. Goes into the forensic report verbatim, "
        "so write it for an analyst, not for a debugger.",
    )
    raw: dict[str, Any] = Field(
        default_factory=dict,
        description="Exactly what the underlying source returned, unmodified. "
        "Never rendered in the UI; exists so a finding can be audited later.",
    )
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # ---- convenience constructors: use these, not Evidence(...) directly ----

    @classmethod
    def triggered(
        cls,
        case_id: UUID,
        analyzer: Analyzer,
        signal: str,
        detail: dict[str, Any] | None = None,
        confidence: float = 1.0,
        raw: dict[str, Any] | None = None,
    ) -> Evidence:
        return cls(
            case_id=case_id,
            analyzer=analyzer,
            signal=signal,
            status=Status.TRIGGERED,
            confidence=confidence,
            detail=detail or {},
            raw=raw or {},
        )

    @classmethod
    def clear(
        cls,
        case_id: UUID,
        analyzer: Analyzer,
        signal: str,
        detail: dict[str, Any] | None = None,
    ) -> Evidence:
        return cls(
            case_id=case_id,
            analyzer=analyzer,
            signal=signal,
            status=Status.CLEAR,
            confidence=1.0,
            detail=detail or {},
        )

    @classmethod
    def unavailable(
        cls,
        case_id: UUID,
        analyzer: Analyzer,
        signal: str,
        reason: str,
    ) -> Evidence:
        """Use this on timeout, rate limit, or missing intel database."""
        return cls(
            case_id=case_id,
            analyzer=analyzer,
            signal=signal,
            status=Status.UNAVAILABLE,
            confidence=0.0,
            detail={"reason": reason},
        )
