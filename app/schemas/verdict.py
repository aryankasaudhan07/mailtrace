"""
What the scorer returns. The only place a number becomes a judgement.

Owner: Track E
"""

from __future__ import annotations

from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.evidence import Analyzer


class Band(str, Enum):
    BENIGN = "BENIGN"          # 0-24
    SUSPICIOUS = "SUSPICIOUS"  # 25-49
    HIGH_RISK = "HIGH_RISK"    # 50-74
    CRITICAL = "CRITICAL"      # 75-100

    @classmethod
    def from_score(cls, score: int) -> Band:
        if score >= 75:
            return cls.CRITICAL
        if score >= 50:
            return cls.HIGH_RISK
        if score >= 25:
            return cls.SUSPICIOUS
        return cls.BENIGN


class Contribution(BaseModel):
    """
    One line of the explanation. The UI renders these ranked by |points|,
    and the PDF report prints them verbatim. This is the whole reason the
    scorer is a weight table and not a model: a judge asking "why 82?"
    gets this list.
    """

    signal: str
    analyzer: Analyzer
    weight: int = Field(..., description="Weight from weights.yaml, before confidence.")
    confidence: float
    points: float = Field(..., description="weight * confidence, as applied.")
    label: str = Field(..., description="Human-readable signal name for the UI.")
    rationale: str = Field(..., description="Why this signal carries this weight.")
    detail: dict = Field(default_factory=dict)


class Verdict(BaseModel):
    case_id: UUID
    score: int = Field(..., ge=0, le=100)
    band: Band
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Separate from score. Drops when analyzer lanes are UNAVAILABLE "
        "or the trust boundary could not be established. A score of 80 at 0.4 "
        "confidence and a score of 80 at 0.95 confidence are different states, "
        "and the UI must show them differently.",
    )
    scorer_version: str = Field(
        ...,
        description="Version string from weights.yaml. Stamped into every report so a "
        "verdict can always be reproduced against the rules that produced it.",
    )

    contributions: list[Contribution] = Field(default_factory=list)
    lanes_unavailable: list[Analyzer] = Field(default_factory=list)
    suppressed_negatives: list[str] = Field(
        default_factory=list,
        description="Negative signals that were present but did not apply, because a "
        "deception signal was also present. Surfaced rather than dropped so an "
        "analyst can see the message had valid authentication AND why that did not "
        "reduce the score. See docs/THREAT-MODEL.md section 7.1.",
    )
    suppressed_by: list[str] = Field(
        default_factory=list,
        description="The deception signals that caused the suppression.",
    )
    summary: str = Field("", description="One sentence for the top of the report.")
