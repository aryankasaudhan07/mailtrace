"""
The scoring engine. The only component that turns evidence into a verdict.

Deterministic, versioned, and fully explainable. Additive with a cap:
score = clamp(sum(weight * confidence) for every TRIGGERED signal, 0, 100).

Owner: Track E
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from uuid import UUID

import yaml

from app.schemas.evidence import Analyzer, Evidence, Status
from app.schemas.verdict import Band, Contribution, Verdict

log = logging.getLogger(__name__)

WEIGHTS_PATH = Path(__file__).parent / "weights.yaml"


class Rules:
    """Parsed weights.yaml."""

    def __init__(self, doc: dict) -> None:
        self.version: str = doc["version"]
        self.signals: dict[str, dict] = doc["signals"]
        self.unavailable_penalty: float = float(
            doc.get("confidence_penalty_per_unavailable_lane", 0.15)
        )
        # Deception signals that disable every negative weight. See the comment in
        # weights.yaml and docs/THREAT-MODEL.md §7.1 for why this is load-bearing.
        self.suppressors: frozenset[str] = frozenset(
            doc.get("suppress_negatives_when_any_triggered", []) or []
        )

    def get(self, signal: str) -> dict | None:
        return self.signals.get(signal)


@lru_cache(maxsize=1)
def load_rules(path: str | None = None) -> Rules:
    p = Path(path) if path else WEIGHTS_PATH
    with p.open("r", encoding="utf-8") as fh:
        return Rules(yaml.safe_load(fh))


def score_case(case_id: UUID, evidence: list[Evidence], rules: Rules | None = None) -> Verdict:
    """
    Turn a case's full evidence set into a Verdict.

    Only TRIGGERED records move the score. CLEAR records are kept in the
    evidence log (they are proof we checked) but contribute nothing. UNAVAILABLE
    records reduce confidence. ERROR records are ignored by the score and should
    be surfaced to the team as bugs, not to the analyst as findings.
    """
    rules = rules or load_rules()

    contributions: list[Contribution] = []
    unavailable_lanes: set[Analyzer] = set()
    raw_total = 0.0
    # a signal firing twice must not double-count -- keep the strongest instance
    seen: dict[str, float] = {}

    # First pass: is any deception signal present? If so, negative weights are
    # suppressed. A compromised mailbox produces a perfectly valid aligned DKIM
    # signature, so credit for good authentication must never be able to cancel
    # out evidence of forgery. See docs/THREAT-MODEL.md §7.1.
    triggered_signals = {
        ev.signal for ev in evidence if ev.status is Status.TRIGGERED
    }
    suppressing = sorted(triggered_signals & rules.suppressors)
    suppressed: list[str] = []

    for ev in evidence:
        if ev.status is Status.UNAVAILABLE:
            unavailable_lanes.add(ev.analyzer)
            continue
        if ev.status is not Status.TRIGGERED:
            continue

        rule = rules.get(ev.signal)
        if rule is None:
            # An analyzer invented a signal that is not in weights.yaml.
            # Loud, because it means someone shipped half a change.
            log.warning(
                "signal %r from %s is not in weights.yaml v%s -- not scored",
                ev.signal,
                ev.analyzer.value,
                rules.version,
            )
            continue

        weight = int(rule["weight"])

        if weight < 0 and suppressing:
            # Recorded, not silently dropped: an analyst must be able to see that
            # the message had good authentication AND why it did not help.
            if ev.signal not in suppressed:
                suppressed.append(ev.signal)
            continue

        points = weight * ev.confidence

        prior = seen.get(ev.signal)
        if prior is not None and abs(prior) >= abs(points):
            continue
        if prior is not None:
            raw_total -= prior
            contributions = [c for c in contributions if c.signal != ev.signal]

        seen[ev.signal] = points
        raw_total += points

        contributions.append(
            Contribution(
                signal=ev.signal,
                analyzer=ev.analyzer,
                weight=weight,
                confidence=ev.confidence,
                points=round(points, 2),
                label=rule.get("label", ev.signal),
                rationale=(rule.get("rationale") or "").strip(),
                detail=ev.detail,
            )
        )

    score = max(0, min(100, round(raw_total)))
    band = Band.from_score(score)

    # Confidence measures evidence completeness, not verdict strength: every
    # lane that ran (TRIGGERED or CLEAR alike) is a check we can stand behind,
    # and every lane that could not run is a blind spot the analyst must see.
    confidence = 1.0 - rules.unavailable_penalty * len(unavailable_lanes)
    confidence = max(0.0, min(1.0, round(confidence, 2)))

    contributions.sort(key=lambda c: abs(c.points), reverse=True)

    return Verdict(
        case_id=case_id,
        score=score,
        band=band,
        confidence=confidence,
        scorer_version=rules.version,
        contributions=contributions,
        lanes_unavailable=sorted(unavailable_lanes, key=lambda a: a.value),
        suppressed_negatives=suppressed,
        suppressed_by=suppressing,
        summary=_summarize(band, contributions, unavailable_lanes, suppressed),
    )


def _summarize(
    band: Band,
    contributions: list[Contribution],
    unavailable: set[Analyzer],
    suppressed: list[str] | None = None,
) -> str:
    if not contributions:
        if unavailable:
            return (
                "No conclusion: every analyzer that could have produced a finding "
                "was unavailable."
            )
        return "No fraud indicators detected across all analyzers."

    top = [c.label for c in contributions if c.points > 0][:3]
    if not top:
        return "No fraud indicators detected; authentication checks passed."

    lead = f"Assessed {band.value.replace('_', ' ').lower()}, driven by: " + "; ".join(top) + "."
    if unavailable:
        lead += (
            f" Confidence reduced: {len(unavailable)} analyzer lane(s) unavailable "
            f"({', '.join(sorted(a.value for a in unavailable))})."
        )
    if suppressed:
        lead += (
            " Note: this message authenticated correctly, but that credit was "
            "withheld because deception indicators were also present -- a "
            "compromised or attacker-owned domain signs validly too."
        )
    return lead
