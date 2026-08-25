"""
M4 -- content intelligence. Two-stage by design.

Stage 1 (always): a cheap local classifier over subject + body.
Stage 2 (only when stage 1 is interesting): an LLM intent pass with a STRICT
JSON schema, for novel social engineering the classifier has never seen.

Ship stage 1 first. The system is demonstrable without stage 2.

Owner: Track C
"""

from __future__ import annotations

from uuid import UUID

from app.analyzers.base import register
from app.schemas.email import ParsedEmail
from app.schemas.evidence import Analyzer, Evidence

# Confidence matters here more than anywhere else: this is the one analyzer
# whose output is probabilistic. Pass the model's probability straight through
# as Evidence.confidence and let the scorer scale the weight by it.
LLM_ESCALATION_THRESHOLD = 0.45


@register(Analyzer.M4_CONTENT)
async def analyze(case_id: UUID, email: ParsedEmail) -> list[Evidence]:
    # TODO-C stage 1: TF-IDF + LinearSVC, trained on Nazario (phish) +
    #                 SpamAssassin easy_ham/hard_ham (ham). Emit
    #                 classifier_phishing_high with confidence = P(phish).
    # TODO-C stage 2: LLM intent pass -> payment_diversion_intent,
    #                 credential_harvest_intent, executive_impersonation.
    #
    # Keep the LLM prompt in a separate file so it is reviewable, and force
    # JSON output. Never let a free-text LLM answer become a signal key.
    return [
        Evidence.unavailable(
            case_id, Analyzer.M4_CONTENT, "classifier_phishing_high",
            "M4 not implemented yet (Track C)",
        )
    ]
