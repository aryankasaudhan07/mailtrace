"""
M7 -- correlation and campaign clustering.

Nodes: emails, domains, IPs, ASNs, attachment hashes. An edge exists when two
cases share an indicator. Connected components are campaigns.

The one trap: cluster against the `indicators` table (everything ever seen),
not against confirmed-malicious cases only, or campaigns never form.

Owner: Track E
"""

from __future__ import annotations

from uuid import UUID

from app.analyzers.base import register
from app.schemas.email import ParsedEmail
from app.schemas.evidence import Analyzer, Evidence


@register(Analyzer.M7_GRAPH)
async def analyze(case_id: UUID, email: ParsedEmail) -> list[Evidence]:
    # TODO-E: write this case's indicators, then look for overlap with prior
    #         cases -> campaign_infrastructure_reuse
    # TODO-E: known_correspondent (-20) when this sender has >= 3 prior clean cases
    return [
        Evidence.unavailable(
            case_id, Analyzer.M7_GRAPH, "campaign_infrastructure_reuse",
            "M7 not implemented yet (Track E)",
        )
    ]
