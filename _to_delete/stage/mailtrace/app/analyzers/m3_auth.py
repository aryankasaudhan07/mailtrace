"""
M3 -- SPF / DKIM / DMARC re-verification.

Important: do NOT trust the Authentication-Results header. Below the trust
boundary it is attacker-supplied like everything else. Re-verify from
email.raw_bytes, which M1 kept on the object precisely for this.

Owner: Track B
"""

from __future__ import annotations

from uuid import UUID

from app.analyzers.base import register
from app.schemas.email import ParsedEmail
from app.schemas.evidence import Analyzer, Evidence


@register(Analyzer.M3_AUTH)
async def analyze(case_id: UUID, email: ParsedEmail) -> list[Evidence]:
    # TODO-B: dkimpy   -> verify each signature; report dkim_valid_aligned (-25)
    #                     only when d= aligns with the From domain.
    # TODO-B: pyspf    -> check(i=connecting_ip, s=return_path, h=helo_host)
    #                     using the BOUNDARY hop's IP from M2, not hop 0.
    # TODO-B: checkdmarc -> fetch the policy, evaluate alignment (relaxed/strict).
    #
    # Emit: dmarc_fail_strict, spf_fail_hard, dkim_missing, dkim_valid_aligned
    return [
        Evidence.unavailable(
            case_id, Analyzer.M3_AUTH, "dmarc_fail_strict",
            "M3 not implemented yet (Track B)",
        )
    ]
