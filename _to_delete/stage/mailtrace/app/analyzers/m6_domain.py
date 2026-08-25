"""
M6 -- domain intelligence.

Domain age is the single most predictive cheap feature in phishing detection.
A domain registered eleven days ago asking for a wire transfer needs no ML.

Use RDAP (whoisit), not python-whois: ICANN sunset port-43 gTLD WHOIS in
January 2025, so WHOIS text scraping now silently degrades on more TLDs every
month. Cache the IANA bootstrap to disk and cache results in Redis with a 24h
TTL -- registry RDAP servers rate-limit per source IP.

Owner: Track B
"""

from __future__ import annotations

from uuid import UUID

from app.analyzers.base import register
from app.schemas.email import ParsedEmail
from app.schemas.evidence import Analyzer, Evidence

# Fill this in for whichever institution the demo impersonates. Keep it short;
# a huge brand list produces false positives on legitimate partner domains.
PROTECTED_BRANDS = [
    "aicte-india.org",
    "sbi.co.in",
    "onlinesbi.sbi",
    "incometax.gov.in",
    "npci.org.in",
]


@register(Analyzer.M6_DOMAIN)
async def analyze(case_id: UUID, email: ParsedEmail) -> list[Evidence]:
    # TODO-B: whoisit.domain(d) -> registration date -> domain_age_lt_30d
    #         NOTE: post-GDPR, registrant NAME/EMAIL are redacted for most gTLDs.
    #         Build features on creation date, registrar and nameservers instead.
    # TODO-B: dnspython MX lookup                      -> domain_no_mx
    # TODO-B: confusable_homoglyphs + rapidfuzz vs PROTECTED_BRANDS
    #                                                   -> brand_lookalike_domain
    return [
        Evidence.unavailable(
            case_id, Analyzer.M6_DOMAIN, "domain_age_lt_30d",
            "M6 not implemented yet (Track B)",
        )
    ]
