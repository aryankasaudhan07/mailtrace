"""
M5 -- network intelligence.

Everything that must work offline is a local database read: GeoLite2-City for
city, IPinfo Lite for ASN, the Tor exit list and the VPN/datacenter ranges as
set membership. Online reputation (AbuseIPDB, VirusTotal) is an ENRICHMENT
layer -- cache it in Redis and degrade to UNAVAILABLE, never block on it.

VirusTotal free tier is 4 requests/minute. Pre-warm your demo samples.

Owner: Track D
"""

from __future__ import annotations

from uuid import UUID

from app.analyzers.base import register
from app.schemas.email import ParsedEmail
from app.schemas.evidence import Analyzer, Evidence

# Providers that strip the sender's originating IP for webmail-composed mail.
# When the boundary hop belongs to one of these, we must say so rather than
# geolocating a data centre and calling it the sender. See doc section 07.
ORIGIN_WITHHOLDING_PROVIDERS = {
    "google.com", "gmail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "protonmail.ch", "icloud.com",
}


@register(Analyzer.M5_NETWORK)
async def analyze(case_id: UUID, email: ParsedEmail) -> list[Evidence]:
    # TODO-D: geoip2.database.Reader over intel/GeoLite2-City.mmdb  -> city/country
    # TODO-D: ipinfo_lite.mmdb                                       -> ASN + org
    # TODO-D: intel/tor-exits.txt                                    -> origin_anonymized
    # TODO-D: intel/vpn-ipv4.txt, intel/datacenter-ipv4.txt          -> origin_*
    # TODO-D: AbuseIPDB /check (1000/day)                            -> origin_ip_blocklisted
    # TODO-D: VirusTotal /files/{sha256} (4/min!)                    -> attachment_hash_malicious
    # TODO-D: provider_withholds_origin when the boundary hop is a webmail provider
    return [
        Evidence.unavailable(
            case_id, Analyzer.M5_NETWORK, "origin_ip_blocklisted",
            "M5 not implemented yet (Track D)",
        )
    ]
