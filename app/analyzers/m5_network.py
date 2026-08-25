"""
M5 -- network intelligence.

Everything that must work offline is a local database read: GeoLite2-City for
city, IPinfo Lite for ASN, the Tor exit list and the VPN/datacenter ranges as
set membership.

Requires data files in intel/ directory:
  • GeoLite2-City.mmdb (MaxMind)
  • tor-exits.txt (Tor project)
  • vpn-ipv4.txt (VPN IP ranges)
  • datacenter-ipv4.txt (Datacenter IP ranges)

Owner: Track D
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from uuid import UUID

try:
    import geoip2.database
except ImportError:
    geoip2 = None

from app.analyzers.base import register
from app.analyzers.m2_headers import authenticated_origin, is_public_ip
from app.schemas.email import ParsedEmail
from app.schemas.evidence import Analyzer, Evidence

INTEL_DIR = Path(__file__).resolve().parents[2] / "intel"

# Webmail providers that strip the sender's originating IP for browser-composed
# mail (see CLAUDE.md / THREAT-MODEL). When the origin IP is absent AND the
# sender is one of these, that is evidence to record, not a clean bill of health.
_WEBMAIL_PROVIDERS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "yahoo.com", "ymail.com", "proton.me", "protonmail.com",
})


def _load_ip_set(filename: str) -> set[str]:
    """Load IP ranges from a text file (one per line)."""
    filepath = INTEL_DIR / filename
    ips = set()

    if not filepath.exists():
        return ips

    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ips.add(line)
    except Exception:
        pass

    return ips


def _ip_in_range_set(ip_str: str, ip_ranges: set[str]) -> bool:
    """Check if an IP is in any of the ranges (supports CIDR notation)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for ip_range in ip_ranges:
            try:
                network = ipaddress.ip_network(ip_range, strict=False)
                if ip in network:
                    return True
            except ValueError:
                # Not a valid CIDR range, skip
                continue
        return False
    except ValueError:
        return False


def _check_tor_exit(ip_str: str) -> bool:
    """Check if IP is a known Tor exit node."""
    tor_exits = _load_ip_set("tor-exits.txt")
    return ip_str in tor_exits


def _check_vpn(ip_str: str) -> bool:
    """Check if IP is in a known VPN range."""
    vpn_ranges = _load_ip_set("vpn-ipv4.txt")
    return _ip_in_range_set(ip_str, vpn_ranges)


def _check_datacenter(ip_str: str) -> bool:
    """Check if IP is in a known datacenter range."""
    datacenter_ranges = _load_ip_set("datacenter-ipv4.txt")
    return _ip_in_range_set(ip_str, datacenter_ranges)


def _geoip_lookup(ip_str: str) -> dict | None:
    """Look up IP in GeoLite2-City database."""
    if geoip2 is None:
        return None

    mmdb_path = INTEL_DIR / "GeoLite2-City.mmdb"
    if not mmdb_path.exists():
        return None

    try:
        with geoip2.database.Reader(str(mmdb_path)) as reader:
            response = reader.city(ip_str)
            return {
                "country": response.country.iso_code,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
            }
    except Exception:
        return None


@register(Analyzer.M5_NETWORK)
async def analyze(case_id: UUID, email: ParsedEmail) -> list[Evidence]:
    """Network intelligence analysis using offline databases.

    SECURITY NOTE -- the authenticated origin, not the claimed one:
    the bottom-most Received hop (seq=0) is fully attacker-forgeable. We resolve
    the trust boundary (M2) to get boundary.from_ip -- the IP the last relay we
    can authenticate received from -- and treat THAT as the true origin. We still
    scan the whole chain for anonymizers (so a Tor relay is never missed), but a
    hit BELOW the boundary is attacker-controllable and reported at reduced
    confidence. When no hop can be authenticated (boundary is None) we fall back
    to a best-effort whole-chain scan. See CLAUDE.md "bottom-most IP".
    """
    boundary, hops = authenticated_origin(email)

    # Every hop that carries a routable, geolocatable source IP, in transmission
    # order (seq=0 = claimed origin ... highest seq = final delivery).
    routable = [h for h in hops if is_public_ip(h.from_ip)]

    # Which intel is on disk? Missing a file just disables that one check.
    has_geoip = (INTEL_DIR / "GeoLite2-City.mmdb").exists()
    has_tor = (INTEL_DIR / "tor-exits.txt").exists()
    has_vpn = (INTEL_DIR / "vpn-ipv4.txt").exists()
    has_datacenter = (INTEL_DIR / "datacenter-ipv4.txt").exists()

    if not any([has_geoip, has_tor, has_vpn, has_datacenter]):
        return [
            Evidence.unavailable(
                case_id,
                Analyzer.M5_NETWORK,
                "origin_anonymized",
                "M5 unavailable: no intel data files in intel/. Run scripts/fetch_intel.sh "
                "to fetch GeoLite2-City.mmdb, tor-exits.txt, vpn-ipv4.txt, datacenter-ipv4.txt",
            )
        ]

    # No routable source IP anywhere. Distinguish a webmail provider that strips
    # the origin (evidentiary) from a genuinely empty chain (clean).
    if not routable:
        from_domain = (email.from_addr or "").rsplit("@", 1)[-1].lower()
        if from_domain in _WEBMAIL_PROVIDERS:
            return [
                Evidence.triggered(
                    case_id,
                    Analyzer.M5_NETWORK,
                    "provider_withholds_origin",
                    detail={
                        "provider": from_domain,
                        "explanation": (
                            f"{from_domain} strips the sender's originating IP for "
                            "webmail-composed mail; it is not recoverable from the headers. "
                            "Geolocation confidence is zero. Lawful next step: a preservation "
                            "request to the provider."
                        ),
                    },
                )
            ]
        return [
            Evidence.clear(
                case_id,
                Analyzer.M5_NETWORK,
                "origin_anonymized",
                detail={"explanation": "No routable source IP present in the relay chain."},
            )
        ]

    ev: list[Evidence] = []

    # The authenticated origin (boundary.from_ip) if we have one, else the
    # best-effort earliest routable hop.
    if boundary is not None and is_public_ip(boundary.from_ip):
        origin_hop = boundary
    else:
        origin_hop = routable[0]

    def _trust_conf(hop) -> float:
        # A hit at or above the boundary is authenticated; below it the attacker
        # could have written the hop, so we still report but at lower confidence.
        if boundary is None or hop.seq >= boundary.seq:
            return 1.0
        return 0.7

    # --- Anonymizer (Tor / VPN): scan the whole chain, report the lowest-seq hit.
    anon_hit = None
    for hop in routable:
        if has_tor and _check_tor_exit(hop.from_ip):
            anon_hit = (hop, "Tor exit node")
            break
        if has_vpn and _check_vpn(hop.from_ip):
            anon_hit = (hop, "known VPN range")
            break
    if anon_hit:
        hop, kind = anon_hit
        conf = _trust_conf(hop)
        region = "authenticated origin" if conf == 1.0 else "unverified region below the trust boundary"
        ev.append(
            Evidence.triggered(
                case_id,
                Analyzer.M5_NETWORK,
                "origin_anonymized",
                confidence=conf,
                detail={
                    "ip": hop.from_ip,
                    "hop_seq": hop.seq,
                    "classification": kind,
                    "trust_region": region,
                    "explanation": (
                        f"Relay hop {hop.seq} ({hop.from_ip}) is a {kind} — the sender "
                        f"anonymized their origin. This hop is in the {region}."
                    ),
                },
            )
        )

    # --- Datacenter-hosted origin: test the authenticated origin only (our own
    # delivery MTAs sit high in the chain and are often datacenter-hosted too).
    if has_datacenter and _check_datacenter(origin_hop.from_ip):
        ev.append(
            Evidence.triggered(
                case_id,
                Analyzer.M5_NETWORK,
                "origin_datacenter_hosted",
                confidence=_trust_conf(origin_hop),
                detail={
                    "ip": origin_hop.from_ip,
                    "hop_seq": origin_hop.seq,
                    "explanation": "Authenticated origin is a datacenter range, "
                                   "not an eyeball/residential network.",
                },
            )
        )

    # --- GeoIP: country-level consistency for the report, never scored --------
    geo = _geoip_lookup(origin_hop.from_ip) if has_geoip else None

    if not ev:
        detail: dict = {
            "ip": origin_hop.from_ip,
            "hops_checked": len(routable),
            "explanation": (
                f"No hop in the chain ({len(routable)} routable) matches Tor, VPN or "
                "datacenter ranges."
            ),
        }
        if geo:
            detail["geo"] = geo
        ev.append(
            Evidence.clear(case_id, Analyzer.M5_NETWORK, "origin_anonymized", detail=detail)
        )

    return ev
