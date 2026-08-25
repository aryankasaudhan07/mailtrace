"""
M2 -- header and relay forensics. THE headline module.

What is done for you: Received: header parsing into an ordered Hop list, and
three worked-example anomaly checks so you can see the pattern.

What YOU must implement (marked TODO-A below): trust boundary resolution and
the remaining anomaly checks. This is deliberate -- it is the most important
logic in the product and the thing a judge is most likely to question you on,
so the track that owns it should write it.

Read architecture doc section 03 before you start.

Owner: Track A
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from uuid import UUID

from app.analyzers.base import register
from app.schemas.email import Hop, HopTrust, ParsedEmail
from app.schemas.evidence import Analyzer, Evidence

# Received: headers are free-form in practice. These patterns cover the great
# majority of real-world MTAs; expect to extend them as you test against the
# Nazario corpus.
FROM_RE = re.compile(
    r"""\bfrom\s+
        (?P<host>[A-Za-z0-9._\-]+)?           # announced hostname (often absent)
        \s*
        (?:\(
            (?:(?P<rdns>[A-Za-z0-9._\-]+)\s*)?  # reverse DNS as seen by the receiver
            \[(?P<ip>[0-9a-fA-F:.]+)\]          # the actual connecting IP
        \))?
    """,
    re.IGNORECASE | re.VERBOSE,
)
BY_RE = re.compile(r"\bby\s+(?P<host>[A-Za-z0-9._\-]+)", re.IGNORECASE)
WITH_RE = re.compile(r"\bwith\s+(?P<proto>[A-Za-z0-9]+)", re.IGNORECASE)
BARE_IP_RE = re.compile(r"\[(?P<ip>[0-9a-fA-F:.]+)\]")


def parse_hops(email: ParsedEmail) -> list[Hop]:
    """
    Build the relay chain.

    Received: headers are PREPENDED by each MTA, so headers[0] is the LAST hop
    and the final header is the FIRST (claimed) hop. We reverse them so that
    seq=0 is the claimed origin and the highest seq is final delivery -- i.e.
    seq ascends in transmission order.
    """
    received = [v for k, v in email.headers if k.lower() == "received"]
    hops: list[Hop] = []

    for seq, raw in enumerate(reversed(received)):
        flat = " ".join(raw.split())

        from_host = from_ip = rdns = None
        m = FROM_RE.search(flat)
        if m:
            from_host = (m.group("host") or "").strip() or None
            from_ip = m.group("ip")
            rdns = m.group("rdns")
        if from_ip is None:
            # e.g. "from [203.0.113.44] by ..." with no announced hostname
            bare = BARE_IP_RE.search(flat.split(" by ")[0] if " by " in flat else flat)
            from_ip = bare.group("ip") if bare else None

        by = BY_RE.search(flat)
        proto = WITH_RE.search(flat)

        ts: datetime | None = None
        if ";" in flat:
            try:
                ts = parsedate_to_datetime(flat.rsplit(";", 1)[1].strip())
            except (TypeError, ValueError, IndexError):
                ts = None

        hops.append(
            Hop(
                seq=seq,
                raw=raw,
                from_host=from_host,
                from_ip=_clean_ip(from_ip),
                by_host=by.group("host") if by else None,
                protocol=proto.group("proto").upper() if proto else None,
                timestamp=ts,
                trust=HopTrust.UNVERIFIED,
                anomalies=[],
                geo=None,
            )
        )
        if rdns and hops[-1].from_host is None:
            hops[-1].from_host = rdns

    return hops


def _clean_ip(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip().lower()
    if v.startswith("ipv6:"):
        v = v[5:]
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# IP classification.
#
# Careful here -- this bit an early version of the code. `ipaddress.is_global`
# is NOT the right test. It returns False for the RFC 5737 documentation ranges
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which is technically correct
# but means every test fixture and every sanitised corpus sample gets flagged as
# an injected hop. Your demo then "detects" forgery in the benign control.
#
# What actually indicates an injected hop is an address that could never have
# carried traffic across the public internet: RFC 1918 private space, loopback,
# link-local, CGNAT, or unspecified. Documentation ranges stand in for public
# addresses and must pass.
# ---------------------------------------------------------------------------
CGNAT = ipaddress.ip_network("100.64.0.0/10")


def is_unroutable_ip(ip: str | None) -> bool:
    """True when this address cannot legitimately appear in public transit."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 4 and addr in CGNAT:
        return True
    if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        return True
    # Note: Python marks the RFC 5737 documentation ranges as `is_private`,
    # hence the explicit exclusion.
    return addr.is_private and not _is_documentation(addr)


def _is_documentation(addr) -> bool:
    """RFC 5737 (v4) / RFC 3849 (v6) ranges reserved for documentation."""
    if addr.version == 4:
        return any(
            addr in ipaddress.ip_network(n)
            for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
        )
    return addr in ipaddress.ip_network("2001:db8::/32")


def is_public_ip(ip: str | None) -> bool:
    """
    Routable-or-documentation, i.e. "acceptable in a relay chain".
    Kept as the inverse of is_unroutable_ip so call sites read naturally.
    """
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not is_unroutable_ip(ip)


# ---------------------------------------------------------------------------
# TODO-A :: Track A implements this. Everything else in the product waits on it.
# ---------------------------------------------------------------------------
def resolve_trust_boundary(hops: list[Hop], trusted_hosts: set[str],
                           trusted_cidrs: list[str]) -> Hop | None:
    """
    Mark each hop TRUSTED / BOUNDARY / UNVERIFIED and return the boundary hop.

    Algorithm (see architecture doc section 03):
      1. Walk from the HIGHEST seq (final delivery) downwards.
      2. A hop is TRUSTED if its `by_host` matches a trusted host, or its
         `from_ip` falls inside a trusted CIDR, or it is a provider hop
         corroborated by a passing DKIM signature (ask Track B for that input).
      3. The LAST trusted hop as you descend is the BOUNDARY. The IP it
         received *from* is the highest-confidence origin.
      4. Every hop below the boundary is UNVERIFIED -- the attacker could have
         written it. Do not geolocate it, and say so in the report.

    Returns the boundary hop, or None when no hop can be trusted (in which case
    the whole chain is unverified and confidence must reflect that).
    """
    raise NotImplementedError("Track A: implement before phase 3 ends")


@register(Analyzer.M2_HEADERS)
async def analyze(case_id: UUID, email: ParsedEmail) -> list[Evidence]:
    ev: list[Evidence] = []
    hops = parse_hops(email)

    # ---- worked example 1: private IP where a public relay should be ----
    for hop in hops:
        if is_unroutable_ip(hop.from_ip):
            ev.append(
                Evidence.triggered(
                    case_id, Analyzer.M2_HEADERS, "private_ip_in_public_chain",
                    detail={
                        "hop": hop.seq,
                        "ip": hop.from_ip,
                        "explanation": "A private or reserved address cannot appear "
                                       "in legitimate public transit; this hop was "
                                       "almost certainly injected.",
                    },
                )
            )
            break
    else:
        ev.append(Evidence.clear(case_id, Analyzer.M2_HEADERS,
                                "private_ip_in_public_chain"))

    # ---- worked example 2: timestamps running backwards ----
    stamped = [h for h in hops if h.timestamp]
    regressed = next(
        (
            (a, b)
            # strict=False is correct: this is a pairwise walk, so the
            # sequences are deliberately different lengths.
            for a, b in zip(stamped, stamped[1:], strict=False)
            if b.timestamp < a.timestamp  # type: ignore[operator]
        ),
        None,
    )
    if regressed:
        a, b = regressed
        ev.append(
            Evidence.triggered(
                case_id, Analyzer.M2_HEADERS, "timestamp_regression",
                detail={"hop": b.seq, "after_hop": a.seq,
                        "explanation": "A later hop is dated earlier than the hop "
                                       "before it, which is physically impossible."},
            )
        )
    else:
        ev.append(Evidence.clear(case_id, Analyzer.M2_HEADERS, "timestamp_regression"))

    # ---- worked example 3: the BEC reply-diversion triangle ----
    from_dom = _domain(email.from_addr)
    reply_dom = _domain(email.reply_to)
    if from_dom and reply_dom and from_dom != reply_dom:
        ev.append(
            Evidence.triggered(
                case_id, Analyzer.M2_HEADERS, "reply_to_domain_mismatch",
                detail={"from_domain": from_dom, "reply_to_domain": reply_dom,
                        "explanation": "Replies would be delivered to a different "
                                       "domain than the apparent sender."},
            )
        )
    else:
        ev.append(Evidence.clear(case_id, Analyzer.M2_HEADERS,
                                "reply_to_domain_mismatch"))

    # TODO-A: forged_received_hop  (needs resolve_trust_boundary)
    # TODO-A: chain_discontinuity  (hop N `by` != hop N+1 `from`)
    # TODO-A: rdns_mismatch        (dnspython reverse lookup vs announced host)
    # TODO-A: message_id_domain_divergence
    return ev


def _domain(addr: str | None) -> str | None:
    if not addr or "@" not in addr:
        return None
    return addr.rsplit("@", 1)[1].strip().lower()
