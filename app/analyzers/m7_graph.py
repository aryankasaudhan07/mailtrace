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

from sqlalchemy import and_, select

from app.analyzers.base import register
from app.analyzers.m2_headers import authenticated_origin, is_public_ip
from app.db.models import Indicator
from app.db.session import get_session
from app.schemas.email import ParsedEmail
from app.schemas.evidence import Analyzer, Evidence

# Public mailbox/URL providers: shared by unrelated senders, so their
# registrable domain must NEVER be used to correlate two cases into a campaign.
_PUBLIC_PROVIDERS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "yahoo.com", "ymail.com", "proton.me", "protonmail.com",
    "icloud.com", "me.com", "aol.com", "zoho.com", "gmx.com", "mail.com",
})
# Two-label public suffixes so eTLD+1 is computed correctly (no PSL dependency).
_TWO_LABEL_SUFFIXES = frozenset({
    "co.in", "ac.in", "gov.in", "org.in", "net.in", "edu.in", "res.in", "nic.in",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "co.jp", "com.br",
})


def _registrable_domain(host: str) -> str | None:
    """eTLD+1 for a host, e.g. login.mail.evil.co.in -> evil.co.in. None if bare suffix."""
    labels = host.lower().strip(".").split(".")
    if len(labels) < 2:
        return None
    last_two = ".".join(labels[-2:])
    take = 3 if last_two in _TWO_LABEL_SUFFIXES else 2
    if len(labels) < take:
        return None
    return ".".join(labels[-take:])


def _extract_indicators(email: ParsedEmail) -> dict[str, set[str]]:
    """
    Extract ATTACK-INFRASTRUCTURE indicators for campaign correlation.

    Deliberately NOT the sender's own domain: every legitimate organization
    reuses its sending domain across unrelated mail, so correlating on it makes
    all of an org's messages look like one campaign (a real false positive found
    when testing at scale). Campaigns are keyed on what an attacker provisions
    and reuses -- the relay origin IP, the URLs in the body, attachment hashes --
    not on who the message claims to be from.
    """
    indicators: dict[str, set[str]] = {
        "ip": set(),
        "url": set(),
        "urlreg": set(),
        "hash": set(),
    }

    # Correlate on the AUTHENTICATED origin (boundary.from_ip) -- the one relay IP
    # an attacker cannot forge. Below-boundary IPs are attacker-controllable, so
    # using them as correlation keys invites graph poisoning (fake shared edges)
    # and rotation evasion. Only when no boundary can be resolved do we fall back
    # to a best-effort scan of every routable hop.
    boundary, hops = authenticated_origin(email)
    if boundary is not None and is_public_ip(boundary.from_ip):
        indicators["ip"].add(boundary.from_ip)
    else:
        for hop in hops:
            if is_public_ip(hop.from_ip):
                indicators["ip"].add(hop.from_ip)

    # URL hosts (exact) and their registrable form (clusters per-victim path/
    # subdomain rotation onto one attacker domain).
    for url_obj in email.urls:
        if url_obj.domain:
            host = url_obj.domain.lower()
            indicators["url"].add(host)
            reg = _registrable_domain(host)
            if reg and reg not in _PUBLIC_PROVIDERS:
                indicators["urlreg"].add(reg)

    # Extract attachment hashes
    for att in email.attachments:
        indicators["hash"].add(att.sha256)

    # Flatten for easier querying
    flattened: dict[str, set[str]] = {}
    for kind, values in indicators.items():
        for val in values:
            if val:  # Skip empty values
                if kind not in flattened:
                    flattened[kind] = set()
                flattened[kind].add(val)

    return flattened


def _find_related_cases(indicators: dict[str, set[str]]) -> dict[str, int]:
    """Query which prior cases share any of our indicators."""
    session = get_session()
    related: dict[str, int] = {}  # case_id -> count of shared indicators

    try:
        for kind, values in indicators.items():
            for value in values:
                # Find all cases that have this indicator
                stmt = (
                    select(Indicator.case_id)
                    .where(
                        and_(
                            Indicator.kind == kind,
                            Indicator.value == value,
                        )
                    )
                    .distinct()
                )
                matching_cases = session.execute(stmt).scalars().all()

                for matching_case_id in matching_cases:
                    related[str(matching_case_id)] = related.get(str(matching_case_id), 0) + 1

        return related
    finally:
        session.close()


def _store_indicators(case_id: UUID, indicators: dict[str, set[str]]):
    """Store indicators in the database for future matching."""
    session = get_session()
    try:
        for kind, values in indicators.items():
            for value in values:
                # Check if already exists (upsert)
                stmt = select(Indicator).where(
                    and_(
                        Indicator.case_id == case_id,
                        Indicator.kind == kind,
                        Indicator.value == value,
                    )
                )
                existing = session.execute(stmt).scalar()

                if not existing:
                    ind = Indicator(case_id=case_id, kind=kind, value=value)
                    session.add(ind)

        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


@register(Analyzer.M7_GRAPH)
async def analyze(case_id: UUID, email: ParsedEmail) -> list[Evidence]:
    """Campaign clustering via shared infrastructure."""
    ev: list[Evidence] = []

    try:
        # Extract indicators from this email
        indicators = _extract_indicators(email)

        if not indicators:
            return [
                Evidence.clear(
                    case_id,
                    Analyzer.M7_GRAPH,
                    "campaign_infrastructure_reuse",
                    detail={"summary": "No indicators extracted from email."},
                )
            ]

        # Check if we've seen these indicators before
        related_cases = _find_related_cases(indicators)

        if related_cases:
            # Sort by number of shared indicators
            top_related = sorted(related_cases.items(), key=lambda x: x[1], reverse=True)[0]
            shared_indicator_count = top_related[1]

            ev.append(
                Evidence.triggered(
                    case_id,
                    Analyzer.M7_GRAPH,
                    "campaign_infrastructure_reuse",
                    confidence=min(1.0, shared_indicator_count / 5.0),  # Max out at 5 shared
                    detail={
                        "summary": f"Shared {shared_indicator_count} indicators with prior case(s).",
                        "related_cases": len(related_cases),
                        "shared_indicator_count": shared_indicator_count,
                        "indicators_extracted": sum(len(v) for v in indicators.values()),
                    },
                )
            )
        else:
            # No prior cases with shared indicators
            ev.append(
                Evidence.clear(
                    case_id,
                    Analyzer.M7_GRAPH,
                    "campaign_infrastructure_reuse",
                    detail={
                        "summary": "No shared indicators with prior cases.",
                        "indicators_extracted": sum(len(v) for v in indicators.values()),
                    },
                )
            )

        # Store indicators for future cases
        _store_indicators(case_id, indicators)

        return ev

    except Exception as e:
        # Graceful degradation: if database fails, return unavailable
        return [
            Evidence.unavailable(
                case_id,
                Analyzer.M7_GRAPH,
                "campaign_infrastructure_reuse",
                f"Database unavailable: {type(e).__name__}",
            )
        ]
