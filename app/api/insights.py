"""
Dashboard stats and IP geolocation for the frontend (Track F).

Stats are computed live from the in-process case store. Geolocation reuses M5's
offline GeoLite2 / Tor / VPN / datacenter checks; the abuse-confidence figure is
an explicit heuristic (no paid reputation feed is wired in) and is labelled so.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

import requests
from fastapi import APIRouter, HTTPException

from app.analyzers.m5_network import (
    _check_datacenter,
    _check_tor_exit,
    _check_vpn,
    _geoip_lookup,
)
from app.api.cases import _MEM
from app.config import settings

router = APIRouter(prefix="/api", tags=["insights"])

# High-level threat class for each case, from its strongest positive signal.
_TYPE = {
    "payment_diversion_intent": "BEC", "executive_impersonation": "BEC",
    "credential_harvest_intent": "Phishing", "classifier_phishing_high": "Phishing",
    "brand_lookalike_domain": "Phishing", "fake_reply": "Phishing",
    "hidden_text_mismatch": "Injection",
    "forged_received_hop": "Spoofing", "private_ip_in_public_chain": "Spoofing",
    "spf_fail_hard": "Spoofing", "dmarc_fail_strict": "Spoofing",
    "origin_anonymized": "Anonymized", "campaign_infrastructure_reuse": "Campaign",
}
_BUCKET = {"CRITICAL": "high", "HIGH_RISK": "high", "SUSPICIOUS": "medium", "BENIGN": "low"}


def _threat_type(verdict) -> str:
    pos = sorted((c for c in verdict.contributions if c.points > 0), key=lambda c: -c.points)
    for c in pos:
        if c.signal in _TYPE:
            return _TYPE[c.signal]
    return "Suspicious" if pos else "Clean"


@router.get("/stats")
async def stats() -> dict:
    cases = list(_MEM.values())
    total = len(cases)
    bands = Counter(r["verdict"].band.value for r in cases)
    buckets = Counter(_BUCKET.get(b, "low") for b in (r["verdict"].band.value for r in cases))
    types = Counter(_threat_type(r["verdict"]) for r in cases if r["verdict"].score > 0)

    # 7-day trend, bucketed by analysis day.
    today = datetime.now(timezone.utc).date()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    trend = {d.isoformat(): {"high": 0, "medium": 0, "low": 0} for d in days}
    for r in cases:
        d = r.get("analyzed_at", datetime.now(timezone.utc)).date().isoformat()
        if d in trend:
            trend[d][_BUCKET.get(r["verdict"].band.value, "low")] += 1

    recent = sorted(cases, key=lambda r: r.get("analyzed_at", datetime.min.replace(tzinfo=timezone.utc)), reverse=True)[:6]
    recent_out = [
        {
            "case_id": str(next(k for k, v in _MEM.items() if v is r)),
            "subject": r["email"].subject or r.get("filename") or "(no subject)",
            "band": r["verdict"].band.value,
            "score": r["verdict"].score,
            "analyzed_at": r.get("analyzed_at", datetime.now(timezone.utc)).isoformat(),
        }
        for r in recent
    ]
    return {
        "total": total,
        "buckets": dict(buckets),
        "bands": dict(bands),
        "threat_types": types.most_common(),
        "trend": [{"day": d, **v} for d, v in trend.items()],
        "recent": recent_out,
    }


# --- AbuseIPDB live reputation (cached; degrades to heuristic when absent) ----
_ABUSE_CACHE: dict[str, tuple[float, dict | None]] = {}
_ABUSE_TTL = 6 * 3600  # abuse scores move slowly; cache to respect the 1000/day cap


def _abuseipdb_sync(ip: str, key: str) -> dict | None:
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": key, "Accept": "application/json"},
        timeout=6,
    )
    r.raise_for_status()
    return r.json().get("data")


async def _abuseipdb(ip: str) -> dict | None:
    """Live AbuseIPDB lookup, cached. Returns None if no key or on any failure."""
    key = settings().abuseipdb_key
    if not key:
        return None
    now = time.time()
    hit = _ABUSE_CACHE.get(ip)
    if hit and hit[0] > now:
        return hit[1]
    try:
        data = await asyncio.to_thread(_abuseipdb_sync, ip, key)
    except Exception:
        data = None
    _ABUSE_CACHE[ip] = (now + _ABUSE_TTL, data)
    return data


# --- Keyless online geo fallback, used only when the offline DB is absent -----
_GEO_CACHE: dict[str, tuple[float, dict | None]] = {}
_GEO_TTL = 24 * 3600


def _online_geo_sync(ip: str) -> dict | None:
    r = requests.get(f"https://ipwho.is/{ip}", timeout=6)
    r.raise_for_status()
    d = r.json()
    if not d.get("success"):
        return None
    conn = d.get("connection") or {}
    return {
        "country": d.get("country_code"),
        "city": d.get("city"),
        "latitude": d.get("latitude"),
        "longitude": d.get("longitude"),
        "isp": conn.get("isp") or conn.get("org"),
    }


async def _online_geo(ip: str) -> dict | None:
    """Free, no-key geolocation (ipwho.is), cached. None on any failure."""
    now = time.time()
    hit = _GEO_CACHE.get(ip)
    if hit and hit[0] > now:
        return hit[1]
    try:
        data = await asyncio.to_thread(_online_geo_sync, ip)
    except Exception:
        data = None
    _GEO_CACHE[ip] = (now + _GEO_TTL, data)
    return data


def _risk(score: int) -> str:
    return "High" if score >= 70 else "Medium" if score >= 35 else "Low"


@router.get("/geo")
async def geo(ip: str) -> dict:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "invalid IP address") from None

    try:
        is_global = ipaddress.ip_address(ip).is_global
    except ValueError:
        is_global = False
    private = not is_global

    # Offline GeoLite2 is primary; fall back to a free online lookup only when the
    # DB isn't present (e.g. the cloud deploy) and the IP is routable.
    g = _geoip_lookup(ip) or {}
    geo_source = "GeoLite2 (offline)" if g.get("latitude") is not None else None
    if g.get("latitude") is None and is_global:
        online = await _online_geo(ip)
        if online:
            g = online
            geo_source = "ipwho.is (live lookup)"

    tor = _check_tor_exit(ip)
    vpn = _check_vpn(ip)
    dc = _check_datacenter(ip)

    feed = await _abuseipdb(ip)

    if feed is not None:
        # ---- real, live reputation from AbuseIPDB ----
        score = int(feed.get("abuseConfidenceScore", 0))
        usage = feed.get("usageType") or ""
        hosting = dc or "hosting" in usage.lower() or "data center" in usage.lower()
        reputation = {
            "abuse_confidence": score,
            "risk": _risk(score),
            "tor_exit": bool(feed.get("isTor", tor)),
            "vpn_proxy": vpn or hosting,
            "hosting": hosting,
            "total_reports": feed.get("totalReports"),
            "last_reported": feed.get("lastReportedAt"),
            "usage_type": usage or None,
            "recent_abuse": "High" if (feed.get("totalReports") or 0) >= 20 else "Low",
            "source": "AbuseIPDB (live, cached 6h)",
        }
        isp = feed.get("isp") or g.get("isp") or ("Datacenter / hosting" if dc else "Unknown")
        country = feed.get("countryCode") or g.get("country")
    else:
        # ---- offline heuristic fallback (no key / no network) ----
        score = min(95, 8 + (62 if tor else 0) + (24 if vpn else 0) + (18 if dc else 0) + (40 if private else 0))
        reputation = {
            "abuse_confidence": score,
            "risk": _risk(score),
            "tor_exit": tor,
            "vpn_proxy": vpn or dc,
            "hosting": dc,
            "recent_abuse": "High" if score >= 70 else "Low",
            "source": "heuristic (Tor/VPN/DC lists; add ABUSEIPDB_KEY for live scores)",
        }
        isp = ("Anonymized (Tor)" if tor else "Datacenter / hosting" if dc else g.get("isp") or "Unknown")
        country = g.get("country")

    return {
        "ip": ip,
        "country": country,
        "city": g.get("city"),
        "latitude": g.get("latitude"),
        "longitude": g.get("longitude"),
        "isp": isp,
        "org": isp,
        "geo_source": geo_source,
        "reputation": reputation,
    }
