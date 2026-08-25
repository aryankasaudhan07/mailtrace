"""
domain_analysis.py
-------------------
Adds "domain intelligence" to the pipeline — the piece the official
problem statement calls out separately from IP geolocation:

    "Domain intelligence analysis using WHOIS data, DNS records, MX
     records, hosting fingerprints, and registrar details to identify
     suspicious sender infrastructure."

What this checks, in plain language:
  1. WHOIS lookup  -> When was this domain registered? A domain that's
     only a few days/weeks old and is already sending "urgent payment"
     emails is a massive red flag (this is one of the single strongest
     phishing signals used by real security tools).
  2. MX records    -> Does this domain even have valid mail servers
     configured? A domain with no MX record has no business sending
     email — it's a strong sign of a spoofed/forged sender address.
  3. DNS/A records -> Does the domain resolve at all? A completely
     dead/unregistered domain being used as a "From" address is another
     spoofing indicator.

Requires (not pre-installed — install these on a machine with internet):
    pip install python-whois dnspython

Usage:
    from domain_analysis import analyze_domain
    result = analyze_domain("paypa1-secure.com")

NOTE: This module needs internet access to actually query WHOIS/DNS
servers. It could not be live-tested in this build environment (no
network access here) — test it on your own laptop before demo day,
using a mix of a known-old legitimate domain (e.g. "google.com") and
a domain from one of your sample phishing emails.
"""

from datetime import datetime, timezone

try:
    import whois  # python-whois package
except ImportError:
    whois = None

try:
    import dns.resolver  # dnspython package
except ImportError:
    dns = None


def _domain_age_days(creation_date) -> int | None:
    """WHOIS libraries sometimes return a list of dates instead of one
    (different registrars format their WHOIS records differently) —
    this handles both cases and returns age in days."""
    if creation_date is None:
        return None
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return (now - creation_date).days


def check_whois(domain: str) -> dict:
    """Looks up registration info for a domain."""
    if whois is None:
        return {"error": "python-whois not installed — run: pip install python-whois"}
    try:
        w = whois.whois(domain)
        age_days = _domain_age_days(w.creation_date)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "domain_age_days": age_days,
            "is_newly_registered": (age_days is not None and age_days < 30),
        }
    except Exception as e:
        return {"error": str(e)}


def check_dns(domain: str) -> dict:
    """Checks whether the domain has valid MX (mail) and A (address) records."""
    if dns is None:
        return {"error": "dnspython not installed — run: pip install dnspython"}

    result = {"has_mx_records": False, "mx_records": [], "has_a_record": False}

    try:
        answers = dns.resolver.resolve(domain, "MX")
        result["has_mx_records"] = True
        result["mx_records"] = [str(r.exchange).rstrip(".") for r in answers]
    except Exception:
        pass  # no MX records found — stays False

    try:
        dns.resolver.resolve(domain, "A")
        result["has_a_record"] = True
    except Exception:
        pass

    return result


def analyze_domain(domain: str) -> dict:
    """
    Combines WHOIS + DNS checks into one risk-flagged result.
    This is the function pipeline.py calls.
    """
    domain = domain.strip().lower()
    whois_result = check_whois(domain)
    dns_result = check_dns(domain)

    risk_flags = []
    if whois_result.get("is_newly_registered"):
        risk_flags.append(
            f"Domain registered only {whois_result['domain_age_days']} days ago — common phishing pattern"
        )
    if dns_result.get("has_mx_records") is False and "error" not in dns_result:
        risk_flags.append("No MX (mail server) records found — domain is not properly configured to send email")
    if dns_result.get("has_a_record") is False and "error" not in dns_result:
        risk_flags.append("Domain does not resolve (no A record) — possibly abandoned or spoofed")

    return {
        "domain": domain,
        "whois": whois_result,
        "dns": dns_result,
        "risk_flags": risk_flags,
    }


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("Usage: python domain_analysis.py example.com")
        sys.exit(1)

    print(json.dumps(analyze_domain(sys.argv[1]), indent=2, default=str))
