"""
M6 -- domain intelligence.

Domain age is the single most predictive cheap feature in phishing detection.
A domain registered eleven days ago asking for a wire transfer needs no ML.

Use whoisit (RDAP), not python-whois: ICANN sunset port-43 gTLD WHOIS.
Cache results in memory for this demo.

Owner: Track B
"""

from __future__ import annotations

import unicodedata
from datetime import datetime, timezone
from uuid import UUID

try:
    import whoisit
except ImportError:
    whoisit = None

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    from rapidfuzz import fuzz
except ImportError:
    fuzz = None

from app.analyzers.base import register
from app.schemas.email import ParsedEmail
from app.schemas.evidence import Analyzer, Evidence

# Brands to protect (from CLAUDE.md)
PROTECTED_BRANDS = [
    "aicte-india.org",
    "sbi.co.in",
    "onlinesbi.sbi",
    "incometax.gov.in",
    "npci.org.in",
]


def _domain_age_days(domain: str) -> int | None:
    """Get domain age in days from WHOIS/RDAP."""
    if whoisit is None:
        return None

    try:
        result = whoisit.query(domain, timeout=5)

        if not result or not result.created:
            return None

        created = result.created
        if isinstance(created, list):
            created = created[0]

        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age = (now - created).days
        return age
    except Exception:
        return None


def _check_dns(domain: str) -> dict:
    """Check if domain has MX and A records."""
    result = {"has_mx": False, "has_a": False, "mx_records": []}

    if dns is None:
        return result

    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        result["has_mx"] = True
        result["mx_records"] = [str(r.exchange).rstrip(".") for r in answers]
    except Exception:
        pass

    try:
        dns.resolver.resolve(domain, "A", lifetime=5)
        result["has_a"] = True
    except Exception:
        pass

    return result


# Unicode look-alikes (Cyrillic/Greek/digit) folded to their Latin twin, so a
# homograph domain reduces to the same "skeleton" as the brand it mimics.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "н": "h", "к": "k", "м": "m", "т": "t", "в": "b",
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "τ": "t", "ν": "v", "ι": "i", "κ": "k",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
})


def _decode_idna(domain: str) -> str:
    """Decode punycode (xn--) labels to unicode so homographs become visible."""
    if "xn--" not in domain:
        return domain
    try:
        return domain.encode("ascii").decode("idna")
    except Exception:
        return domain


def _skeleton(s: str) -> str:
    """NFKC-fold, lowercase, and map confusable characters to a Latin skeleton."""
    return unicodedata.normalize("NFKC", s).lower().translate(_CONFUSABLES)


def _tokens(skel: str) -> set[str]:
    """Alphanumeric labels/tokens (split on dot and hyphen), len>=4 only."""
    out: set[str] = set()
    for part in skel.replace("-", ".").split("."):
        if len(part) >= 4:
            out.add(part)
    return out


def _check_brand_lookalike(domain: str) -> tuple[str, str] | None:
    """
    Detect impersonation of a protected brand, including homographs and
    brand-name-in-subdomain spoofs. Returns (brand, technique) or None.

    The exact checks (homograph collision, brand-name-as-label) run even without
    rapidfuzz installed; only the fuzzy typosquat check needs it.
    """
    raw = domain.lower().strip(".")

    # A domain that IS a protected brand (or a subdomain of one) is legitimate --
    # checked on the raw string so a homograph of a brand is not let through here.
    for brand in PROTECTED_BRANDS:
        b = brand.lower()
        if raw == b or raw.endswith("." + b):
            return None

    uni = _decode_idna(raw)
    skel = _skeleton(uni)
    labels = skel.split(".")
    non_tld = labels[:-1] if len(labels) > 1 else labels   # exclude the TLD label
    non_tld_tokens = _tokens(".".join(non_tld))
    sig = max(non_tld, key=len) if non_tld else ""          # most significant label
    homographed = (uni != raw) or ("xn--" in raw) or any(ord(c) > 127 for c in raw)

    for brand in PROTECTED_BRANDS:
        b = brand.lower()
        b_skel = _skeleton(b)
        b_core = b_skel.split(".")[0]           # e.g. "sbi", "aicte-india", "npci"

        # 1. Whole-domain homograph collision (visually identical after folding).
        if skel == b_skel:
            return (brand, "homograph" if homographed else "typosquat")

        # 2. The brand's core label appears verbatim outside the TLD position
        #    (dotted label or hyphen token) -> subdomain/prefix spoof, e.g.
        #    sbi.co.in.secure-login.tk or npci-refund.tk.
        if b_core in non_tld or b_core in non_tld_tokens:
            return (brand, "brand-name-in-domain")

        # 3. Fuzzy typosquat of the significant label (paypa1 -> paypal).
        if fuzz is not None and len(b_core) >= 4:
            if fuzz.ratio(sig, b_core) >= 82:
                return (brand, "homograph" if homographed else "typosquat")
            for bt in (_tokens(b_core) or {b_core}):
                if len(bt) >= 5 and any(fuzz.ratio(t, bt) >= 85 for t in non_tld_tokens):
                    return (brand, "typosquat")

    return None


@register(Analyzer.M6_DOMAIN)
async def analyze(case_id: UUID, email: ParsedEmail) -> list[Evidence]:
    """Analyze sender domain for age, DNS records, and brand lookalike."""
    ev: list[Evidence] = []

    from_domain = email.from_addr.split("@")[-1].lower() if email.from_addr else None
    if not from_domain:
        return [
            Evidence.unavailable(
                case_id,
                Analyzer.M6_DOMAIN,
                "domain_age_lt_30d",
                "No From domain found",
            )
        ]

    # Check domain age
    age_days = _domain_age_days(from_domain)
    if age_days is not None and age_days < 30:
        ev.append(
            Evidence.triggered(
                case_id,
                Analyzer.M6_DOMAIN,
                "domain_age_lt_30d",
                detail={
                    "age_days": age_days,
                    "explanation": f"Domain registered only {age_days} days ago — common phishing pattern.",
                },
            )
        )

    # Check DNS records
    dns_result = _check_dns(from_domain)

    if not dns_result["has_mx"]:
        ev.append(
            Evidence.triggered(
                case_id,
                Analyzer.M6_DOMAIN,
                "domain_no_mx",
                detail={
                    "domain": from_domain,
                    "explanation": "No MX (mail server) records found — domain is not properly configured to send email.",
                },
            )
        )

    if not dns_result["has_a"]:
        ev.append(
            Evidence.triggered(
                case_id,
                Analyzer.M6_DOMAIN,
                "domain_does_not_resolve",
                detail={
                    "domain": from_domain,
                    "explanation": "Domain does not resolve (no A record) — possibly abandoned or spoofed.",
                },
            )
        )

    # Check for brand lookalike (homograph / typosquat / subdomain spoof)
    lookalike = _check_brand_lookalike(from_domain)
    if lookalike:
        brand, technique = lookalike
        reasons = {
            "homograph": f"uses look-alike characters to imitate '{brand}'",
            "typosquat": f"is a near-misspelling of protected brand '{brand}'",
            "brand-name-in-domain": f"places the protected brand '{brand}' in a domain it does not own",
        }
        ev.append(
            Evidence.triggered(
                case_id,
                Analyzer.M6_DOMAIN,
                "brand_lookalike_domain",
                detail={
                    "domain": from_domain,
                    "similar_to": brand,
                    "technique": technique,
                    "explanation": f"Domain '{from_domain}' {reasons.get(technique, 'imitates a protected brand')}.",
                },
            )
        )

    # If nothing found, return CLEAR
    if not ev:
        ev.append(
            Evidence.clear(
                case_id,
                Analyzer.M6_DOMAIN,
                "domain_age_lt_30d",
                detail={
                    "domain": from_domain,
                    "explanation": "Domain appears legitimate (not new, has MX records, resolves, not a lookalike).",
                },
            )
        )

    return ev
