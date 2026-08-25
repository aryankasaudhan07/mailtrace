"""
M3 -- SPF / DKIM / DMARC re-verification.

Important: do NOT trust the Authentication-Results header. Below the trust
boundary it is attacker-supplied like everything else. Re-verify from
email.raw_bytes, which M1 kept on the object precisely for this.

DKIM is verified cryptographically from the raw bytes (offline-capable: a
missing or broken signature is detectable with no network). SPF and DMARC need
DNS; when it is unreachable they degrade to "not checked", never to a guess.

DMARC is a PASS/FAIL of alignment, never of policy strength: a domain that
publishes p=reject is well-secured, not suspicious. We only raise
dmarc_fail_strict when authentication actually fails alignment AND the domain
asked us to reject/quarantine such mail.

Owner: Track B
"""

from __future__ import annotations

import re
from uuid import UUID

try:
    import spf  # pyspf
except ImportError:
    spf = None

try:
    import dkim  # dkimpy -- the import name is 'dkim', NOT 'dkimpy'
except ImportError:
    dkim = None

try:
    import dns.resolver  # dnspython, for the DMARC TXT lookup
except ImportError:
    dns = None

from app.analyzers.base import register
from app.analyzers.m2_headers import authenticated_origin
from app.schemas.email import ParsedEmail
from app.schemas.evidence import Analyzer, Evidence

_DMARC_P_RE = re.compile(r"[;\s]p\s*=\s*(\w+)", re.IGNORECASE)
_DKIM_D_RE = re.compile(r"[;\s]d\s*=\s*([^;]+)", re.IGNORECASE)


def _domain_of(addr: str | None) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1].strip().lower().rstrip(">")


def _aligned(a: str, b: str) -> bool:
    """Relaxed alignment: same domain, or one is the other's organizational parent."""
    if not a or not b:
        return False
    a, b = a.lower(), b.lower()
    return a == b or a.endswith("." + b) or b.endswith("." + a)


# --- SPF ---------------------------------------------------------------------
def _verify_spf(case_id: UUID, email: ParsedEmail, client_ip: str | None) -> tuple[Evidence | None, bool]:
    """Return (hard-fail evidence or None, spf_aligned_pass).

    client_ip is the IP that connected to our trust boundary (M2). When it is
    known we check SPF against it; otherwise SPF is skipped rather than guessed.
    """
    if spf is None:
        return None, False
    try:
        ip = client_ip
        if not ip:
            return None, False

        # Envelope sender (MAIL FROM) domain drives SPF; fall back to From.
        mail_from_domain = _domain_of(email.return_path) or _domain_of(email.from_addr)
        if not mail_from_domain:
            return None, False

        result, _ = spf.check2(i=ip, s=f"user@{mail_from_domain}", h=mail_from_domain)
        aligned_pass = result == "pass" and _aligned(mail_from_domain, _domain_of(email.from_addr))

        if result == "fail":
            return (
                Evidence.triggered(
                    case_id, Analyzer.M3_AUTH, "spf_fail_hard",
                    detail={"ip": ip, "domain": mail_from_domain,
                            "explanation": "SPF hard fail: this IP is not authorized to send "
                                           "for the envelope-sender domain."},
                ),
                aligned_pass,
            )
        return None, aligned_pass
    except Exception:
        return None, False


# --- DKIM --------------------------------------------------------------------
def _dkim_signing_domains(email: ParsedEmail) -> list[str]:
    return [
        m.group(1).strip().lower()
        for k, v in email.headers
        if k.lower() == "dkim-signature"
        for m in [_DKIM_D_RE.search(v)]
        if m
    ]


def _verify_dkim(case_id: UUID, email: ParsedEmail) -> tuple[Evidence | None, bool]:
    """Return (evidence or None, dkim_aligned_pass). No signature -> (None, False)."""
    if dkim is None or not email.raw_bytes:
        return None, False

    sig_domains = _dkim_signing_domains(email)
    if not sig_domains:
        return None, False  # unsigned: not scored (see module docstring)

    try:
        ok = bool(dkim.verify(email.raw_bytes))
    except Exception:
        ok = False

    d = sig_domains[0]
    from_domain = _domain_of(email.from_addr)
    aligned = _aligned(d, from_domain)

    if ok and aligned:
        return (
            Evidence.triggered(
                case_id, Analyzer.M3_AUTH, "dkim_valid_aligned",
                detail={"domain": d,
                        "explanation": f"DKIM signature valid and d={d} aligns with the From domain."},
            ),
            True,
        )
    if not ok:
        return (
            Evidence.triggered(
                case_id, Analyzer.M3_AUTH, "dkim_fail",
                detail={"domain": d,
                        "explanation": f"DKIM signature (d={d}) failed cryptographic verification "
                                       "— content was altered or the signature was forged."},
            ),
            False,
        )
    # valid but not aligned (mailing list / ESP): no credit, no penalty.
    return None, False


# --- DMARC -------------------------------------------------------------------
def _dmarc_policy(domain: str) -> str | None:
    """Return the DMARC policy word (none/quarantine/reject) via a DNS tree walk."""
    if dns is None or not domain:
        return None
    labels = domain.split(".")
    # Walk up: exact domain, then progressively broader parents (RFC 9989 tree walk).
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        try:
            answers = dns.resolver.resolve(f"_dmarc.{candidate}", "TXT", lifetime=5)
        except Exception:
            continue
        for rr in answers:
            txt = b"".join(getattr(rr, "strings", [])).decode(errors="replace") or str(rr).strip('"')
            if txt.lower().startswith("v=dmarc1"):
                m = _DMARC_P_RE.search(txt)
                return (m.group(1).lower() if m else "none")
    return None


def _verify_dmarc(case_id: UUID, email: ParsedEmail, authenticated: bool) -> Evidence | None:
    from_domain = _domain_of(email.from_addr)
    if not from_domain:
        return None
    policy = _dmarc_policy(from_domain)
    if policy is None:
        return None  # no policy reachable/published: not a failure by itself
    # A strict policy is only a FINDING when authentication actually failed.
    if policy in ("reject", "quarantine") and not authenticated:
        return Evidence.triggered(
            case_id, Analyzer.M3_AUTH, "dmarc_fail_strict",
            detail={"domain": from_domain, "policy": policy,
                    "explanation": f"Neither SPF nor DKIM aligned with the From domain, and the "
                                   f"domain's DMARC policy is p={policy} — this message violates "
                                   "a policy the domain owner explicitly published."},
        )
    return None


@register(Analyzer.M3_AUTH)
async def analyze(case_id: UUID, email: ParsedEmail) -> list[Evidence]:
    """Re-verify SPF, DKIM, and DMARC from the raw bytes and DNS."""
    if spf is None and dkim is None:
        return [
            Evidence.unavailable(
                case_id, Analyzer.M3_AUTH, "dkim_valid_aligned",
                "M3 unavailable: neither pyspf nor dkimpy is installed.",
            )
        ]

    ev: list[Evidence] = []

    # The IP that connected to our trust boundary is the correct SPF client IP.
    boundary, _hops = authenticated_origin(email)
    client_ip = boundary.from_ip if boundary is not None else None

    spf_ev, spf_pass = _verify_spf(case_id, email, client_ip)
    if spf_ev:
        ev.append(spf_ev)

    dkim_ev, dkim_pass = _verify_dkim(case_id, email)
    if dkim_ev:
        ev.append(dkim_ev)

    # DMARC passes if EITHER SPF or DKIM produced an aligned pass.
    dmarc_ev = _verify_dmarc(case_id, email, authenticated=spf_pass or dkim_pass)
    if dmarc_ev:
        ev.append(dmarc_ev)

    # Only negative/credit signals above are scored. If none fired, we still
    # verified what we could -- record a CLEAR so the log shows the check ran.
    triggered = [e for e in ev if e.signal != "dkim_valid_aligned"]
    if not triggered:
        ev.append(
            Evidence.clear(
                case_id, Analyzer.M3_AUTH, "auth_verification_passed",
                detail={"explanation": "No SPF/DKIM/DMARC alignment failures detected "
                                       "(re-verified from raw bytes; DNS-dependent checks "
                                       "skipped when unreachable)."},
            )
        )

    return ev
