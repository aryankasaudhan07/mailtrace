"""
pipeline.py
-----------
The Week 3-4 "fusion engine": runs an .eml file through all three stages
and produces the single combined output your dashboard will display.

Usage:
    python pipeline.py path/to/email.eml
"""

import sys
import json

from header_parser import load_email, analyze_headers, get_body_text
from ai_analyzer import analyze_email_body
from geolocation import lookup_ip
from domain_analysis import analyze_domain


def compute_fraud_score(header_result: dict, ai_result: dict, domain_result: dict | None = None) -> dict:
    """
    Simple, explainable weighted scoring — deliberately NOT a black box,
    since judges will ask "how did you get this score?" Each factor below
    maps directly to something shown on the dashboard.
    """
    score = 0
    reasons = []

    auth = header_result["auth_results"]
    if auth["spf"] not in ("pass", "not found"):
        score += 20
        reasons.append(f"SPF check failed ({auth['spf']})")
    if auth["dkim"] not in ("pass", "not found"):
        score += 20
        reasons.append(f"DKIM check failed ({auth['dkim']})")
    if auth["dmarc"] not in ("pass", "not found"):
        score += 15
        reasons.append(f"DMARC check failed ({auth['dmarc']})")

    if header_result["identity"]["mismatch_flags"]:
        score += 15
        reasons.extend(header_result["identity"]["mismatch_flags"])

    if "error" not in ai_result:
        score += ai_result.get("urgency_score", 0) * 2          # 0-20
        score += ai_result.get("impersonation_likelihood", 0) * 2  # 0-20
        if ai_result.get("suspicious_link_flags"):
            score += 10
            reasons.extend(ai_result["suspicious_link_flags"])
        if ai_result.get("social_engineering_tactics"):
            reasons.extend(ai_result["social_engineering_tactics"])

    score = min(score, 100)

    if domain_result and domain_result.get("risk_flags"):
        score += 15 * len(domain_result["risk_flags"])
        reasons.extend(domain_result["risk_flags"])

    if score >= 60:
        verdict = "High-Risk"
    elif score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {"fraud_score": score, "verdict": verdict, "reasons": reasons}


def run_pipeline(eml_path: str) -> dict:
    msg = load_email(eml_path)

    header_result = analyze_headers(msg)
    body_text = get_body_text(msg)
    ai_result = analyze_email_body(header_result["subject"], body_text)

    geo_result = {}
    if header_result["originating_ip_guess"]:
        geo_result = lookup_ip(header_result["originating_ip_guess"])

    domain_result = {}
    from_domain = header_result["identity"].get("from_domain")
    if from_domain:
        domain_result = analyze_domain(from_domain)

    fraud_score = compute_fraud_score(header_result, ai_result, domain_result)

    return {
        "subject": header_result["subject"],
        "fraud_assessment": fraud_score,
        "header_analysis": header_result,
        "ai_analysis": ai_result,
        "geolocation": geo_result,
        "domain_analysis": domain_result,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pipeline.py path/to/email.eml")
        sys.exit(1)

    result = run_pipeline(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))
