#!/usr/bin/env python
"""Live demo of all 6 working analyzers on sample phishing email."""
from __future__ import annotations
import asyncio
from pathlib import Path
from uuid import uuid4
import app.analyzers  # Register all analyzers
from app.ingest.parser import parse_email
from app.analyzers.base import run_all
from app.scoring.engine import score_case

async def demo():
    print("=" * 80)
    print("📧 LIVE DEMO: All 6 Analyzers Processing Sample Phishing Email")
    print("=" * 80)

    # Load the sample phishing email
    sample_path = Path("sample_phishing.eml")
    if not sample_path.exists():
        print(f"❌ Sample not found: {sample_path}")
        return

    raw_bytes = sample_path.read_bytes()
    email = parse_email(raw_bytes)
    case_id = uuid4()

    print(f"\n📬 Email loaded:")
    print(f"   From: {email.from_addr}")
    print(f"   To: {', '.join(email.to_addrs)}")
    print(f"   Subject: {email.subject}")
    print(f"   Case ID: {case_id}")

    # Run all 6 analyzers
    print(f"\n🔍 Running all 6 analyzers in parallel...\n")
    evidence_all = await run_all(case_id, email)

    # Display evidence from each analyzer
    analyzer_names = {
        "M1": "Ingestion",
        "M2": "Headers",
        "M3": "Auth (SPF/DKIM/DMARC)",
        "M4": "Content/NLP (Gemini)",
        "M5": "Network (Tor/VPN/GeoIP)",
        "M6": "Domain Intelligence",
        "M7": "Graph/Campaign Clustering",
    }

    from app.schemas.evidence import Status

    for analyzer_id, display_name in analyzer_names.items():
        evidence = [e for e in evidence_all if e.analyzer == analyzer_id]

        if not evidence:
            print(f"  {analyzer_id}: No evidence collected")
            continue

        triggered = [e for e in evidence if e.status == Status.TRIGGERED]
        clear = [e for e in evidence if e.status == Status.CLEAR]
        unavailable = [e for e in evidence if e.status == Status.UNAVAILABLE]

        status = ""
        if unavailable:
            status = f"⊘ UNAVAILABLE ({', '.join(e.signal for e in unavailable)})"
        elif triggered:
            status = f"🔴 TRIGGERED ({len(triggered)} signals)"
        elif clear:
            status = f"✅ CLEAR ({len(clear)} checks)"
        else:
            status = "—"

        print(f"\n  {analyzer_id} — {display_name}")
        print(f"     Status: {status}")

        for e in triggered + clear + unavailable:
            confidence = f" ({e.confidence:.0%})" if e.confidence is not None else ""
            emoji = "🔴" if e.status == Status.TRIGGERED else ("✅" if e.status == Status.CLEAR else "⊘")
            print(f"       {emoji} {e.signal}{confidence}: {e.detail.get('summary', '')[:60]}")

    # Score
    print(f"\n" + "=" * 80)
    print("🎯 SCORING ENGINE")
    print("=" * 80)

    verdict = score_case(case_id, evidence_all)

    band_emoji = {
        "BENIGN": "✅",
        "SUSPICIOUS": "⚠️",
        "MALICIOUS": "🚨",
        "CRITICAL": "🔴",
    }

    print(f"\n  Final Score: {verdict.score}/100")
    print(f"  Band: {band_emoji.get(verdict.band.value, '?')} {verdict.band.value}")
    print(f"  Confidence: {verdict.confidence:.0%}")

    print(f"\n  Top Contributing Signals:")
    sorted_contribs = sorted(verdict.contributions, key=lambda c: abs(c.points), reverse=True)
    for contrib in sorted_contribs[:5]:
        print(f"    • {contrib.signal}: +{contrib.points:.0f} pts ({contrib.confidence:.0%})")

    if verdict.suppressed_negatives:
        print(f"\n  Suppressed Signals (high-confidence negatives):")
        for sig in verdict.suppressed_negatives:
            print(f"    • {sig}")

    print(f"\n" + "=" * 80)
    print("✅ Demo complete!")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(demo())
