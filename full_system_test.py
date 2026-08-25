#!/usr/bin/env python
"""Comprehensive system test with all available email samples."""
from __future__ import annotations
import asyncio
import json
from pathlib import Path
from uuid import uuid4
import app.analyzers
from app.ingest.parser import parse_email
from app.analyzers.base import run_all
from app.scoring.engine import score_case

async def test_all_emails():
    """Test all available email samples."""
    samples = [
        ("sample_phishing.eml", "Phishing Attack"),
        ("samples/bec-injected-hop.eml", "BEC with Injected Hop"),
        ("samples/benign-control.eml", "Benign Control Email"),
    ]

    results = {
        "test_suite": "Full System Evaluation",
        "timestamp": "2026-08-24T12:00:00Z",
        "emails": {},
        "summary": {},
    }

    print("=" * 80)
    print("🔬 COMPREHENSIVE SYSTEM TEST — ALL EMAIL SAMPLES")
    print("=" * 80)

    for sample_path, description in samples:
        path = Path(sample_path)
        if not path.exists():
            print(f"\n⚠️  {description}: File not found ({sample_path})")
            continue

        print(f"\n{'='*80}")
        print(f"📧 {description}")
        print(f"{'='*80}")
        print(f"Path: {sample_path}\n")

        raw_bytes = path.read_bytes()
        email = parse_email(raw_bytes)

        print(f"From: {email.from_addr}")
        print(f"Subject: {email.subject}")
        print(f"SHA256: {email.sha256[:16]}...\n")

        # Run all 7 analyzers
        case_id = uuid4()
        evidence = await run_all(case_id, email)
        verdict = score_case(case_id, evidence)

        # Organize by analyzer
        by_analyzer = {}
        for ev in evidence:
            analyzer_id = ev.analyzer.value
            if analyzer_id not in by_analyzer:
                by_analyzer[analyzer_id] = []
            by_analyzer[analyzer_id].append({
                "signal": ev.signal,
                "status": ev.status.value,
                "confidence": float(ev.confidence),
            })

        # Display results
        print("🔍 ANALYZER RESULTS:")
        print("-" * 80)
        for analyzer_id in sorted(by_analyzer.keys()):
            signals = by_analyzer[analyzer_id]
            triggered = [s for s in signals if s["status"] == "TRIGGERED"]
            clear = [s for s in signals if s["status"] == "CLEAR"]
            unavailable = [s for s in signals if s["status"] == "UNAVAILABLE"]

            status_str = ""
            if triggered:
                status_str = f"🔴 TRIGGERED ({len(triggered)})"
            elif clear:
                status_str = f"✅ CLEAR ({len(clear)})"
            elif unavailable:
                status_str = f"⊘ UNAVAILABLE"

            print(f"\n{analyzer_id}: {status_str}")
            for sig in signals[:3]:  # Show top 3
                emoji = "🔴" if sig["status"] == "TRIGGERED" else "✅" if sig["status"] == "CLEAR" else "⊘"
                print(f"  {emoji} {sig['signal']}: {sig['confidence']:.0%}")

        print(f"\n🎯 VERDICT:")
        print(f"   Score: {verdict.score}/100")
        print(f"   Band: {verdict.band.value}")
        print(f"   Confidence: {verdict.confidence:.0%}")

        # Top 3 signals
        if verdict.contributions:
            print(f"\n📊 Top Contributing Signals:")
            for contrib in verdict.contributions[:3]:
                print(f"   • {contrib.label}: +{contrib.points:.0f} pts")

        # Store results
        results["emails"][description] = {
            "path": sample_path,
            "case_id": str(case_id),
            "sha256": email.sha256,
            "from": email.from_addr,
            "subject": email.subject,
            "verdict": {
                "score": verdict.score,
                "band": verdict.band.value,
                "confidence": float(verdict.confidence),
            },
            "analyzers": by_analyzer,
            "top_signals": [
                {
                    "signal": c.signal,
                    "label": c.label,
                    "points": float(c.points),
                    "confidence": float(c.confidence),
                }
                for c in verdict.contributions[:5]
            ],
        }

    # Generate summary
    print(f"\n{'='*80}")
    print("📈 TEST SUMMARY")
    print(f"{'='*80}\n")

    critical_count = 0
    high_risk_count = 0
    suspicious_count = 0
    benign_count = 0

    for desc, data in results["emails"].items():
        band = data["verdict"]["band"]
        score = data["verdict"]["score"]

        if band == "CRITICAL":
            critical_count += 1
            status = "🔴 CRITICAL"
        elif band == "HIGH_RISK":
            high_risk_count += 1
            status = "🟠 HIGH_RISK"
        elif band == "SUSPICIOUS":
            suspicious_count += 1
            status = "🟡 SUSPICIOUS"
        else:
            benign_count += 1
            status = "✅ BENIGN"

        print(f"{desc}")
        print(f"  Score: {score}/100 {status}")
        print(f"  Confidence: {data['verdict']['confidence']:.0%}\n")

    results["summary"] = {
        "critical": critical_count,
        "high_risk": high_risk_count,
        "suspicious": suspicious_count,
        "benign": benign_count,
        "total_emails": len(results["emails"]),
    }

    print(f"Detection Summary:")
    print(f"  🔴 CRITICAL: {critical_count}")
    print(f"  🟠 HIGH_RISK: {high_risk_count}")
    print(f"  🟡 SUSPICIOUS: {suspicious_count}")
    print(f"  ✅ BENIGN: {benign_count}")

    # Save results
    with open("full_test_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n✅ Full test complete. Results saved to full_test_results.json")
    print(f"{'='*80}\n")

    return results

if __name__ == "__main__":
    asyncio.run(test_all_emails())
