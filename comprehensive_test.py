#!/usr/bin/env python
"""Comprehensive test running all 7 analyzers with detailed output."""
from __future__ import annotations
import asyncio
import json
from pathlib import Path
from uuid import uuid4
import app.analyzers
from app.ingest.parser import parse_email
from app.analyzers.base import run_all
from app.scoring.engine import score_case

async def run_comprehensive_test():
    sample_path = Path("sample_phishing.eml")
    raw_bytes = sample_path.read_bytes()
    email = parse_email(raw_bytes)

    results = {
        "email": {
            "from": email.from_addr,
            "to": ", ".join(email.to_addrs),
            "subject": email.subject,
            "sha256": email.sha256,
        },
        "analyzers": {},
        "verdict": None,
    }

    # Run all analyzers 3 times to show M7 learning
    for run_num in range(1, 4):
        case_id = uuid4()
        evidence = await run_all(case_id, email)
        verdict = score_case(case_id, evidence)

        # Organize evidence by analyzer
        by_analyzer = {}
        for ev in evidence:
            analyzer_id = ev.analyzer.value
            if analyzer_id not in by_analyzer:
                by_analyzer[analyzer_id] = []
            by_analyzer[analyzer_id].append({
                "signal": ev.signal,
                "status": ev.status.value,
                "confidence": float(ev.confidence),
                "detail": ev.detail,
            })

        results["analyzers"][f"run_{run_num}"] = {
            "case_id": str(case_id),
            "analyzers": by_analyzer,
            "verdict": {
                "score": verdict.score,
                "band": verdict.band.value,
                "confidence": float(verdict.confidence),
                "contributions": [
                    {
                        "signal": c.signal,
                        "points": float(c.points),
                        "confidence": float(c.confidence),
                        "label": c.label,
                    }
                    for c in verdict.contributions[:5]
                ],
            },
        }

        print(f"\n{'='*80}")
        print(f"RUN {run_num}: Email Analysis")
        print(f"{'='*80}")
        print(f"Case ID: {case_id}")

        for analyzer_id in sorted(by_analyzer.keys()):
            signals = by_analyzer[analyzer_id]
            print(f"\n{analyzer_id}: {len(signals)} signal(s)")
            for sig in signals:
                emoji = "🔴" if sig["status"] == "TRIGGERED" else "✅" if sig["status"] == "CLEAR" else "⊘"
                print(f"  {emoji} {sig['signal']}: {sig['status']} ({sig['confidence']:.0%})")

        print(f"\nVERDICT: {verdict.score}/100 ({verdict.band.value}) @ {verdict.confidence:.0%} confidence")
        top_labels = [c.label for c in verdict.contributions[:3]]
        print(f"Top signals: {', '.join(top_labels)}")

    results["verdict"] = {
        "final_score": verdict.score,
        "final_band": verdict.band.value,
        "final_confidence": float(verdict.confidence),
    }

    # Save as JSON for web dashboard
    with open("test_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n{'='*80}")
    print(f"✅ Test complete. Results saved to test_results.json")
    print(f"{'='*80}")
    return results

if __name__ == "__main__":
    asyncio.run(run_comprehensive_test())
