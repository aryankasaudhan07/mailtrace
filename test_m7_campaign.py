#!/usr/bin/env python
"""Test M7 by running the same email twice to detect infrastructure reuse."""
from __future__ import annotations
import asyncio
from pathlib import Path
from uuid import uuid4
import app.analyzers
from app.ingest.parser import parse_email
from app.analyzers.base import run_all
from app.scoring.engine import score_case

async def test():
    print("=" * 80)
    print("🧪 TEST: M7 Campaign Infrastructure Detection")
    print("=" * 80)

    sample_path = Path("sample_phishing.eml")
    raw_bytes = sample_path.read_bytes()

    # First run
    print("\n📧 RUN 1: First phishing email")
    print("-" * 80)
    email1 = parse_email(raw_bytes)
    case_id1 = uuid4()
    evidence1 = await run_all(case_id1, email1)
    verdict1 = score_case(case_id1, evidence1)

    m7_signals1 = [e for e in evidence1 if e.analyzer.value == "M7"]
    if m7_signals1:
        print(f"M7 Signal: {m7_signals1[0].signal}")
        print(f"Status: {m7_signals1[0].status.value}")
        print(f"Detail: {m7_signals1[0].detail.get('summary', '')}")
    print(f"Score: {verdict1.score}/100 ({verdict1.band.value})")
    print(f"Confidence: {verdict1.confidence:.0%}")

    # Second run with same email
    print("\n📧 RUN 2: Same phishing email (should detect infrastructure reuse)")
    print("-" * 80)
    email2 = parse_email(raw_bytes)
    case_id2 = uuid4()
    evidence2 = await run_all(case_id2, email2)
    verdict2 = score_case(case_id2, evidence2)

    m7_signals2 = [e for e in evidence2 if e.analyzer.value == "M7"]
    if m7_signals2:
        sig = m7_signals2[0]
        print(f"M7 Signal: {sig.signal}")
        print(f"Status: {sig.status.value}")
        print(f"Confidence: {sig.confidence:.0%}")
        print(f"Detail: {sig.detail}")
    print(f"Score: {verdict2.score}/100 ({verdict2.band.value})")
    print(f"Confidence: {verdict2.confidence:.0%}")

    # Compare
    print("\n" + "=" * 80)
    print("📊 COMPARISON")
    print("=" * 80)
    if m7_signals1 and m7_signals2:
        sig1 = m7_signals1[0]
        sig2 = m7_signals2[0]
        print(f"Run 1: {sig1.status.value} - {sig1.detail.get('summary', '')}")
        print(f"Run 2: {sig2.status.value} - {sig2.detail.get('summary', '')}")

        if sig2.status.value == "TRIGGERED":
            print("\n✅ SUCCESS: M7 detected campaign infrastructure reuse!")
            print(f"   Shared indicators: {sig2.detail.get('shared_indicator_count', 0)}")
            print(f"   Related prior cases: {sig2.detail.get('related_cases', 0)}")
        else:
            print(f"\n⚠️  Run 2 did not trigger (status: {sig2.status.value})")

if __name__ == "__main__":
    asyncio.run(test())
