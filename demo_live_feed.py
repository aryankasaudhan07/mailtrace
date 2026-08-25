#!/usr/bin/env python
"""
Feed the sample emails to a running Mailtrace API one at a time, so the live
graph at http://localhost:8000/live visibly grows during a demo.

Usage: with the server running, ./venv/bin/python demo_live_feed.py [--delay 3]
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path

import requests

API = "http://localhost:8000/api/cases"

SAMPLES = [
    "sample_phishing.eml",
    "samples/bec-injected-hop.eml",
    "samples/benign-control.eml",
    # The phishing sample again: same infrastructure, so M7 links the two
    # cases and the graph shows its first campaign cluster.
    "sample_phishing.eml",
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--delay", type=float, default=3.0, help="seconds between submissions")
    args = ap.parse_args()

    for path in SAMPLES:
        p = Path(path)
        if not p.exists():
            print(f"skip (missing): {path}")
            continue
        resp = requests.post(
            API,
            files={"file": (p.name, p.read_bytes(), "message/rfc822")},
            timeout=60,
        )
        resp.raise_for_status()
        v = resp.json()["verdict"]
        print(f"{path:35s} -> {v['score']:3d}/100 {v['band']:10s} confidence {v['confidence']:.0%}")
        time.sleep(args.delay)

    print("\nDone. Watch the graph at http://localhost:8000/live")


if __name__ == "__main__":
    main()
