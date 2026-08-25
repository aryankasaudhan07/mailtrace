# SIH26106 — Email Threat Detection Demo (Starter Code)

This is the Week 1-3 scaffolding for the demo build we scoped: upload an
email → get a fraud score with a clear "why."

## Files

| File | What it does | Status |
|---|---|---|
| `header_parser.py` | Parses `.eml` files: SPF/DKIM/DMARC, From/Reply-To/Return-Path mismatches, Received chain, originating IP | ✅ Tested, works standalone (no API needed) |
| `ai_analyzer.py` | Sends email body to Claude, gets back urgency/impersonation/link-risk scoring as structured JSON | Needs `ANTHROPIC_API_KEY` to run |
| `geolocation.py` | Looks up the originating IP's country/city/ISP via ip-api.com (free, no key) | Needs internet access to run |
| `domain_analysis.py` | WHOIS + DNS/MX checks on the sender's domain — flags newly-registered domains and missing mail-server records | Needs `pip install python-whois dnspython` + internet |
| `pipeline.py` | Combines header + AI + geolocation + domain analysis into one fraud score (Safe / Suspicious / High-Risk) with reasons | Ties everything together |
| `correlation_graph.py` | Takes several already-analyzed emails and detects if any share an IP or sender domain — flagging them as a likely single "campaign" instead of isolated incidents | Works offline once you have saved pipeline.py outputs — no install needed |
| `sample_phishing.eml` | A fake phishing email to test against | Use this first |

## Setup

```bash
pip install anthropic requests python-whois dnspython
export ANTHROPIC_API_KEY=your_key_here
```

## Try it

```bash
# Test just the header parser (works right now, no setup needed)
python header_parser.py sample_phishing.eml

# Test just the domain checker on any domain (needs internet)
python domain_analysis.py paypa1-secure.tk

# Full pipeline — now includes domain analysis (needs API key + internet)
python pipeline.py sample_phishing.eml

# Save a few pipeline outputs, then look for shared attacker infrastructure across them
python pipeline.py email1.eml > result1.json
python pipeline.py email2.eml > result2.json
python correlation_graph.py result1.json result2.json
```

## How the score is built (Week 4 talking point for judges)

The fraud score is **deliberately not a black box** — every point added
maps to something visible on the dashboard:

- SPF/DKIM/DMARC failures → +20/+20/+15
- From vs Reply-To/Return-Path domain mismatch → +15
- AI urgency score (0-10) → up to +20
- AI impersonation likelihood (0-10) → up to +20
- Suspicious link patterns flagged by AI → +10
- Domain risk flags (newly-registered domain, missing MX records) → +15 each

0-29 = Safe · 30-59 = Suspicious · 60-100 = High-Risk

## What's NOT built (say this proactively in your pitch)

- Real-time large-scale ingestion (we process one email at a time for the demo)
- Licensed threat-intel/blacklist correlation (we'd integrate open-source IOC feeds in production)
- Legal chain-of-custody / evidentiary handling (institutional-grade feature, out of hackathon scope)
- Campaign-level graph correlation across many past incidents (needs real historical data)

Framing these as **"future roadmap"** rather than hiding them is what
makes a demo credible to judges — it shows you understood the full
problem statement even though you scoped a focused MVP.

## Next steps for your team

1. Get 10-15 more sample `.eml` files (mix of real spam-corpus phishing +
   a few legitimate emails from your own inbox, headers scrubbed of
   personal info) and run them through `header_parser.py` to sanity-check
   the parsing logic.
2. Get an Anthropic API key and test `ai_analyzer.py` on a few emails —
   tune the system prompt if scores feel off.
3. Build the dashboard (Flask/React) that calls `pipeline.py` and displays
   the JSON output visually — score, reasons list, and a map pin for the
   geolocation result.
