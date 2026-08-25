# Mailtrace — project instructions

Email threat detection, geolocation and forensic intelligence. AICTE Cyber
Security Cell problem statement, SIH. Python 3.10+ / FastAPI / React.

Read `CONTRACTS.md` before changing anything under `app/schemas/`.
Read `docs/THREAT-MODEL.md` before adding a detection signal or writing any copy
about what the platform detects — it has the attack taxonomy, our coverage gaps,
and the claims we must not make.

## Commands

```bash
pytest -q                                  # must stay green; 6 skips are Track A's spec
ruff check app tests                       # lint
FIXTURE_MODE=1 uvicorn app.main:app --reload
docker compose up --build                  # full stack, needed from phase 4
./scripts/fetch_intel.sh                   # offline geo/ASN/Tor/VPN databases
```

## Architecture in one paragraph

One parser (`app/ingest/parser.py`) produces a `ParsedEmail`. Six analyzers run
concurrently and each emits a list of `Evidence` records. One scorer
(`app/scoring/engine.py`) reads the whole evidence set and produces the only
verdict. Analyzers never talk to each other and never produce a score.

## The four rules for analyzers

These are architectural invariants, not style preferences. Breaking one breaks
the team's ability to work in parallel.

1. **Return `Evidence`, never a score.** Only `app/scoring/engine.py` interprets
   evidence.
2. **Never read another analyzer's output.** Lanes run concurrently and are
   mutually blind. If you need another lane's result, the *scorer* combines them.
3. **Every new signal goes in `app/scoring/weights.yaml` in the same commit**,
   with a `weight`, `label`, `rationale` and `analyzer`. A signal missing from
   weights.yaml is silently unscored.
4. **Return `UNAVAILABLE`, never raise.** Offline, rate-limited, timed out — all
   are evidence. This is what keeps the demo alive with no network, and it is
   not optional.

## Code conventions

- **Python 3.10 is the floor**, 3.12 recommended (the Dockerfile uses 3.12).
  Two traps: `datetime.UTC` is 3.11+, so use `timezone.utc`; and a bare
  `except TimeoutError` only catches `asyncio.TimeoutError` from 3.11, so always
  write `except asyncio.TimeoutError`. `ruff --fix` will try to "upgrade" both —
  they are in the ignore list in `pyproject.toml`. Do not remove them.
- `from __future__ import annotations` at the top of every module.
- Type-hint everything. Pydantic v2 models for anything crossing a boundary.
- Analyzer entry points are `async def analyze(case_id, email) -> list[Evidence]`
  decorated with `@register(Analyzer.MX_NAME)`.
- Use the `Evidence.triggered()` / `.clear()` / `.unavailable()` constructors,
  not `Evidence(...)` directly.
- Write `detail` dicts for an *analyst*, not a debugger — they are printed
  verbatim in the forensic report.
- Never write to `app/schemas/evidence.py` without saying so explicitly; it is
  the frozen contract every track builds against.

## Testing

- Tests live in `tests/`, named `test_<module>.py`.
- `tests/test_headers.py` has six `@pytest.mark.skip` tests. **Those are the
  specification for Track A.** Remove a skip marker only when the test passes for
  real — never weaken an assertion to make it pass.
- When adding an analyzer, add both a TRIGGERED case and a CLEAR case.
- The scorer is the integration point. If `tests/test_scoring.py` breaks,
  something architectural broke.

## The threat model in five lines

Full detail in `docs/THREAT-MODEL.md`. The parts that change how you write code:

- **Most damaging attacks pass SPF, DKIM and DMARC by construction.** Thread
  hijacking from a compromised mailbox is ~28% of BEC and authenticates perfectly.
  Auth failure is a signal for exact-domain spoofing (~0.5% of impersonation) and
  botnet spam. It is not the story.
- **Never let good authentication cancel evidence of deception.** That was a real
  bug in scorer v1.0.0; `suppress_negatives_when_any_triggered` in weights.yaml is
  the fix. Do not remove it — `tests/test_scoring.py` guards it.
- **Geolocation is a consistency check, never attribution.** Country-level only.
  BreakSPF harvested 87,430 attacker-controllable IPs across 181 countries at
  under a cent each; the earliest hop is usually a relay or a cheap cloud VM.
- **DMARC is RFC 9989 now** (May 2026): DNS Tree Walk replaced the Public Suffix
  List, and `pct=` is removed. A PSL-based parser is non-conformant.
- **We do not compete on binary classification at the MX.** At a 0.1% base rate,
  99% accuracy means ~9% precision. We work on already-flagged mail where
  explainability is the product.

## Domain facts that are easy to get wrong

- **`Received:` headers are prepended**, so the raw header order is reverse
  transmission order. `parse_hops` reverses them: `seq=0` is the *claimed*
  origin, highest `seq` is final delivery. Never re-sort them by timestamp.
- **The bottom-most IP is not the origin.** An attacker can forge every hop below
  the first server we control. Report the earliest hop we can *authenticate* (the
  trust boundary) and label everything below it unverified. See `CONTRACTS.md`
  and `resolve_trust_boundary`.
- **Do not use `ipaddress.is_global`** to detect injected hops. It flags the RFC
  5737 documentation ranges, which makes every test fixture and sanitised corpus
  sample look forged — including the benign control. Use `is_unroutable_ip`.
- **Gmail strips the sender's IP** for webmail-composed mail, and Outlook.com has
  since 2012. It is not recoverable. Never write code or copy that claims to
  recover it; emit the `provider_withholds_origin` signal instead.
- **Do not trust the `Authentication-Results` header.** Below the trust boundary
  it is attacker-supplied. M3 re-verifies from `email.raw_bytes`, which is why M1
  keeps the original bytes on the object — any re-serialization breaks DKIM.
- **`evidence` and `audit_log` are append-only.** Never write an `UPDATE` or
  `DELETE` against them. An analyst override is a new `audit_log` row.
- **Un-wrap security-vendor URL rewriters** (Proofpoint, Safe Links, Mimecast,
  Barracuda, Cisco, Zscaler, Sophos, Inky, Trend Micro, EdgePilot) before storing
  or displaying a URL. Attackers deliberately harvest and re-mail vendor-rewritten
  links, stacked three deep — so an un-decoded report names a security vendor's
  domain as the destination.
- **Parse `image/svg+xml` as XML, not as an image.** Extract every script, event
  handler, `href`/`xlink:href` and data URI, and match script `type=` against a
  broad allowlist including the deprecated `application/ecmascript` — rules keyed
  only on `text/javascript` miss it.
- **Keep two text views per message, rendered and raw, and score the difference.**
  Hidden text (`display:none`, `font-size:0`, colour-on-colour) is how
  AI-assistant prompt injection arrives (CVE-2026-26133).
- **`Subject: Re:` with no `In-Reply-To` and no `References` is a fake reply.**
  Cheap and high precision — 55.9% of VIP-impersonation attacks manipulate the
  subject this way.

## External services — verified 23 Aug 2026

- **PhishTank: do not use.** Registration closed since 2020, no new API keys. Its
  docs pages are stale and misleading. Use the OpenPhish community feed.
- **MaxMind:** the `geoip_download?license_key=` URL is dead. Use
  `/geoip/databases/{edition}/download` with HTTP basic auth and follow
  redirects. `scripts/fetch_intel.sh` already does this correctly.
- **Use `whoisit` (RDAP), not `python-whois`.** ICANN sunset port-43 gTLD WHOIS in
  Jan 2025. Registrant name/email are GDPR-redacted anyway — build features on
  creation date, registrar and nameservers.
- **IPinfo:** free tier is ASN + country only; the old city-level free tier is
  gone. Use GeoLite2 for city.
- **VirusTotal free is 4 requests/minute.** Always cache; never put a live lookup
  on the critical path.
- **urlscan.io defaults to public visibility.** Always pass
  `visibility: "unlisted"` — scanning a real phishing URL otherwise makes it
  world-searchable.
- Never commit `.mmdb` files or anything under `intel/`.

## Track ownership

Ask before editing another track's module; suggest the change instead.

| Track | Modules | Files |
|---|---|---|
| A | M1, M2, framework | `ingest/parser.py`, `analyzers/m2_headers.py`, `analyzers/base.py`, `schemas/` |
| B | M3, M6 | `analyzers/m3_auth.py`, `analyzers/m6_domain.py` |
| C | M4 | `analyzers/m4_content.py` |
| D | M5, intel | `analyzers/m5_network.py`, `scripts/fetch_intel.sh` |
| E | M7, M8, M10 | `analyzers/m7_graph.py`, `scoring/`, reporting |
| F | M9 | the React app, `fixtures/` |

## What not to do

- Don't add a machine-learning model to the scorer. It is deliberately a weight
  table so a verdict can be explained and defended. ML belongs in M4 as one
  signal among many.
- Don't silence a failing test or delete a skip marker to make CI green.
- Don't invent accuracy numbers, service limits, or dataset licences. If a fact
  isn't in this file or the docs, say it needs checking.
- Don't put real phishing samples in `samples/` — that directory is committed.
  Real corpus mail goes in `samples/private/`, which is gitignored.
