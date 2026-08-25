# Mailtrace

AI-powered email threat detection, geolocation and forensic intelligence.
AICTE Cyber Security Cell problem statement — SIH.

**This repo is the contract freeze.** It exists so that six people can build in
parallel without waiting on each other. Read this file before writing any code.

Building with Claude Code? Read **`CLAUDE-CODE-SETUP.md`** — the `.claude/`
directory is committed, so every clone gets the same commands, review agent, and
post-edit checks.

---

## Day one: the only meeting that matters

Get the whole team in one room and do these four things. Nothing else starts
until they are merged, and once they are, nobody is blocked for days.

1. **Read `CONTRACTS.md` together, out loud.** Twenty minutes. Everyone must
   understand `Evidence`, because every track produces or consumes it.
2. **Agree it or change it now.** After today, changing `app/schemas/evidence.py`
   is a whole-team decision. Argue about it while it is cheap.
3. **Claim your track** in the table below. Write names in this README and commit.
4. **Confirm the skeleton runs on every laptop** (see Quickstart). If it runs for
   all six of you, integration hell is already mostly avoided.

---

## Quickstart

No Docker, no database, no network, no API keys:

Needs **Python 3.10 or newer** (`python3 --version`). macOS may ship 3.9 —
`brew install python@3.12` if so.

```bash
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install fastapi uvicorn pydantic pydantic-settings PyYAML python-multipart pytest httpx ruff
cp .env.example .env

pytest                                                 # 26 pass, 6 skipped (the skips are Track A's spec)
ruff check app tests                                   # clean
FIXTURE_MODE=1 uvicorn app.main:app --reload
```

Open http://localhost:8000/docs and upload `samples/bec-injected-hop.eml` to
`POST /api/cases`. You get a real verdict, scored from real evidence:

```
SCORE 36  BAND SUSPICIOUS  CONFIDENCE 0.25
  20.0  M2  Reply-To domain differs from From domain
  16.0  M2  Private or reserved IP in a public relay chain
Confidence reduced: 5 analyzer lanes unavailable (M3, M4, M5, M6, M7)
```

That output is the whole architecture working. The score is low because five of
six analyzers are still stubs — as each track lands, the same upload scores
higher and the explanation grows. **That is your progress bar.**

Full stack (adds Postgres + Redis, needed from phase 4):

```bash
docker compose up --build
```

---

## Track assignments

| Track | Owner | Modules | Publishes |
|---|---|---|---|
| **A** — Core & header forensics | _name_ | M1, M2 | `parse_email()`, `parse_hops()`, `resolve_trust_boundary()` |
| **B** — Auth & domain intel | _name_ | M3, M6 | `m3_auth.analyze()`, `m6_domain.analyze()` |
| **C** — Content intelligence | _name_ | M4 | `m4_content.analyze()` |
| **D** — Network intel & offline data | _name_ | M5 | `m5_network.analyze()`, `scripts/fetch_intel.sh` |
| **E** — Scorer, graph & reporting | _name_ | M7, M8, M10 | `score_case()`, campaign graph, PDF report |
| **F** — Dashboard & demo | _name_ | M9 | React app + the demo script |

Give track A your strongest engineer. M2 is the module a judge will interrogate.

**Track F starts immediately and never waits.** `FIXTURE_MODE=1` serves
`fixtures/*.json` from every read endpoint, so the entire dashboard can be built
before a single analyzer exists. Do not let the frontend block on the backend —
that is the classic way hackathon teams lose their last 48 hours.

---

## How to add an analyzer

This is the whole extension model. Five lines of ceremony, then your logic.

```python
from app.analyzers.base import register
from app.schemas.evidence import Analyzer, Evidence

@register(Analyzer.M6_DOMAIN)
async def analyze(case_id, email) -> list[Evidence]:
    age_days = await lookup_domain_age(email.from_addr)
    if age_days is None:
        return [Evidence.unavailable(case_id, Analyzer.M6_DOMAIN,
                                     "domain_age_lt_30d", "RDAP timeout")]
    if age_days < 30:
        return [Evidence.triggered(case_id, Analyzer.M6_DOMAIN, "domain_age_lt_30d",
                                   detail={"age_days": age_days})]
    return [Evidence.clear(case_id, Analyzer.M6_DOMAIN, "domain_age_lt_30d")]
```

Four rules, and they are not style preferences:

1. **Return `Evidence`, never a score.** Only `app/scoring/engine.py` decides
   what evidence means.
2. **Never read another analyzer's output.** Lanes run concurrently and are
   mutually blind. If you think you need M2's result, you need the scorer to
   combine them instead.
3. **Every new signal goes in `weights.yaml` in the same commit.** Otherwise the
   scorer ignores it and logs a warning.
4. **Return `UNAVAILABLE`, never raise.** Offline, rate-limited, timed out — all
   are evidence, not errors. This is what keeps the demo alive when the venue
   Wi-Fi dies, and it is not optional.

---

## Build order

Phases are sequential; each unblocks the next.

1. ~~**Freeze the contracts**~~ — this repo
2. **Skeleton runs end to end** — done: upload → parse → score → verdict
3. **Header forensics to done** (A + B) — implement `resolve_trust_boundary`, then
   the `TODO-A` checks. **At the end of this phase you have a demonstrable
   product even if nothing else lands.** That is why it is third, not sixth.
4. **Offline intel + geo trace** (D + F) — `scripts/fetch_intel.sh`, map working
   with the network cable pulled
5. **Scorer + explainability panel** (E + F) — after this, every analyzer you add
   visibly improves the demo
6. **Content intelligence** (C) — baseline classifier first, ship it, then upgrade.
   Deliberately late: most likely to overrun, and the system works without it
7. **Graph, campaigns, PDF report** (E) — load 30–50 corpus emails so clusters form
8. **Harden and rehearse** (all) — pull the network cable, pre-warm caches,
   rehearse three times, record a fallback video

---

## Things that will waste your time if nobody tells you

Verified against live documentation, 23 August 2026.

- **PhishTank is dead to you.** Registration has been closed since 2020 and no
  new API keys are issued. Its developer docs pages are still up and still
  describe the old flow — they will cost you a day. Use the OpenPhish community
  feed (already in `fetch_intel.sh`).
- **MaxMind's old download URL is gone.** `geoip_download?license_key=` no longer
  works. Use `/geoip/databases/{edition}/download` with HTTP basic auth, and
  follow redirects — it 302s to Cloudflare R2. `fetch_intel.sh` does this right.
- **`python-whois` is a fallback, not the primary.** ICANN sunset port-43 gTLD
  WHOIS in January 2025. Use `whoisit` (RDAP). Registrant name and email are
  redacted post-GDPR anyway — build features on creation date, registrar and
  nameservers.
- **IPinfo's free city-level tier no longer exists.** Lite gives ASN + country
  only. Use GeoLite2 for city, IPinfo Lite for ASN.
- **VirusTotal free is 4 requests/minute.** An email with 20 URLs takes six
  minutes. Cache everything, pre-warm your demo samples, and never put a live
  lookup on the critical path.
- **urlscan.io defaults to public visibility.** Scanning a real phishing URL
  makes it world-searchable. Always pass `visibility: "unlisted"`.
- **Most "phishing email dataset" downloads have no headers.** The popular
  Kaggle/HuggingFace sets are body text only — fine for the M4 classifier,
  useless for relay tracing. Use the **Nazario** yearly mboxes
  (`phishing-2015`…`phishing-2025`, CC BY 4.0) — the older files are
  IP-anonymised and will trace to nothing. `phishing_pot` is good for
  individually inspectable `.eml`.
- **SpamAssassin's corpus has fake hostnames** (`spamassassin.taint.org`). Never
  demo a geo-trace on one; it resolves to nothing. Fine as the ham class.
- **Gmail strips the sender's IP** for mail composed in its web UI. You cannot
  recover it, and a demo built on doing so will fail on stage. Send yourself test
  mail *through* `smtp.gmail.com` with an app password instead — that path
  records your real client IP and gives you ground truth to validate against.
  App passwords need 2FA and do **not** work on Workspace/school accounts.

---

## Layout

```
CLAUDE.md               project instructions Claude Code loads every session
CLAUDE-CODE-SETUP.md    how the six of you should drive it
.claude/
  settings.json         team permissions + post-edit hook — COMMITTED
  commands/             /implement-analyzer /add-signal /contract-check /quiz /demo-check
  agents/               @contract-reviewer — read-only invariant review
  hooks/check.sh        ruff + pytest after every edit; silent unless broken
app/
  schemas/evidence.py   THE CONTRACT — read this first
  schemas/email.py      ParsedEmail, Hop, HopTrust
  schemas/verdict.py    Verdict, Contribution, Band
  ingest/parser.py      M1 — working
  analyzers/base.py     register() + concurrent runner with per-lane timeouts
  analyzers/m2_*.py     M2 — hop parsing done, trust boundary is TODO-A
  analyzers/m3..m7      stubs with per-track TODOs and the exact libraries to use
  scoring/weights.yaml  the verdict logic. 26 signals. versioned.
  scoring/engine.py     M8 — working
  db/models.py          8 tables; evidence is append-only, audit_log hash-chains
  api/                  the ten endpoints
fixtures/               Track F builds against these on day one
samples/                two synthetic .eml files, safe to commit
scripts/fetch_intel.sh  every offline database, correct URLs
tests/                  26 passing; the 6 skipped are Track A's definition of done
```

---

## Attribution

If you ship GeoLite2 data, this line must appear in the UI footer and the PDF
report:

> This product includes GeoLite2 data created by MaxMind, available from
> https://www.maxmind.com

Never commit `.mmdb` files — `.gitignore` already blocks them.
