# Mailtrace threat model

What we are actually defending against, what the existing defences do and fail at,
where Mailtrace fits, and the concrete signals still missing from
`app/scoring/weights.yaml`.

Researched from primary sources (vendor threat research, RFCs, peer-reviewed
measurement) in **August 2026**. Every figure below carries its source and window,
because half the bad analysis in this field comes from citing 2024 data as current.

Evidence tags: **[primary]** RFC / IETF / vendor product docs · **[academic]**
peer-reviewed · **[vendor]** vendor telemetry, no reproducible methodology.

---

## 1. The one thing to understand

**Email authentication proves that a domain string was authorised to appear. It
proves nothing about intent, about the human, or about whether the account was
stolen.**

In 2026 the *majority* of financially damaging email attacks pass SPF, DKIM and
DMARC — by design, not by evasion. Thread hijacking from a compromised mailbox
passes all three perfectly, because the real tenant really did send it.

That single fact should shape every design decision we make. It also means the
three auth signals we already have (`spf_fail_hard`, `dmarc_fail_strict`,
`dkim_missing`) address the *rarest* attack class. Exact-domain spoofing is
around **0.5%** of impersonation attacks; display-name impersonation is around
**73.5%** [vendor, IRONSCALES 2019 — dated, cite for the *ratio* only, not as
product evidence].

---

## 2. Taxonomy — attack class → header signature → our coverage

`✅` covered by an existing signal · `◐` partially · `❌` no coverage today.

| # | Class | Header / MIME signature | SPF | DKIM | DMARC | Mailtrace |
|---|---|---|---|---|---|---|
| 1 | **Thread hijacking / ATO** | Valid `In-Reply-To` + `References` chaining to real prior IDs; authentic quoted history; org's own client fingerprint | ✅ | ✅ aligned | ✅ | ❌ |
| 2 | **Internal-to-internal (lateral)** | `X-MS-Exchange-Organization-AuthAs: Internal`; **no external `Received:` hop** | ✅ | ✅ | ✅ | ❌ |
| 3 | **Vendor email compromise (VEC)** | As #1, from the counterparty's domain | ✅ | ✅ | ✅ | ❌ |
| 4 | **LOTS — trusted-platform sending** | `dkim=pass header.d=`*platform*; platform's own MIME template, real `List-Unsubscribe`; **display name and often `Reply-To` are attacker-controlled** | ✅ | ✅ | ✅ | ❌ |
| 5 | **"Authentication laundering"** via a legit relay | Routed through Calendly / Google / an ESP to inherit their auth. Microsoft's own term, 25 Jun 2026 | ✅ | ✅ | ✅ | ❌ |
| 6 | **Freemail + display-name spoof** | `From: "CEO Name" <random@gmail.com>` | ✅ | ✅ | ✅ | ◐ |
| 7 | **Lookalike / cousin / typosquat / homoglyph / subdomain** | Attacker owns and correctly configures the domain, sometimes `p=reject` for credibility | ✅ | ✅ | ✅ *for the lookalike* | ✅ |
| 8 | **Calendar `.ics` invite phishing** | `text/calendar` part or `.ics`; payload in `DESCRIPTION`/`LOCATION`/`ORGANIZER`. Sent from attacker-created free tenants | ✅ | ✅ | ✅ | ❌ |
| 9 | **Device-code phishing** | **The only link is `microsoft.com/devicelogin`** + an 8–9 char code. No attachment | ➖ | ➖ | ➖ | ❌ |
| 10 | **OAuth consent phishing** | Link to the *genuine* IdP `/oauth2/v2.0/authorize`; the tell is in the query string (`client_id`, `redirect_uri`, `scope`) | ➖ | ➖ | ➖ | ❌ |
| 11 | **AI-assistant prompt injection** (CVE-2026-26133) | Hidden instructions in HTML: `display:none`, `font-size:0`, colour-on-colour. Invisible to the human, ingested by the summariser | ➖ | ➖ | ➖ | ❌ |
| 12 | **TOAD / callback phishing** | `application/pdf` or plain body. **Zero URLs.** One phone number, often rendered as an image | ➖ | ➖ | ➖ | ❌ |
| 13 | **Quishing (QR)** | 70% PDF / 24% DOC / 5% body (Microsoft Q1 2026). Often zero URLs anywhere | ➖ | ➖ | ➖ | ❌ |
| 14 | **AiTM / MFA-bypass** | Email is unremarkable; evasion is on the landing page. HTML or SVG attachment, or a link laundered through Azure Blob / Cloudflare Workers | ➖ | ➖ | ➖ | ◐ |
| 15 | **True spoof of our own domain** | `spf=fail`, `dkim=none`, `dmarc=fail` — **but delivered anyway** via CompAuth `reason=905`/`451`/`601` or connector misconfiguration | ❌ | ❌ | ❌ | ✅ |
| 16 | **Commodity credential phishing** | Throwaway domain that increasingly passes auth *for itself* | ⚠ | ⚠ | ⚠ | ◐ |
| 17 | **Sextortion / advance-fee / spam** | Botnet origin, no DKIM, SPF fail. **The only class where auth failure is a strong signal** | ❌ | ❌ | ❌ | ✅ |

`➖` = no inherent signature; determined by chosen delivery.

**Read the pattern: we currently cover rows 7, 15 and 17 well and rows 1–5 and
8–13 not at all.** Rows 1–5 are where the money goes.

### Prevalence anchors

- **Thread hijacking = 28.1% of BEC/fraud** — the single most common BEC technique [vendor, Sublime, Jan 2026].
- **Vendor-related BEC = 61% of all BEC** [vendor, Abnormal, H2 2025].
- **Banking-details-change requests carry a 26.5% compromise rate vs <1% for routine invoice inquiries** [vendor, Abnormal] — a 26× differential and the most actionable single number for our scoring.
- **72% of BEC used free webmail; Gmail 53%** [vendor, APWG Q1 2026].
- **HTML attachments: >10% malicious base rate — ~70× PDFs (0.15%)** [vendor, Barracuda, Jan 2026]. HTML is 31% of payloads.
- **SVG went 0.1% of attachment phishing (2024) → 19% of payloads (Q1 2026)**.
- **QR attacks +146% in 90 days** (7.6M Jan → 18.7M Mar 2026) [vendor, Microsoft].
- **Device-code phishing +1,500% H1 2026 vs H2 2025** [vendor, CrowdStrike, 4 Aug 2026]; 25+ kits by mid-2026, up from 1–2 in January.
- **Callback/TOAD = 15.9% of all attacks** — third-largest class, larger than malware [vendor, Sublime].
- **34.7% of attacks stack two or more evasion techniques** [vendor, Sublime]. **Our labelling must be multi-label.**
- **Higher education: 7.1% of phishing comes from compromised internal accounts — ~3× the average. For students specifically, 14.9%** [vendor, Abnormal, H2 2025]. As a university project this is our most relevant class and the one a purpose-built tool has the most headroom on.

---

## 3. The pre-built defences: what they do, what they provably fail at

### 3.1 SPF (RFC 7208)

**Proves:** the connecting IP is listed in the DNS policy of the domain in the
SMTP `MAIL FROM`. That is all.

| Pro | Con |
|---|---|
| Cheap, universal, catches naive direct spoofing | **Says nothing about the visible `From:`** — different identifier entirely |
| Machine-checkable, no crypto | **Forwarding breaks it by design** — the whole reason ARC exists |
| | **10-DNS-lookup limit (§4.6.4).** Any org with M365 + Google + Salesforce + Zendesk + payroll is at or over it. Exceeding → **PermError**, and receiver behaviour on PermError is *not* uniform. Silent, intermittent, and it **voids DMARC's SPF leg** |
| | **BreakSPF** [academic, NDSS 2024]: anyone controlling an IP inside a domain's SPF record can spoof that domain. **23,916 vulnerable domains** (23 in the Tranco top 1,000, incl. microsoft.com); **87,430 attacker-controllable IPs at <$0.01 each** across 181 countries; one IP usable against **11,408 domains**; **51.7% of SPF-publishing domains authorise >65,536 addresses** |
| | `+all`/`?all` misconfiguration — 3.3% of SPF domains; 7.7% syntactically malformed [vendor, RedHunt 2022, dated] |

### 3.2 DKIM (RFC 6376)

**Proves:** the holder of the key for `selector._domainkey.d=` signed *these
headers and this body*. A statement about **custody of content** — not about
this delivery, this envelope, this recipient, or this time.

| Pro | Con |
|---|---|
| Cryptographic, survives forwarding | **Does not cover the SMTP envelope at all.** This is the root of replay |
| `d=` is a real, checkable identity | **DKIM replay is actively exploited and the IETF says per-message detection is impossible.** `draft-ietf-dkim-replay-problem-00`: *"an individual, replayed message has no observable differences from a legitimate message"* [primary] |
| | **The April 2025 Google incident**: attacker put an entire phishing message in a Google OAuth app-name field, let Google email it, and replayed it — legitimately signed `d=google.com`, DMARC pass. Google fixed the *injection*, not the *replay*. Recurring since with Apple/PayPal invoice templates |
| | **`l=` tag abuse** — limits how many body octets are signed; anything appended beyond it renders but is unsigned. Trivially parsed, near-zero false positives, and **almost no product surfaces it** |
| | `d=` need not be the visible From — third-party signing is normal. Alignment only comes from DMARC |
| | 1024-bit keys persist; `x=` expiry rarely used; orphaned selectors for dead vendors are a standing forgery capability |

**General rule:** *any transactional email template with an attacker-controllable
free-text field is a DKIM-signature vending machine.*

### 3.3 DMARC — **and the standard changed in May 2026**

**DMARC is no longer RFC 7489.** **RFC 9989** (May 2026, Proposed Standard)
obsoletes RFC 7489 and RFC 9091; RFC 9990 covers aggregate reporting, RFC 9991
per-message failure reporting. [primary]

Three changes we must implement correctly:

1. **DNS Tree Walk replaces the Public Suffix List** for organisational-domain
   determination. **Any parser built on PSL logic is now non-conformant** — and
   that includes most libraries, possibly `checkdmarc`. Verify before trusting it.
2. New `psd=` tag for public-suffix domains.
3. **`pct=` is removed.** A tool that still displays or honours `pct` is
   describing a deprecated mechanism.

| Pro | Con |
|---|---|
| Adds alignment — the missing link between SPF/DKIM and the visible From | **Covers exactly one header field: `From:`.** Says nothing about `Reply-To`, `Return-Path`, `Sender`, or display name |
| Gives domain owners a policy lever and reporting | **Relaxed alignment (the default) means any attacker-controlled subdomain — including a dangling DNS/subdomain takeover — produces DMARC pass for the parent brand** |
| Mandates drove real adoption | **~56% of DMARC adopters are at `p=none`** [vendor, EasyDMARC, 1.8M domains, early 2026]. Only ~9% combine `p=reject` with reporting |
| | `dmarc=pass` under `p=none` is a **policy artefact, not a trust signal**. Record the policy alongside the result |
| | Higher education has the **lowest enforcement of any sector: 33.7%** [vendor, Valimail 2026] |

### 3.4 ARC (RFC 8617, Experimental)

**Fixes** the forwarding problem by having intermediaries record what auth
results they saw. **But it is not a protocol you can trust — it is an allowlist
you must curate.** M365 requires admins to name trusted sealers explicitly;
nothing is trusted by default, and a trusted sealer's ARC pass **overrides DMARC
failure**. Microsoft's own warning: *"a compromised vendor could pass spoofed
messages through your authentication checks."* [primary]

Measured abuse [academic, WWW '22, 674,564 headers]: misinterpretation attack on
Zoho (`arc=pass` from an *untrusted* source raised trust); broken-chain attacks
via iCloud Hide-My-Email and Firefox Relay; RFC violations in Outlook, Zoho,
Fastmail, OpenARC and Mailman3.

**The ARC chain is the richest untapped forensic artefact in a mail header** — a
per-hop, cryptographically anchored record of what each intermediary saw. Nobody
surfaces it to analysts. Parsing `i=` ordering, `cv=` values, chain validity, and
*whether the sealer is one this org actually trusts* is directly useful and
largely unbuilt.

### 3.5 BIMI

Requires DMARC at enforcement plus a mark certificate. **Common Mark
Certificates** (announced 26 Sep 2024) dropped the registered-trademark
requirement.

**There is no independent evidence that BIMI reduces phishing, and we should say
so plainly.** It is a *positive* indicator, and absence of a logo is the
overwhelmingly common case (**4% adoption**, Feb 2026), so users cannot learn
"no logo = suspicious" — the same failure mode as EV certificates. A lookalike
domain can obtain its own CMC for its own logo. BIMI's real, defensible benefit
is **enforcement-forcing**: it is a commercial carrot that gets marketing
departments to fund `p=reject`.

### 3.6 MTA-STS / DANE

Protect the **transport**, not the content. Both defeat STARTTLS stripping and MX
substitution. **Neither has anything to say about whether a message is phishing** —
wrong layer for our problem. Adoption is a rounding error: **0.07–0.12%**, with
**29.6% of adopters misconfigured** [academic, IMC '25].

### 3.7 DKIM2 — the thing worth watching

`draft-ietf-dkim-dkim2-spec-04`, **5 Jul 2026**, IETF DKIM WG (rechartered
specifically to solve replay). **Not deployable and won't be for years.**

Per-hop signatures, **envelope binding** (`MAIL FROM`/`RCPT TO` in the signature
— the direct fix for replay), and `Message-Instance` headers with JSON-encoded
modification "recipes" so a verifier can reconstruct and check *earlier* hops
over the *original* content. Explicitly positioned as an ARC successor.

**This is a genuine opportunity.** DKIM2's recipe model means a forensic tool
could, for the first time, reconstruct and independently verify the mutation
history of a forwarded message. There is no tooling. A DKIM2 chain
visualiser/verifier is a novel, standards-anchored contribution — and the draft
is weeks old.

### 3.8 The bulk-sender mandates

Google/Yahoo (Feb 2024) and Microsoft consumer domains (5 May 2025) require
SPF **and** DKIM, a DMARC record (`p=none` suffices), and alignment, for senders
of ≥5,000 msg/day. **Microsoft rejects (`550 5.7.515`); Google junks.** Same
nominal requirement, materially different consequence.

Measured effect: **265 billion fewer unauthenticated messages** reached Gmail in
2024 vs 2023, a **65% YoY reduction** [Google via M3AAWG Oct 2024, secondary].

**The honest half:** the surge was almost entirely `p=none` — dmarcian, Nov 2024:
*"the vast majority of domains that came in during the surge have stayed at
`p=none`."* The mandates eliminated unauthenticated bulk mail — a real win
against the cheapest spoofing. They did **not** produce enforcement, and they did
not touch the classes that account for the losses. **That is the strongest single
argument for why a detection and forensics tool is still needed in 2026, and it
belongs in our pitch.**

### 3.9 Secure Email Gateways (Proofpoint, Mimecast, Barracuda, Cisco)

MX-record interception. Pre-delivery blocking, DLP on egress, one policy surface.

**Structural limits — consequences of topology, not product quality:**

1. **Sees only mail crossing the MX. Internal-to-internal lateral phishing never
   traverses the gateway** — invisible. Against ~28% of BEC being thread
   hijacking, that matters enormously.
2. No mailbox or organisational context: doesn't know who normally emails whom,
   whether this vendor has ever invoiced you, or that an inbox rule was just
   created to hide replies.
3. **The MX record advertises the gateway.** Attackers look up which product a
   target uses and pre-test payloads against it.
4. Bypassable by direct delivery if the tenant still accepts SMTP directly.
5. **Allowlists are a standing hole**, and every false positive creates a durable
   one — admins respond to a quarantined invoice by adding an exemption.
6. Running a SEG in front of Defender means two engines disagreeing, with the auth
   trail already mangled by the SEG's own relaying.

**On the bypass statistics:** the widely-quoted Cofense "105% increase in
malicious emails bypassing SEGs" is **heavily selection-biased** — the data source
is user-reported mail in environments that already have SEGs, so by construction
every sample is a bypass. Cite it as "attackers routinely get through," never as
a rate. The IRONSCALES "SEGs miss 99.5%" figure is vendor-run, seven years old,
no methodology, no products named. **Do not cite it as evidence of SEG
performance.**

### 3.10 ICES / API-based (Abnormal, Sublime, Material, Check Point Harmony)

No MX change; reads mail post-delivery via Graph or the Gmail API. Builds a
behavioural baseline and communication graph.

| Catches what SEGs structurally cannot | Weaknesses |
|---|---|
| Internal/lateral phishing | **Post-delivery by design** — a real window during which the message is clickable. Vendors do not publish detection latency |
| Payload-less BEC (no URL, no attachment) | **Cold start** — new employees, new vendors, low-volume mailboxes are the weakest part of the model, and are exactly the BEC scenario |
| Thread hijacking / VEC via relationship anomaly | **Baseline poisoning** — a patient attacker inside a compromised account can establish normality before acting |
| Retroactive remediation | **Explainability** — behavioural ensembles are hard to justify to a user or an auditor |

**Sublime is the notable exception on explainability**: detections are written in
**MQL**, an open readable rule language, with the rule corpus public on GitHub and
a self-hostable platform. It is the closest thing to "Sigma for email" and the
most important prior art for what we are building. **Read it and position against
it rather than pretending it doesn't exist.**

There is **no independent comparative efficacy testing** of ICES products.
That absence is itself worth stating in a literature review.

### 3.11 Microsoft Defender for Office 365 — the documented gap worth quoting

From Microsoft's own docs [primary], which makes these non-contestable:

- User-impersonation protection: **max 350 users per policy**. Domain
  impersonation: **max 50 custom domains**. Exception lists cap at 1,024.
- Trusted-domain entries **do not cover subdomains** — you must add each one.
- **"Enable intelligence for impersonation protection" is OFF by default.**
- Impersonation protection needs Defender P1/P2. Exchange Online Protection alone
  gets only *spoof* intelligence. **Since impersonation is ~97%+ of the attack mix
  and exact-domain spoofing ~0.5%, the free tier addresses the rare case.**
- **The one to memorise:** *"Mailbox intelligence protection doesn't work if the
  sender and recipient previously communicated via email."* Read against thread
  hijacking being 28.1% of BEC: **Defender's impersonation protection is disabled
  by design for precisely the highest-volume BEC scenario.** It's a deliberate
  false-positive tradeoff, not a bug — but it is documented, quotable and
  exploitable.

**Google Workspace:** Security Sandbox is **off by default**, requires specific
tiers, and scans "Office documents, Microsoft executables, and PDFs" — note
what's *not* on that list: archives, ISO/IMG, LNK, HTML smuggling, script files.
Several advanced phishing toggles are also off by default. Gmail's own classifiers
are the largest phishing detectors in existence and **entirely opaque** — no
published FPR/FNR. For academic purposes **Gmail is an unmeasurable baseline**,
which is worth stating as a limitation of the field.

### 3.12 URL rewriting / time-of-click — and how it inverts

**CAPTCHA gating is the best-measured evasion and the result is total failure,
not degradation.** *PhishDecloaker* [academic, USENIX Security 2024]: against
CAPTCHA-cloaked phishing sites, **VirusTotal (92 engines) blacklisted 0/100,
Google Safe Browsing 0/100, Microsoft Defender SmartScreen 0/100** — versus
100/100 on the identical uncloaked baseline. *"All CAPTCHA-cloaked sites remain
undetected for 7 days and counting."* CAPTCHA-cloaked sites grew ~10× in six
months. A CAPTCHA is a ~10-line addition to a kit that reduces the entire
URL-reputation industry to zero. Microsoft measured **11.9 million CAPTCHA-gated
phishing attacks in March 2026 alone, +125%** within the quarter.

Also: cloaking on crawler UA/ASN, geofencing, single-use victim-keyed links
(the scanner's fetch burns the token), and delayed weaponisation.

**And the inversion — *Weaponizing Safe Links*** [LevelBlue SpiderLabs, 12 Mar
2026]: compromise an account at an org whose gateway rewrites URLs, mail yourself
the malicious link, harvest the now-vendor-branded rewritten URL, and mass-mail
*that*. The link is now hosted on a security vendor's trusted domain. Attackers
**stack three or more vendors' rewriters in one chain**. Documented abused:
Cisco, Trend Micro, Barracuda, EdgePilot, Sophos, Inky, Proofpoint, Zscaler.
Peaked January 2026.

**URL rewriting converts a security vendor into a reputation-laundering service —
and it poisons our forensics, because the observable URL is a vendor domain and
the true destination is only recoverable by decoding the wrapper.**

### 3.13 Attachment sandboxing

Environment detection, human-interaction gating, time bombs,
**password-protected archives** (the sandbox has no password), container formats,
HTML smuggling (nothing to detonate), environmental keying.

**Structural point: sandboxing is a *malware* control being asked to solve a
*social-engineering* problem. Against credential phishing and BEC — where the
money goes — it has no purchase at all.**

### 3.14 What actually works: phishing-resistant MFA

The one intervention with a strong, consistent real-world signal, and it is
*categorical* rather than statistical. FIDO2/WebAuthn credentials are scoped to
an origin; a credential for `login.microsoftonline.com` is cryptographically
unusable at a lookalike. The browser, not the human, enforces it.

- **Google:** hardware keys mandated for >85,000 employees (2017), **zero
  successful employee account phishing** afterwards. [Google self-reported via
  Krebs — a specific, falsifiable, large-N claim unrefuted since 2018.]
- **Cloudflare, Aug 2022:** during the 0ktapus campaign, employees *were* phished
  — credentials and TOTP codes captured — and the attack still failed, because
  hardware keys were mandatory. **The cleanest natural experiment available:**
  same campaign, same lure, same human failure, different factor, different
  outcome.

**Caveats we must state:** fallback paths ("lost my key → verify by SMS") are only
as strong as the fallback; Proofpoint demonstrated a **FIDO downgrade attack**
(spoof Safari-on-Windows, Entra declines FIDO, user is offered a weaker method) in
Aug 2025 — demonstrated, not observed in the wild. And **device-code and OAuth
consent phishing bypass the login page entirely, so passkeys do not stop them.**
That is the most important correction to a 2024-era mental model.

### 3.15 The thing not to build our pitch on: user training

*Understanding the Efficacy of Phishing Training in Practice*, Ho et al.,
**IEEE S&P 2025** — RCT, **~19,500 employees, 8 months, 10 campaigns**. The
strongest study design in this whole area, and the result is negative.

- Annual mandatory awareness training: **no significant relationship** with
  susceptibility.
- Embedded "you clicked, here's a lesson" training: **~2% absolute reduction**,
  "despite substantial time and resource investment."
- **75% spent ≤1 minute on the training; 33% closed it with no engagement.**
- **Click-through rose from ~10% in month 1 to >50% by month 8** — over an
  8-month window, **more than half of employees clicked at least one link**. Any
  model premised on users not clicking is invalid.
- **Lure content dominates the person: 1.82% clicked an "Outlook password update"
  lure vs 30.8% for "vacation policy update" — a ~17× spread.** Susceptibility is
  a property of the *message*, not the person, which undercuts risk-scoring
  individuals from simulation results.
- Authors' conclusion, verbatim: *"anti-phishing training programs, in their
  current and commonly deployed forms, are unlikely to offer significant practical
  value in reducing phishing risks."*

---

## 4. Where Mailtrace fits — and the arithmetic that decides it

**Do not compete on binary classification at the MX. It is unwinnable, and the
reason is arithmetic, not effort.**

Take a 10,000-person org receiving 1M emails/day with 0.1% phishing (1,000 phish,
999,000 legitimate — and 0.1% is generous):

- A detector at **99% accuracy / 1% FPR** produces **9,990 false positives/day**
  against 990 true positives. **Precision ≈ 9%.** Over 90% of what the analyst
  sees is wrong, and ~10,000 legitimate business emails get quarantined daily.
- For 50% precision you need **FPR ≈ 0.1%** — 10× better than "99% accurate".
- For operationally comfortable precision you need **FPR in the 10⁻⁴–10⁻⁵ range**.

**A paper reporting 98–99% accuracy on a balanced 50/50 corpus has demonstrated
approximately nothing about deployability, because the balanced corpus removes the
base rate, which is the entire difficulty.** This is the most common
methodological error in the phishing-ML literature, and stating it clearly is
itself a contribution.

And false positives on email are not cheap alerts — they are lost business. A
quarantined invoice or customer reply has direct cost, admins respond with
allowlist entries, and **every false positive creates a durable hole.**

**So our position is:** operate on mail that is *already* flagged or reported,
where the base rate is 20–60% rather than 0.1%, where a false positive costs an
analyst a minute rather than a contract, and where **explainability is the
product**. Triage and forensics is the tractable problem. Detection at the MX is
not. This is exactly what our evidence-and-scorer architecture is for, and it is
the answer to "why not just use Gmail's filter?"

---

## 5. Prior art — name it, position against it

| Tool | What it is | Its limits = our opening |
|---|---|---|
| **Microsoft MHA** (open source) | Paste-a-header web tool; parses `Received` chains, hop delays, `Authentication-Results` | Presentation only. No enrichment, no geolocation, no intel, no persistence, **no correlation across messages**. One message at a time |
| **Mailheader.org / MXToolbox** | Same category, hosted | Same, **plus you paste sensitive headers into a third party** — an easy differentiator for a self-hosted tool |
| **PhishTool** | Commercial phishing forensics; `.eml`/`.msg` parsing, IOC extraction, case tracking. Free tier used in TryHackMe SOC training | Closed source, **no rule language, no campaign clustering**, verdicts are analyst-assigned rather than modelled |
| **ThePhish** (ITASEC '22) | **The closest academic prior art to us.** Flask app automating observable extraction → Cortex analysers → verdict → MISP | Read it and position explicitly. Its stated limits are instructive: *"a universally correct configuration does not exist"*; parsed only 90% of emails; verdicts came out **84.6% malicious / 15.4% suspicious — it essentially never returns benign**, making it useless as a triage filter |
| **Sublime MQL** | Open rule corpus, self-hostable, VS Code extension | Our realistic benchmark for expressiveness. Open, so we can evaluate against it instead of guessing |
| **TheHive / Cortex / MISP** | The standard open IR/TI triad | Moved to commercial-first licensing under StrangeBee; the free edition is feature-limited, which affects "open source" claims |

**Nothing integrates header forensics + enrichment + campaign clustering with a
defensible methodology. The integration and the rigour are our opening.**

### A specific novel angle, grounded in peer review

**Parser differentials.** *Weak Links in Authentication Chains* [academic, USENIX
Security 2021] plus *Composition Kills* [USENIX Security 2020]: different
components in the mail path (MTA, authenticator, MUA) **disagree about which
header is "the" `From`**, and attackers exploit the disagreement so that the
*authenticated* identity differs from the *displayed* identity.

**A forensic tool that reports "the authenticator evaluated identity X; a typical
mail client will display identity Y" is directly novel, grounded in peer-reviewed
work, and cheap to implement. No product surfaces this.**

---

## 6. Geolocation — what we may and may not claim

This is our weakest component and the easiest to overclaim. Get it wrong in front
of a DFIR judge and it costs us the room.

**The defensible evidence** [academic, Komosny, PeerJ CS 9:e1305, 2023]:
country-level accuracy 2015–2022 — Germany/Austria/US/India >99%, UK >99.4%,
France >98.7%, Italy ~97.4% — **but Iran 86.5% and Ukraine 89.3%**, below the
author's 95th-percentile validity threshold. Conclusion: country-level
geolocation *can* be forensically valid, but *"each evidence should be processed
individually,"* and country accuracy must not be generalised or taken from stale
data.

**Everything below country level is not forensically defensible.** City-level
accuracy is poor and variable; the commonly cited MaxMind city figures are
commercial claims.

**And the killer argument, which we should make ourselves before anyone makes it
at us:** BreakSPF harvested **87,430 attacker-controllable IPs across 181
countries at under one cent each**. Sender IP geolocation is **not attribution**.
The earliest `Received` IP is very often a legitimate relay, an ESP, or a cheap
cloud VM — geolocating it tells you where AWS is.

**Rule for the UI, the report and the demo script: present geolocation as a
*consistency check*, never as attribution.** The defensible framing is relational:
*"this sender claims to be a UK council but the first trustworthy hop is a
Vietnamese residential proxy"*, or *"this thread's hops changed country
mid-conversation"* — not *"the attacker is in country X."*

---

## 7. Two flaws in our current scoring model

Found while writing this. Both are real, both are in `weights.yaml` today.

### 7.1 `dkim_valid_aligned: -25` actively suppresses the worst attacks

A valid, aligned DKIM signature is exactly what thread hijacking, ATO, VEC, LOTS
and authentication laundering all produce — rows 1–5 of the taxonomy, where the
losses are. Subtracting 25 points for it means **the more damaging the attack
class, the lower we score it.** That is backwards.

Same problem, smaller: `known_correspondent: -20`. A known correspondent is
precisely the thread-hijacker's position, and baseline poisoning is a documented
technique.

**Fix implemented:** negative signals now support a `suppressed_by` list in
`weights.yaml`. A negative weight does not apply when any listed deception signal
is TRIGGERED. Cryptographic proof of authorship still reduces risk on an
otherwise clean message — but it can no longer cancel out evidence of forgery or
impersonation. The suppression is recorded in the verdict's contributions so it
stays explainable.

### 7.2 Our auth signals target ~0.5% of the attack mix

`spf_fail_hard`, `dmarc_fail_strict` and `dkim_missing` are high-precision when
they fire, so keep them — but they only fire on exact-domain spoofing and botnet
spam. **They must not be the story we tell.** The story is rows 1–13, and today we
cover almost none of them. Section 8 is the fix list.

---

## 8. Proposed new signals

Ready to paste into `app/scoring/weights.yaml` — **but only alongside the analyzer
that emits each one**, per rule 3 in `CLAUDE.md`. Ordered by (value × cheapness).

### Tier 1 — cheap, high precision, build these first

```yaml
  fake_reply_framing:
    weight: 22
    analyzer: M2
    label: "Subject claims a reply but no thread reference exists"
    rationale: >
      Subject begins Re:/Fwd: with no In-Reply-To and no References header.
      55.9% of VIP-impersonation attacks used subject manipulation (Sublime 2026).
      Cheap, deterministic, and very high precision.

  dkim_length_limited:
    weight: 24
    analyzer: M3
    label: "DKIM signature carries an l= body-length tag"
    rationale: >
      l= limits how many body octets are signed; anything appended beyond it
      renders unsigned. Lets an attacker replay one signed message with arbitrary
      added HTML. Trivially parsed, near-zero false positives, and almost no
      product surfaces it.

  spf_permerror:
    weight: 12
    analyzer: M3
    label: "SPF evaluation returned PermError"
    rationale: >
      Usually the RFC 7208 10-lookup limit. Receiver behaviour on PermError is
      not uniform and it silently voids DMARC's SPF leg. Universally unmonitored.

  dmarc_pass_under_p_none:
    weight: 8
    analyzer: M3
    label: "DMARC passed but the policy is p=none"
    rationale: >
      A pass under p=none is a policy artefact, not a trust signal. Record the
      policy next to the result rather than reporting a bare pass.

  dkim_aligned_via_subdomain:
    weight: 14
    analyzer: M3
    label: "DKIM aligns only under relaxed alignment, via a subdomain"
    rationale: >
      Relaxed alignment is the default, so any attacker-controlled subdomain -
      including a dangling DNS record or subdomain takeover - produces DMARC pass
      for the parent brand.

  freemail_display_name_impersonation:
    weight: 24
    analyzer: M4
    label: "Free webmail sender with a display name impersonating a known party"
    rationale: >
      72% of BEC used free webmail, 53% Gmail (APWG Q1 2026). Passes SPF, DKIM
      and DMARC by construction, so authentication cannot see it at all.

  html_attachment_present:
    weight: 16
    analyzer: M1
    label: "HTML file attached"
    rationale: >
      Over 10% of all HTML attachments are malicious - roughly 70x the rate for
      PDFs and Office documents (Barracuda, Jan 2026). The strongest single
      attachment prior available.

  no_url_with_phone_number:
    weight: 20
    analyzer: M4
    label: "No URLs, but a phone number is present"
    rationale: >
      The TOAD / callback-phishing signature. Callback is 15.9% of all attacks
      (Sublime) and there is no shared reputation feed for phone numbers, so they
      stay clean for days. Genuine greenfield.

  bank_detail_change_request:
    weight: 26
    analyzer: M4
    label: "Request to change banking or payment details"
    rationale: >
      Billing-account-update requests carry a 26.5% compromise rate versus under
      1% for routine invoice inquiries (Abnormal) - a 26x differential, the
      sharpest intent signal available.
```

### Tier 2 — needs real parsing work

```yaml
  hidden_text_payload:
    weight: 26
    analyzer: M1
    label: "Text present in the raw MIME but invisible when rendered"
    rationale: >
      display:none, font-size:0, colour-on-colour, off-screen positioning, or
      zero-width characters. The delivery mechanism for AI-assistant prompt
      injection (CVE-2026-26133) and for classifier poisoning. The delta between
      the rendered and raw text views is the feature, and it costs almost nothing
      to compute.

  svg_active_content:
    weight: 26
    analyzer: M1
    label: "SVG attachment containing script or event handlers"
    rationale: >
      SVG is XML, so it carries script, onload=, foreignObject and data URIs.
      SVG went from 0.1% of attachment phishing in 2024 to 19% of payloads in
      Q1 2026. Parse it as XML, not as an image, and match script type= against a
      broad allowlist - including the deprecated application/ecmascript, which
      current rules keyed on text/javascript miss entirely.

  qr_code_present:
    weight: 14
    analyzer: M1
    label: "QR code found in the body or an attachment"
    rationale: >
      A message containing a QR code is 1.4x more likely to be an attack
      (Sublime). 70% of malicious PDFs carry one. Needs recursive
      rasterize-and-decode; vector QR inside SVG has no bitmap to decode until
      rendered.

  device_code_lure:
    weight: 30
    analyzer: M4
    label: "Device-code authorization lure"
    rationale: >
      A short alphanumeric code plus a link to a genuine first-party device-login
      endpoint, and nothing else. Device-code phishing rose 1,500% in H1 2026 and
      defeats passkeys, URL reputation and sandboxing simultaneously, because the
      only link is legitimate. No existing tool covers it.

  oauth_consent_lure:
    weight: 28
    analyzer: M4
    label: "OAuth consent URL with broad scopes or an off-domain redirect"
    rationale: >
      Link is the real IdP authorize endpoint, so reputation is clean. The tell is
      in the query string: unfamiliar client_id, attacker-domain redirect_uri,
      broad scope list. Parsing authorize-URL parameters as first-class fields is
      an under-served detection surface.

  foreign_url_rewriter:
    weight: 22
    analyzer: M5
    label: "URL was rewritten by a security vendor that is not ours"
    rationale: >
      Weaponizing Safe Links (LevelBlue, Mar 2026): attackers harvest
      vendor-rewritten URLs and mass-mail them, stacking three or more rewriters.
      Turns a security vendor into a reputation-laundering service. Requires a
      recursive unwrapper for Cisco, Trend Micro, Barracuda, EdgePilot, Sophos,
      Inky, Proofpoint and Zscaler formats.

  ics_invite_payload:
    weight: 18
    analyzer: M1
    label: "Calendar invite carrying a URL, QR code or phone number"
    rationale: >
      Over 20% of Q4 2025 callback phishing arrived by calendar invite, roughly
      100x growth across 2025. Invites auto-add to the calendar and the entry
      persists after the email is deleted or quarantined - so message-scoped
      remediation is structurally wrong here.

  html_smuggling_indicators:
    weight: 24
    analyzer: M1
    label: "HTML attachment assembles a file client-side"
    rationale: >
      atob(, Blob(, createObjectURL, download=, or base64 decoding to MZ/PK magic
      bytes. No file crosses the perimeter, so gateway file inspection sees
      nothing. MITRE T1027.006.

  header_parser_differential:
    weight: 26
    analyzer: M2
    label: "Authenticated identity differs from the identity a mail client renders"
    rationale: >
      Duplicate From headers, or MIME structure where the authenticator and the
      MUA disagree about which identity is authoritative. Grounded in Weak Links
      in Authentication Chains (USENIX Security 2021) and Composition Kills
      (USENIX Security 2020). No product reports this.

  arc_untrusted_sealer:
    weight: 16
    analyzer: M3
    label: "ARC chain sealed by a party this organisation does not trust"
    rationale: >
      A trusted sealer's ARC pass overrides DMARC failure, so an untrusted or
      broken chain being honoured is a bypass. Measured abuse in WWW '22:
      misinterpretation on Zoho, broken chains via iCloud Hide-My-Email and
      Firefox Relay.

  lots_platform_sender:
    weight: 10
    analyzer: M6
    label: "Sent through a legitimate platform's notification feature"
    rationale: >
      Weak alone - most such mail is genuine - but it explains why every auth
      signal is green and it should gate first-contact and content checks on the
      user-controlled fields. Emerging platforms are now the largest LOTS bucket
      at 32.8%, so a hardcoded Big-Tech allowlist is worse than nothing.

  first_contact_sender:
    weight: 12
    analyzer: M7
    label: "No prior correspondence with this sender identity"
    rationale: >
      For the classes that pass authentication, relationship history is the only
      discriminator left. Pairs with bank_detail_change_request and
      freemail_display_name_impersonation.

  compauth_bypass_indicator:
    weight: 26
    analyzer: M2
    label: "Delivered despite failing composite authentication"
    rationale: >
      CompAuth reason=905/451/601 or the internal-looking X-MS-Exchange-
      Organization-* combination indicate complex-routing or misconfigured
      spoof-protection bypass. Microsoft blocked over 13 million Tycoon2FA-linked
      emails via this vector in October 2025. Note this is NOT Direct Send abuse -
      Microsoft explicitly distinguishes the two, and most vendor blogs conflate
      them.
```

### Non-message-scoped detectors — need architecture, not a signal

These cannot be expressed as per-message evidence and should be scoped
deliberately in or out:

- **Email bombing** — burst/rate detection over the *recipient* axis. Largest
  observed 10,000+ messages; average 360.5 at 17.85/minute. Used to bury a real
  ATO notification, or as the setup for a fake tech-support callback. A
  per-message classifier is architecturally blind to it.
- **Calendar object lifecycle** — the `.ics` entry survives message remediation.
- **IdP telemetry join** — device-code phishing is visible in Entra as
  `authenticationProtocol: deviceCode`; AiTM shows as User-Agent/AppID
  mismatch in sign-in logs. Several classes are **only** visible there. If we
  claim to detect them, design the join now or scope them out honestly.
- **Internal mail ingestion** — lateral phishing never crosses the MX. Without
  journaling or Graph ingestion, our most relevant class as a university is
  invisible.

---

## 9. Corpus and evaluation — the field's binding constraint

The de facto corpora (Nazario, Enron, SpamAssassin, Nigerian Fraud) are
inadequate, and saying so clearly is itself a contribution:

- Most **predate 2010**, so they cannot reflect modern or AI-assisted campaigns.
- They **strip full URL structures, attachment names and usually headers** — the
  exact signals half the current attack classes live in.
- **No intent annotations**, no three-way phishing/spam/valid separation.
- Because they are old and public they are **almost certainly in LLM pretraining
  data**; Toth et al. (2026) observed contamination directly. Reported LLM scores
  on them are partly memorisation.

**What we must do instead:**

1. **Temporal split** — train on pre-date, test on post-date. Never random split.
2. **Report at a fixed, operationally relevant FPR**, not top-line accuracy, and
   never on a balanced corpus (see §4).
3. **Multi-label ground truth** — 34.7% of attacks stack ≥2 techniques; a
   single-label schema bakes in error.
4. Report the forensic checks separately from the classifier. A forged hop is
   present or absent — the meaningful metric there is **false-positive rate on a
   clean ham corpus**, not F1.

On LLMs specifically: they **currently underperform** well-tuned classical models
on raw binary accuracy, while being better at explanation and context-dependent
cues. Best frontier result found: **Gemini-3.1-Pro 0.958 F1 on phishing with
metadata** — but the same models **collapse on spam (F1 ≤ 0.428)**. And
LLM-rephrased emails degrade both ML and LLM detectors. Use the LLM for intent
and explanation, as M4 already does; do not make it the verdict.

---

## 10. Corrections to make in our own code and copy

1. **DMARC is RFC 9989 now.** Verify whether `checkdmarc` implements the DNS Tree
   Walk rather than PSL logic. Remove any `pct=` handling.
2. **Never claim to recover a sender IP from webmail-composed mail** — already in
   `CLAUDE.md`, restated here because it is the single most likely thing to be
   challenged on.
3. **Reframe the geolocation UI and report copy as a consistency check**, not
   attribution. See §6.
4. **Un-wrap security-vendor URL rewriters** before storing or displaying a URL,
   or our forensics report will name a vendor's domain as the destination.
5. **Store three identity fields separately** — `smtp.mailfrom`, `header.from`,
   `dkim.header.d` — plus `Reply-To`, `Sender`, `Return-Path`, `Message-ID` domain
   and the `From` display name, and compute every cross-field divergence
   explicitly. Never trust a summarised "auth: pass".
6. **Preserve `Authentication-Results`, `ARC-Authentication-Results`,
   `X-MS-Exchange-Organization-*` and CompAuth `reason=` codes verbatim.** They
   are the only way to distinguish "passed" from "not evaluated" from "bypassed".
7. **Two text views per message, rendered and raw.** Score the difference (§8,
   `hidden_text_payload`).
8. **Do not submit live phishing URLs to public urlscan.** It burns a single-use
   link, tips off the actor, and public submissions have repeatedly leaked
   sensitive URLs. Always `visibility: "unlisted"`.

---

## 11. What to say when a judge asks "why does this need to exist?"

> The bulk-sender mandates removed 265 billion unauthenticated messages from Gmail
> in one year — a real, structural win. But the surge was almost entirely
> `p=none`, and exact-domain spoofing was already about half a percent of
> impersonation attacks. The mandates raised the floor of the sending ecosystem.
> They did not touch the classes that account for the losses, because those
> classes pass authentication by construction — a compromised mailbox really is
> the mailbox. Meanwhile the best-designed study of user training, an RCT over
> 19,500 people, found essentially no effect, and more than half of employees
> clicked at least one link within eight months. So the gap is not prevention and
> it is not user education. It is what happens after a suspicious message is
> identified: reconstructing the path, naming the infrastructure, linking it to a
> campaign, and producing something an investigator can act on. That is the gap we
> build into.

---

## Sources

Attack landscape: [Microsoft Q1 2026 email threat landscape](https://www.microsoft.com/en-us/security/blog/2026/04/30/email-threat-landscape-q1-2026-trends-and-insights/) · [Microsoft: Inside Tycoon2FA](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/) · [Microsoft: complex routing & spoof misconfiguration](https://www.microsoft.com/en-us/security/blog/2026/01/06/phishing-actors-exploit-complex-routing-and-misconfigurations-to-spoof-domains/) · [Microsoft: authentication laundering / Photo ZIP](https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/) · [Microsoft: ClickFix analysis](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/) · [APWG Q1 2026](https://docs.apwg.org/reports/apwg_trends_report_q1_2026.pdf) · [Barracuda 2026 Email Threats Report](https://www.barracuda.com/reports/2026-email-threats-report) · [Sublime 2026 Email Threat Research Report](https://sublime.security/blog/key-findings-from-the-2026-sublime-email-threat-research-report/) · [Sublime: ICS phishing surge](https://sublime.security/blog/ics-phishing-stopping-a-surge-of-malicious-calendar-invites/) · [Abnormal 2026 Attack Landscape](https://abnormal.ai/newsroom/press-releases/2026-attack-landscape-report) · [Abnormal: higher education](https://abnormal.ai/blog/2026-attack-landscape-report-higher-education) · [FBI IC3 2025](https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf) · [Talos IR Trends Q2 2026](https://blog.talosintelligence.com/ir-trends-q2-2026/) · [Talos: PDFs and TOAD](https://blog.talosintelligence.com/pdfs-portable-documents-or-perfect-deliveries-for-phish/) · [Push: browser threat landscape mid-2026](https://pushsecurity.com/blog/browser-threat-landscape-mid-year-update-2026) · [Push: device code phishing](https://pushsecurity.com/blog/device-code-phishing) · [CSA Labs: OAuth device code phishing](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_oauth-device-code-phishing-M365-20260325-csa-styled.pdf) · [Permiso: Copilot prompt injection, CVE-2026-26133](https://permiso.io/blog/copilot-prompt-injection-ai-email-phishing) · [Hoxhunt: SVG attachments](https://hoxhunt.com/blog/svg-phishing-email-attachments-mini-report) · [Ironscales: when SPF, DKIM and DMARC all pass](https://ironscales.com/threat-intelligence/authenticated-phishing-bypasses-email-authentication) · [Sekoia: AiTM analysis](https://www.sekoia.com/blog/global-analysis-of-adversary-in-the-middle-phishing-threats)

Standards: [RFC 9989 — DMARC](https://datatracker.ietf.org/doc/rfc9989/) · [draft-ietf-dkim-dkim2-spec](https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-spec/) · [DKIM replay problem statement](https://www.ietf.org/archive/id/draft-ietf-dkim-replay-problem-00.html) · [RFC 8617 — ARC](https://www.rfc-editor.org/rfc/rfc8617.html)

Peer-reviewed: [BreakSPF, NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-113-paper.pdf) · [ARC forwarding security, WWW '22](https://gangw.cs.illinois.edu/arc-www22.pdf) · [Weak Links in Authentication Chains, USENIX Sec '21](https://www.usenix.org/system/files/sec21-shen-kaiwen.pdf) · [PhishDecloaker, USENIX Sec '24](https://www.usenix.org/system/files/usenixsecurity24-teoh.pdf) · [MTA-STS deployment, IMC '25](https://dl.acm.org/doi/10.1145/3730567.3732916) · [Efficacy of Phishing Training, IEEE S&P 2025](https://people.cs.uchicago.edu/~grantho/papers/oakland2025_phishing-training.pdf) · [SoK: Grouping Spam and Phishing Email Threats, IEEE Access 2025](https://vaniea.com/publication/saka2025sokcampaign/saka2025sokcampaign.pdf) · [IP geolocation evidential value, PeerJ CS 2023](https://peerj.com/articles/cs-1305/) · [ThePhish, ITASEC '22](https://ceur-ws.org/Vol-3260/paper6.pdf) · [LLM personalized phishing field study, USENIX Sec '26](https://www.usenix.org/conference/usenixsecurity26/presentation/czybik) · [PhishFuzzer benchmark, 2026](https://arxiv.org/html/2511.21448v5) · [Newly-registered phishing domains at scale, Oxford 2026](https://academic.oup.com/cybersecurity/article/12/1/tyag020/8735840)

Product documentation: [Microsoft anti-phishing policy limits](https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-about) · [Microsoft trusted ARC sealers](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc-configure) · [Gmail Security Sandbox](https://knowledge.workspace.google.com/business-continuity/security-and-monitoring/gmail-security-sandbox-overview) · [Sublime MQL](https://docs.sublime.security/docs/message-query-language) · [Sublime open rule corpus](https://github.com/sublime-security/sublime-rules)

Bypass research: [LevelBlue: Weaponizing Safe Links](https://www.levelblue.com/blogs/spiderlabs-blog/weaponizing-safe-links-abuse-of-multi-layered-url-rewriting-in-phishing-attacks) · [Cofense: SEG vs SEG](https://cofense.com/blog/seg-vs-seg-how-threat-actors-are-pitting-email-security-products-against-each-other/) · [EasyDMARC: Google DKIM replay breakdown](https://easydmarc.com/blog/google-spoofed-via-dkim-replay-attack-a-technical-breakdown/) · [Proofpoint: FIDO downgrade](https://www.proofpoint.com/us/blog/threat-insight/dont-phish-let-me-down-fido-authentication-downgrade)

Adoption: [EasyDMARC 2026 adoption report](https://easydmarc.com/blog/ebook/dmarc-adoption-report-2026/) · [Valimail 2026 State of DMARC](https://www.valimail.com/newsroom/valimail-2026-dmarc-report/) · [dmarcian: Microsoft enforcement](https://dmarcian.com/microsoft-enforces-spf-dkim-dmarc/)
