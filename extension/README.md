# Mailtrace for Gmail (Chrome extension)

Two features over one Mailtrace account:

- **Inbox risk** — every new message that lands in your Gmail inbox is sent to
  your Mailtrace backend and comes back with a 0–100 score, a band
  (**Clean / Suspicious / High Risk / Critical**) and the signals behind it.
- **Read receipts** — see when the mail *you* send gets opened (the original
  feature; unchanged).

The extension does **no scoring and no parsing of its own**. It ships the
original message bytes to `POST /api/cases` and displays the verdict the backend
returns, so the judgement stays in one place.

Which scorer that is depends on the backend URL you configure: the FastAPI
surface runs `app/scoring/engine.py`, the Next.js/Vercel one (the default) runs
`web/src/lib/scoring/engine.ts`.

Those two place the band boundaries one point apart, so a score of exactly
**25, 50 or 75 lands one band higher on the Python backend** than on the
TypeScript one (25 is `SUSPICIOUS` on Python, `BENIGN` on TypeScript). Both are
self-consistent with their own `weights.yaml` — this is two maintained rule sets
differing by an off-by-one in convention, not code that drifted from a spec, and
it predates the extension. Track E owns `scoring/`; the difference is theirs to
resolve. Each record keeps the `scorer_version` that produced it, so a verdict
can be traced back to the rules behind it.

## Install

1. Open `chrome://extensions`, toggle **Developer mode** on.
2. **Load unpacked** → select this `extension/` folder.
3. Copy the **extension ID** Chrome shows on the card — you need it below.
4. Do the Google setup in the next section, then reload the extension.
5. A setup tab opens on install. Sign in to Mailtrace, then **Connect Gmail**.

> The unpacked extension ID is derived from this folder's path, so it stays
> stable as long as you don't move the folder. If you need it fixed across
> machines, add the `key` field to `manifest.json`.

## Google setup (required for inbox risk)

Reading mail needs an OAuth client that you own; there is no shared one. In the
[Google Cloud Console](https://console.cloud.google.com/):

1. Create (or pick) a project.
2. **APIs & Services → Library → Gmail API → Enable.**
3. **OAuth consent screen** → User type **External** → fill in app name and
   support email. Under **Scopes** add
   `https://www.googleapis.com/auth/gmail.readonly`. Leave the publishing
   status on **Testing** and add every address that needs to connect under
   **Test users** — see "Who can connect their Gmail" below, because this is
   the step that decides who the extension works for.
4. **Credentials → Create credentials → OAuth client ID → Application type:
   Chrome Extension**, and paste the extension ID from step 3 of Install.
5. Copy the generated client ID into `extension/manifest.json`:

```json
"oauth2": {
  "client_id": "123456789-abcdef.apps.googleusercontent.com",
  "scopes": ["https://www.googleapis.com/auth/gmail.readonly"]
}
```

6. Reload the extension at `chrome://extensions`, then click **Connect Gmail**.

Until a real client ID is in place, the setup page and popup say so instead of
opening a broken consent prompt.

## Who can connect their Gmail

`gmail.readonly` is a **restricted** scope, the tier Google controls most
tightly. While the consent screen's publishing status is **Testing**, only
addresses on the test-user list can connect. Everyone else gets
*"Access blocked: Mailtrace has not completed the Google verification process"*
with `Error 403: access_denied`. That is policy enforcement, not a bug, and no
change to this extension can bypass it.

**Two gates, commonly confused.** Chrome Web Store review controls whether
someone can *install* the extension. Google OAuth verification controls whether
they can *connect Gmail*. Passing store review grants nothing on the OAuth side:
a published extension still shows "Access blocked" to anyone who is not a test
user.

### Adding a user (the current model)

**Google Auth Platform → Audience → Test users → Add users** (older console:
**APIs & Services → OAuth consent screen → Test users**). Paste one address per
line; up to **100**. They must be Google accounts — a Gmail address, or a domain
actually hosted on Google Workspace. A non-Google mailbox cannot be a test user
at all.

Check the project selector is on the right project first. Adding users to the
wrong project is the usual reason it appears not to work.

### The warning screen your users will still see

Test users are let through, but they first get
*"Google hasn't verified this app"*. To proceed they must click **Advanced**,
then **Go to Mailtrace (unsafe)**. This surprises people mid-demo, so warn them
it is expected for an app in Testing. It disappears only after verification.

### Going fully public

Moving to **In production** with a restricted scope requires OAuth verification
(public homepage, privacy policy, verified domain ownership, and a demo video of
the consent flow) *plus* a **CASA** security assessment by a Google-authorised
third-party assessor, repeated annually and paid for. Review takes weeks.
Requirements and pricing change — check Google's current API Services User Data
Policy rather than trusting a figure from here.

There is no narrower scope that avoids this. `gmail.metadata` is also restricted
**and** forbids `format=raw`, so it cannot return the bytes M2 and M3 need.
`gmail.send` is merely sensitive but cannot read anything.

### Session mode — the no-OAuth route (experimental)

`gmail-web.js` explores a way around all of the above. Gmail's own
**Show original** view serves the raw message from `mail.google.com`, and the
content script already runs on that origin — so a `fetch` with
`credentials: 'include'` returns the source using the session the user is
already signed into. No OAuth, no consent screen, no restricted scope, no
verification, and therefore no 100-user ceiling.

It is not a documented API, so treat it as a prototype:

- The URL shape and the `ik` session token are Gmail internals. Several
  candidate forms are tried in order and the one that worked is reported.
- **Fidelity is the real risk.** If Gmail returns the message wrapped in HTML,
  recovering it means unescaping entities and possibly losing CRLF line endings.
  DKIM body hashes are computed over exact bytes, so an HTML-recovered message
  can fail verification even when the mail is correctly signed — and a *wrong*
  DKIM result is worse than none. The probe therefore measures line endings and
  extraction path, sets `dkimSafe` only for a byte-exact response, and records
  `dkimTrustworthy` on the stored verdict so the popup can say so.
- There is no equivalent of `history.list`, so new mail cannot be detected the
  way the API path does. This suits on-demand analysis of a message on screen
  better than continuous background scanning.

Run **Test session mode** in the popup, with Gmail open, to see what a given
account actually returns.

## Why the Gmail API and not the page

The verdict rests on things that only exist in the original message: the
`Received:` chain M2 walks to find the trust boundary, and the DKIM signature M3
re-verifies byte-for-byte. Gmail's rendered DOM has neither, and anything the
extension re-serialized itself would break the signature. `messages.get` with
`format=raw` returns the untouched RFC 5322 bytes, which is the only input the
backend parsers are specified against.

## How often it checks

Gmail is polled with `history.list`, which returns only what changed since the
last cursor — cheap enough to run often.

| Setting | While a Gmail tab is open | With Gmail closed |
|---|---|---|
| 3s / 5s / 15s | that interval | every 30s |
| 30s / 60s | that interval | that interval |

Intervals under 30s are driven by the Gmail content script, because Chrome
floors `chrome.alarms` at 30 seconds. Either way a new message is normally
scored within a few seconds of arriving; the analysis itself runs seven lanes
with DNS and RDAP lookups, so allow a moment for the verdict to land.

Only mail arriving **after** you connect is scored — the cursor is baselined on
connect rather than back-filling your whole mailbox. To score mail that is
already there, pick a window (last 5 / 10 / 25 / 50) in the popup and press
**Scan**. That pages through the id list and analyses in batches of 10, so the
whole window is covered rather than just the first batch; 50 is the ceiling,
which keeps a backfill inside the 60/min analysis budget. Messages already
scored are skipped, so pressing it twice costs nothing.

## Where you see the result

- **Toolbar badge** — count of messages needing attention, coloured by the worst
  band. Opening the popup clears it.
- **Popup → Inbox risk** — band, score, confidence and the top contributing
  signals per message.
- **In Gmail** — a small band chip next to the subject in the list and the open
  conversation.

The chip is best-effort: Gmail's DOM is obfuscated and changes often, so
placement relies on `data-legacy-thread-id` / `data-thread-perm-id` and the
`tr.zA` / `h2.hP` containers. If a Gmail update breaks it the console logs
`[Mailtrace] no thread ids resolved` while mail is on screen — update the
selectors in `inbox-chip.js`. The badge and popup do not depend on the DOM.

## Local development

Popup → **Advanced ▾** → set the backend URL before signing in.
`http://localhost:3000` (Next.js) and `http://localhost:8000` (FastAPI) are
already in `host_permissions`.

The FastAPI surface has no auth on `/api/cases`, so any token works against it.
The Next.js surface requires a real login and rate-limits analysis to 60/min per
user — the scanner caps each pass at 10 messages and queues the rest to stay
under it.

## Limits worth being honest about

- **Gmail strips the sender's IP** for webmail-composed mail (Outlook.com too,
  since 2012). It is not recoverable, and the backend emits
  `provider_withholds_origin` instead of guessing.
- **A verdict is about the message, not the sender.** Geolocation in the report
  is a consistency check, never attribution.
- **The most damaging attacks authenticate correctly.** Thread hijacking from a
  compromised mailbox passes SPF, DKIM and DMARC by construction, so a Clean
  band on a well-authenticated message is not proof of safety. See
  `docs/THREAT-MODEL.md`.
- **Read receipts** have the usual pixel-tracking caveats — Gmail proxies and
  caches images, Apple Mail Privacy Protection pre-loads everything, and images
  are often off. Treat opened/not-opened as a signal and the count as
  approximate.

## Privacy

Connecting Gmail grants `gmail.readonly`, which cannot send, delete or modify
anything. New inbox messages are sent over HTTPS to the Mailtrace backend URL
you configured and stored against your Mailtrace account — nowhere else. Scored
results are cached locally (last 100 messages) and cleared with **Clear
history**. Revoke access from the popup's **Disconnect Gmail**, or from
[your Google account permissions](https://myaccount.google.com/permissions).

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 manifest, OAuth client, permissions |
| `background.js` | Service worker; owns both sessions and all network calls |
| `store.js` | Settings, bounded caches, retry queue, band presentation |
| `gmail.js` | OAuth consent + `profile` / `history.list` / `messages.get` |
| `scanner.js` | Poll → de-dupe → raw bytes → `POST /api/cases` → verdict |
| `onboarding.html/js` | Install-time setup and the Gmail permission prompt |
| `popup.html/js` | Inbox risk and read-receipt views |
| `content.js` | Read-receipt pixel injection on Send |
| `inbox-chip.js` | Band chips in the Gmail UI + the sub-30s poll tick |

## Notes for maintainers

- `chrome.identity.getAuthToken({ interactive: true })` is called from extension
  **pages**, not the worker, so the consent prompt stays attached to the click
  that asked for it. Chrome caches the token extension-wide, so the worker mints
  it silently afterwards.
- The Gmail history cursor only moves forward. A message whose analysis fails
  can never be re-found from `history.list`, so failures are parked in an
  explicit retry queue (`store.js`) rather than left "unseen". Transient
  failures (network, 429, 5xx) retry up to four times; 4xx is recorded as an
  error on the message.
- The cursor is deliberately **not** advanced while ids are deferred by the
  per-pass cap, which is what lets the next tick re-find them.
- No icons are bundled (Chrome shows a default). Drop `icon16/48/128.png` in and
  add an `icons` block to brand it.
