# Mailtrace — Gmail Read Receipts (Chrome extension)

Track when the Gmail messages **you send** get opened. On Send, the extension
drops an invisible 1×1 tracking pixel into the message body and registers it
against your Mailtrace account. When the recipient's mail client loads that
pixel, Mailtrace logs the open — and the popup shows opened / not-opened and an
open count per email.

The backend is the existing Mailtrace app (`/api/track*`), so tracked emails are
scoped to your Mailtrace login and stored with the rest of your account data.

## Install (load unpacked)

1. Open `chrome://extensions` in Chrome.
2. Toggle **Developer mode** (top-right) on.
3. Click **Load unpacked** and select this `extension/` folder.
4. Click the puzzle-piece icon → pin **Mailtrace — Gmail Read Receipts**.
5. Open the popup and **sign in** with your Mailtrace account
   (the same one you use at `mailtrace-zeta.vercel.app`).

## Use

- Compose a message in Gmail. A **● Tracking on** chip appears next to **Send** —
  click it to turn tracking off for that one message.
- Send as normal. The console logs `[Mailtrace] pixel injected …` when it works.
- Open the extension popup to see your tracked emails: **✓ Opened · N× · time**
  or **○ Not opened yet**. Hit **Refresh** to re-poll.

## Local development

Point the extension at a local backend: popup → **Advanced ▾** → set
`http://localhost:3000` before signing in. (`http://localhost:3000/*` is already
in `host_permissions`.)

## How reliable is "opened"?

Pixel tracking has limits that affect **every** tracker (Mailtrack, HubSpot,
Yesware included) — be honest with yourself about them:

- **Gmail proxies & caches images.** For Gmail→Gmail the open **count** often
  stays at 1 even after re-opens, and Gmail sometimes **pre-fetches** the pixel
  (a false "opened").
- **Apple Mail Privacy Protection** pre-loads all pixels → always "opened."
- **Images off** (common default) → a real open goes **undetected**.
- **Your own opens** of the sent copy can register too.

So treat **opened / not-opened** as a good signal and the **exact count** as
approximate.

## Privacy

The only Gmail data read is the **subject** and **recipient** of mail *you* send,
used to label your tracked list. The pixel records the open time, and the
requesting IP/user-agent (usually Google's image proxy, not the person). Only you
can see your tracked emails (owner-scoped by your Mailtrace token). Recipients are
not told there's a pixel — the same as any read-receipt tool; use it responsibly
and within the laws that apply to you.

## Notes for maintainers

- Gmail's DOM is obfuscated and changes often. Injection relies on selectors in
  `content.js` (`input[name="subjectbox"]`, `[aria-label="Message Body"]`, the
  Send button's `data-tooltip`/`aria-label` starting "Send"). If a Gmail update
  breaks it, the `[Mailtrace] pixel injected` log stops appearing on Send —
  update those selectors.
- No custom icons are bundled (Chrome shows a default). Drop `icon16/48/128.png`
  in the folder and add an `icons` block to `manifest.json` to brand it.
