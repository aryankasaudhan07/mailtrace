/**
 * Session-based raw message fetch — the no-OAuth path. EXPERIMENTAL.
 *
 * Gmail's own "Show original" view serves the raw RFC 5322 message from
 * mail.google.com. This content script runs on that origin, so a plain fetch
 * carries the user's existing cookies and returns the same bytes without any
 * OAuth token, consent screen, restricted scope or Google verification.
 *
 * The trade-off is that none of this is a documented API:
 *
 *  - The URL shape and the `ik` session token are Gmail internals and can
 *    change without notice. Hence several candidate forms, tried in order.
 *  - "Show original" may return the message wrapped in HTML. Extracting it from
 *    HTML means unescaping entities and possibly losing CRLF line endings, and
 *    DKIM signatures are computed over exact bytes — so a body hash check on
 *    HTML-extracted text can fail on mail that is genuinely fine. That is worse
 *    than no DKIM result at all, so fidelity is measured and reported rather
 *    than assumed, and the caller decides what to trust.
 *
 * Nothing here parses or scores. It obtains bytes and describes them.
 */
(() => {
  const LOG = '[Mailtrace/session]';

  // --- session token ------------------------------------------------------

  /**
   * Gmail's per-session "inbox key", required by most internal endpoints.
   *
   * Content scripts run in an isolated world so page globals (GLOBALS, the
   * usual source) are unreachable — but inline script *text* is in the DOM and
   * readable, which is where these patterns look.
   */
  function findInboxKey() {
    const patterns = [/"ik":"([^"]+)"/, /GM_ID_KEY\s*=\s*'([^']+)'/, /,"([A-Za-z0-9_-]{10,})",\s*"ik"/];
    for (const el of document.querySelectorAll('script')) {
      const txt = el.textContent;
      if (!txt || txt.length < 20) continue;
      for (const re of patterns) {
        const m = re.exec(txt);
        if (m?.[1]) return m[1];
      }
    }
    // Last resort: whole-document sweep (slower, but survives markup changes).
    const m = /"ik":"([^"]+)"/.exec(document.documentElement.innerHTML);
    return m?.[1] || null;
  }

  /** The /mail/u/<n>/ account index of the current tab. */
  const userIndex = () => (/\/mail\/u\/(\d+)/.exec(location.pathname)?.[1] ?? '0');

  // --- message identity ---------------------------------------------------

  /**
   * Gmail exposes message ids two ways: `data-legacy-message-id` as hex, and
   * `data-message-id` as `#msg-f:<decimal>`. The internal endpoints want the
   * decimal form, so hex is converted.
   */
  function messageIdsFrom(el) {
    const out = [];
    const hex = el.getAttribute('data-legacy-message-id');
    if (hex && /^[0-9a-f]+$/i.test(hex)) {
      try { out.push({ decimal: BigInt('0x' + hex).toString(10), hex }); } catch { /* not convertible */ }
    }
    const dm = el.getAttribute('data-message-id');
    const m = dm && /msg-f:(\d+)/.exec(dm);
    if (m) out.push({ decimal: m[1], hex: null });
    return out;
  }

  /** Messages currently rendered, newest-looking last. */
  function visibleMessages() {
    const seen = new Map();
    for (const el of document.querySelectorAll('[data-legacy-message-id],[data-message-id]')) {
      for (const id of messageIdsFrom(el)) {
        if (!seen.has(id.decimal)) seen.set(id.decimal, { ...id, el });
      }
    }
    return [...seen.values()];
  }

  // --- candidate endpoints ------------------------------------------------

  function candidateUrls({ decimal, hex }, ik) {
    const u = userIndex();
    const base = `https://mail.google.com/mail/u/${u}/`;
    const urls = [];
    if (ik) {
      urls.push(`${base}?ui=2&ik=${encodeURIComponent(ik)}&view=om&permmsgid=msg-f:${decimal}`);
      if (hex) urls.push(`${base}?ui=2&ik=${encodeURIComponent(ik)}&view=om&th=${hex}`);
    }
    // Without ik as a fallback; frequently rejected, but cheap to try.
    urls.push(`${base}?view=om&permmsgid=msg-f:${decimal}`);
    return urls;
  }

  // --- response handling --------------------------------------------------

  const looksLikeMessage = (t) =>
    /^[A-Za-z][A-Za-z0-9-]*:\s/m.test(t) && /\r?\n\r?\n/.test(t) && /^(received|from|date|message-id):/im.test(t);

  function unescapeHtml(s) {
    const el = document.createElement('textarea');
    el.innerHTML = s;
    return el.value;
  }

  /**
   * Pull the message out of whatever came back.
   * Returns { text, fidelity } where fidelity is 'exact' for a raw body and
   * 'html-extracted' when it had to be recovered from markup.
   */
  function extractMessage(body, contentType) {
    const isHtml = /text\/html/i.test(contentType || '') || /^\s*<(!doctype|html)/i.test(body.slice(0, 200));
    if (!isHtml) return { text: body, fidelity: 'exact' };

    // "Show original" renders the source inside a <pre>.
    const pre = /<pre[^>]*>([\s\S]*?)<\/pre>/i.exec(body);
    if (pre) return { text: unescapeHtml(pre[1]), fidelity: 'html-extracted' };

    const div = /<div[^>]*class="[^"]*\bmessage\b[^"]*"[^>]*>([\s\S]*?)<\/div>/i.exec(body);
    if (div) return { text: unescapeHtml(div[1]), fidelity: 'html-extracted' };

    return { text: null, fidelity: null };
  }

  const toB64 = (text) => {
    // Latin-1 per byte: the message is already bytes, not Unicode text.
    const bytes = new TextEncoder().encode(text);
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  };

  /**
   * Fetch one message's source. Resolves with a report either way — it never
   * throws, so a caller can show the user why it failed.
   */
  async function fetchRaw(id) {
    const ik = findInboxKey();
    const attempts = [];

    for (const url of candidateUrls(id, ik)) {
      const form = /permmsgid/.test(url) ? (url.includes('ik=') ? 'ik+permmsgid' : 'permmsgid-only') : 'ik+th';
      try {
        const res = await fetch(url, { credentials: 'include', redirect: 'follow' });
        const contentType = res.headers.get('content-type') || '';
        if (!res.ok) { attempts.push({ form, status: res.status, note: 'HTTP error' }); continue; }

        const body = await res.text();
        // A redirect to the sign-in page returns 200 with a login document.
        if (/accounts\.google\.com|ServiceLogin/i.test(body.slice(0, 500))) {
          attempts.push({ form, status: res.status, note: 'redirected to sign-in' });
          continue;
        }

        const { text, fidelity } = extractMessage(body, contentType);
        if (!text || !looksLikeMessage(text)) {
          attempts.push({ form, status: res.status, contentType, note: 'response was not a message', preview: body.slice(0, 120) });
          continue;
        }

        const crlf = text.includes('\r\n');
        return {
          ok: true,
          form,
          contentType,
          fidelity,
          crlf,
          // CRLF is what DKIM body hashes are computed over. Without it M3 can
          // report a failure on mail that is actually correctly signed.
          dkimSafe: fidelity === 'exact' && crlf,
          bytes: text.length,
          b64: toB64(text),
          attempts,
        };
      } catch (e) {
        attempts.push({ form, note: String(e?.message || e) });
      }
    }
    return { ok: false, error: ik ? 'No endpoint returned a message.' : 'Could not find the Gmail session key (ik).', attempts };
  }

  // --- message surface ----------------------------------------------------

  const handlers = {
    /** Report what session access can and cannot do on this account. */
    async sessionProbe() {
      const ik = findInboxKey();
      const msgs = visibleMessages();
      if (!msgs.length) {
        return { ok: false, error: 'No messages visible on this page. Open the inbox or a conversation, then probe again.', ikFound: Boolean(ik) };
      }
      const r = await fetchRaw(msgs[msgs.length - 1]);
      return { ...r, ikFound: Boolean(ik), visible: msgs.length, userIndex: userIndex() };
    },

    /** Raw bytes for one message, or for the newest visible one. */
    async sessionFetch({ decimal }) {
      const msgs = visibleMessages();
      const target = decimal ? msgs.find((m) => m.decimal === decimal) : msgs[msgs.length - 1];
      if (!target) return { ok: false, error: 'That message is not on screen.' };
      const r = await fetchRaw(target);
      return { ...r, decimal: target.decimal };
    },

    async sessionList() {
      return { ok: true, messages: visibleMessages().map(({ decimal, hex }) => ({ decimal, hex })) };
    },
  };

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    const fn = handlers[msg?.type];
    if (!fn) return false; // not ours; another listener may handle it
    Promise.resolve(fn(msg))
      .then(sendResponse)
      .catch((e) => sendResponse({ ok: false, error: String(e?.message || e) }));
    return true;
  });

  console.log(LOG, 'session raw-fetch ready (experimental)');
})();
