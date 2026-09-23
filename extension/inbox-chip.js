/**
 * Gmail inbox risk chips + the fast poll tick.
 *
 * Two jobs, both only meaningful while a Gmail tab is open:
 *
 *  1. Tick the background worker on the user's chosen interval. chrome.alarms is
 *     floored at 30s, so anything faster than that has to be driven from a page.
 *  2. Paint the verdict the backend already produced next to the matching
 *     conversation.
 *
 * Nothing here decides anything. It asks the worker "do you have a verdict for
 * these threads" and renders the answer.
 *
 * Gmail's DOM is obfuscated and changes often, so chip placement is best-effort
 * and the popup stays the reliable surface. The tell that placement broke is
 * "[Mailtrace] no thread ids resolved" in the console while mail is on screen.
 */
(() => {
  const LOG = '[Mailtrace]';
  const MARK = 'data-mt-band';
  let pollSeconds = 15;
  let timer = null;

  // --- tick ---------------------------------------------------------------

  function restartTimer() {
    if (timer) clearInterval(timer);
    timer = setInterval(() => {
      // Errors here are expected while the worker is asleep or reloading.
      try {
        chrome.runtime.sendMessage({ type: 'tick' }, () => void chrome.runtime.lastError);
      } catch {
        /* extension context invalidated (reload) — the next sweep re-arms */
      }
    }, Math.max(3, pollSeconds) * 1000);
  }

  chrome.storage.local.get({ pollSeconds }).then((s) => {
    pollSeconds = s.pollSeconds || pollSeconds;
    restartTimer();
  });
  chrome.storage.onChanged.addListener((ch) => {
    if (ch.pollSeconds) { pollSeconds = ch.pollSeconds.newValue; restartTimer(); }
    if (ch.scored) sweep();
  });

  // --- thread id resolution ------------------------------------------------

  /**
   * Gmail exposes two ids. `data-legacy-thread-id` is the same hex id the Gmail
   * API returns as threadId. `data-thread-perm-id` is `thread-f:<decimal>` of
   * that same number, so it converts cleanly.
   */
  function threadIdsFrom(el) {
    const out = [];
    const legacy = el.getAttribute('data-legacy-thread-id');
    if (legacy) out.push(legacy);
    const perm = el.getAttribute('data-thread-perm-id');
    const m = perm && /thread-[a-z]:(\d+)/.exec(perm);
    if (m) {
      try { out.push(BigInt(m[1]).toString(16)); } catch { /* not a number we can convert */ }
    }
    return out;
  }

  // --- chip ---------------------------------------------------------------

  // Gmail ships a light and a dark theme, and the theme is a Gmail setting —
  // not the OS one — so prefers-color-scheme is the wrong signal. Sample the
  // actual page background and pick a palette by luminance.
  const PALETTE = {
    light: {
      CRITICAL:   { fg: '#b3261e', bg: '#fdecea', bd: '#f3c9c5' },
      HIGH_RISK:  { fg: '#a1500a', bg: '#fdf1e3', bd: '#f0d6b3' },
      SUSPICIOUS: { fg: '#87680a', bg: '#fbf5e1', bd: '#ecdfb3' },
      BENIGN:     { fg: '#0e7a57', bg: '#e9f6f0', bd: '#c2e3d5' },
      UNKNOWN:    { fg: '#5f5f5f', bg: '#f0f0f0', bd: '#dcdcdc' },
    },
    dark: {
      CRITICAL:   { fg: '#ff9c94', bg: 'rgba(255,86,74,.16)',  bd: 'rgba(255,86,74,.38)' },
      HIGH_RISK:  { fg: '#ffb877', bg: 'rgba(255,150,60,.16)', bd: 'rgba(255,150,60,.36)' },
      SUSPICIOUS: { fg: '#f0d47a', bg: 'rgba(230,190,60,.15)', bd: 'rgba(230,190,60,.34)' },
      BENIGN:     { fg: '#6fd6ab', bg: 'rgba(45,200,150,.15)', bd: 'rgba(45,200,150,.34)' },
      UNKNOWN:    { fg: '#b5b5b5', bg: 'rgba(255,255,255,.08)', bd: 'rgba(255,255,255,.18)' },
    },
  };

  function isDarkUi() {
    const probe = document.querySelector('div[role="main"]') || document.body;
    const bg = getComputedStyle(probe).backgroundColor || '';
    const m = bg.match(/\d+/g);
    if (!m) return false;
    const [r, g, b] = m.map(Number);
    // Rec. 601 luma; Gmail dark sits far below the midpoint.
    return (0.299 * r + 0.587 * g + 0.114 * b) < 128;
  }

  // One stylesheet beats re-writing cssText on every chip, and it gives the
  // chip a hover state without inline handlers.
  let styleInjected = false;
  function injectStyle() {
    if (styleInjected) return;
    styleInjected = true;
    const css = document.createElement('style');
    css.id = 'mt-chip-style';
    css.textContent = `
      .mt-risk-chip{display:inline-flex;align-items:center;gap:5px;margin-left:8px;padding:2px 8px;
        border-radius:11px;border:1px solid transparent;white-space:nowrap;vertical-align:middle;
        font:700 10px/1.7 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
        letter-spacing:.2px;cursor:default;transition:filter .12s}
      .mt-risk-chip:hover{filter:brightness(1.06)}
      .mt-risk-chip .mt-dot{width:6px;height:6px;border-radius:50%;background:currentColor;flex:none}
      .mt-risk-chip .mt-score{opacity:.72;font-weight:600}`;
    (document.head || document.documentElement).appendChild(css);
  }

  // Analyzer ids mean nothing to someone reading their inbox.
  const LANE_NAMES = {
    M2: 'header & relay', M3: 'authentication', M4: 'content',
    M5: 'network & location', M6: 'domain', M7: 'correlation', M8: 'sender history',
  };
  const humanLane = (id) => LANE_NAMES[id] || String(id).toLowerCase();

  function chipFor(v) {
    injectStyle();
    const chip = document.createElement('span');
    chip.className = 'mt-risk-chip';
    chip.setAttribute(MARK, v.band);

    const tone = (PALETTE[isDarkUi() ? 'dark' : 'light'])[v.band] || PALETTE.light.UNKNOWN;
    chip.style.color = tone.fg;
    chip.style.background = tone.bg;
    chip.style.borderColor = tone.bd;

    // Confidence rides along with the score deliberately: a score of 80 at 0.4
    // confidence and a score of 80 at 0.95 confidence are different states, and
    // the verdict contract requires the UI to show them differently. This chip
    // labels BENIGN as "Clean", so an unqualified one would be the strongest
    // safety claim in the product.
    const pct = v.confidence != null ? Math.round(v.confidence * 100) : null;
    const dot = document.createElement('span');
    dot.className = 'mt-dot';
    chip.appendChild(dot);
    chip.appendChild(document.createTextNode(v.style.label));
    if (v.score != null) {
      const sc = document.createElement('span');
      sc.className = 'mt-score';
      sc.textContent = `${v.score}${pct != null && pct < 100 ? ` · ${pct}%` : ''}`;
      chip.appendChild(sc);
    }

    const lines = [`Mailtrace: ${v.style.risk} · ${v.score ?? '-'}/100`];
    if (pct != null && pct < 100) lines.push(`${pct}% confident - some checks could not run`);
    if (v.lanesUnavailable?.length) lines.push(`Couldn't check: ${v.lanesUnavailable.map(humanLane).join(', ')}`);
    if (v.suppressedNegatives?.length) {
      lines.push('This mail passed its authentication checks, but that did not lower the score because signs of forgery were found.');
    }
    if (v.summary) lines.push('', v.summary);
    chip.title = lines.join('\n');
    return chip;
  }

  /** Where a chip should go for a given id-bearing element. */
  function anchorFor(el) {
    const row = el.closest('tr.zA');
    if (row) return row.querySelector('.y6 > span:first-child') || row.querySelector('.y6') || row.querySelector('.xT');
    const header = el.closest('.h7, .adn, .ads')?.querySelector('h2.hP');
    if (header) return header;
    return null;
  }

  function paint(el, v) {
    const anchor = anchorFor(el);
    if (!anchor) return false;
    const existing = anchor.parentElement?.querySelector(':scope > .mt-risk-chip');
    if (existing) {
      if (existing.getAttribute(MARK) === v.band) return true; // already correct
      existing.remove();
    }
    anchor.insertAdjacentElement('afterend', chipFor(v));
    return true;
  }

  // --- sweep --------------------------------------------------------------

  let sweeping = false;

  async function sweep() {
    if (sweeping) return;
    sweeping = true;
    try {
      const els = [...document.querySelectorAll('[data-legacy-thread-id],[data-thread-perm-id]')];
      if (!els.length) return;

      const byId = new Map();
      for (const el of els) for (const id of threadIdsFrom(el)) {
        if (!byId.has(id)) byId.set(id, []);
        byId.get(id).push(el);
      }
      if (!byId.size) { console.debug(LOG, 'no thread ids resolved'); return; }

      const reply = await new Promise((res) => {
        try {
          chrome.runtime.sendMessage({ type: 'verdictsFor', threadIds: [...byId.keys()] }, (r) => {
            void chrome.runtime.lastError;
            res(r);
          });
        } catch { res(null); }
      });
      if (!reply?.ok) return;

      for (const [id, v] of Object.entries(reply.verdicts || {})) {
        for (const el of byId.get(id) || []) paint(el, v);
      }
    } finally {
      sweeping = false;
    }
  }

  // Gmail re-renders constantly; debounce the observer so we sweep once per
  // settled batch of mutations rather than per mutation.
  let debounce = null;
  new MutationObserver(() => {
    clearTimeout(debounce);
    debounce = setTimeout(sweep, 350);
  }).observe(document.body, { childList: true, subtree: true });

  sweep();
  console.log(LOG, 'inbox risk chips ready');
})();
