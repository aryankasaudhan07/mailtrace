/**
 * Gmail content script.
 *
 * On Send, it drops an invisible 1x1 tracking pixel into the message body and
 * asks the background worker to register it against your Mailtrace account.
 * Gmail's DOM is obfuscated and changes often, so selectors are defensive with
 * fallbacks; if a Gmail update breaks injection, the tell is the absence of the
 * "[Mailtrace] pixel injected" console line on Send.
 */
(() => {
  const LOG = '[Mailtrace]';
  let cfg = { base: 'https://mailtrace-zeta.vercel.app', trackingOn: true };

  chrome.storage.local.get(cfg).then((s) => { cfg = { ...cfg, ...s }; });
  chrome.storage.onChanged.addListener((ch) => {
    if (ch.base) cfg.base = ch.base.newValue;
    if (ch.trackingOn) cfg.trackingOn = ch.trackingOn.newValue;
  });

  const uuid = () =>
    (crypto.randomUUID && crypto.randomUUID()) ||
    'xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });

  // --- locate the compose context from an element inside/near it ------------
  function findComposeContext(fromEl) {
    const root = fromEl?.closest('[role="dialog"]') || document;
    const body =
      root.querySelector('[aria-label="Message Body"][contenteditable="true"]') ||
      root.querySelector('div[g_editable="true"][contenteditable="true"]') ||
      root.querySelector('div[contenteditable="true"][role="textbox"]') ||
      root.querySelector('div[contenteditable="true"]');
    if (!body) return null;
    const subject = root.querySelector('input[name="subjectbox"]')?.value || '';
    const emails = new Set();
    root.querySelectorAll('[data-hovercard-id],[email]').forEach((el) => {
      const v = el.getAttribute('data-hovercard-id') || el.getAttribute('email') || '';
      if (v.includes('@')) emails.add(v.trim());
    });
    if (!emails.size) {
      // fall back to whatever is typed in the To box
      const to = root.querySelector('input[aria-label*="To"], textarea[aria-label*="To"]');
      (to?.value || '').split(/[,;\s]+/).forEach((t) => { if (t.includes('@')) emails.add(t.trim()); });
    }
    return { root, body, subject, recipients: [...emails].join(', ') };
  }

  function trackingEnabledFor(root) {
    const override = root?.dataset?.mtTracking; // per-compose toggle
    if (override === 'off') return false;
    if (override === 'on') return true;
    return cfg.trackingOn;
  }

  // --- inject the pixel; returns the tracking id, or null -------------------
  function injectPixel(ctx) {
    if (!ctx || !ctx.body) return null;
    if (ctx.body.querySelector('img[data-mt]')) return null; // already tagged this draft
    const id = uuid();
    const img = document.createElement('img');
    img.src = `${cfg.base.replace(/\/$/, '')}/api/track/pixel/${id}.gif`;
    img.alt = '';
    img.width = 1;
    img.height = 1;
    img.setAttribute('data-mt', id);
    img.style.cssText = 'width:1px;height:1px;opacity:0;border:0;';
    ctx.body.appendChild(img);
    console.log(LOG, 'pixel injected', id, '->', ctx.recipients || '(no recipient parsed)');
    chrome.runtime.sendMessage({ type: 'register', id, subject: ctx.subject, to: ctx.recipients }, (r) => {
      if (chrome.runtime.lastError || !r?.ok) console.warn(LOG, 'register failed:', r?.error || chrome.runtime.lastError?.message);
    });
    return id;
  }

  function isSendButton(el) {
    if (!el || el.getAttribute?.('role') !== 'button') return false;
    const label = (el.getAttribute('data-tooltip') || el.getAttribute('aria-label') || '').trim();
    return /^Send\b/i.test(label) && !/schedule/i.test(label);
  }
  function sendButtonFrom(target) {
    let el = target;
    for (let i = 0; el && i < 6; i++, el = el.parentElement) if (isSendButton(el)) return el;
    return null;
  }

  function handleSend(target) {
    const btn = sendButtonFrom(target);
    if (!btn) return;
    const ctx = findComposeContext(btn);
    if (!ctx) { console.warn(LOG, 'compose body not found — Gmail layout may have changed'); return; }
    if (!trackingEnabledFor(ctx.root)) { console.log(LOG, 'tracking off for this message'); return; }
    injectPixel(ctx);
  }

  // mousedown fires before Gmail serializes+sends, so the pixel is in the DOM in time
  document.addEventListener('mousedown', (e) => handleSend(e.target), true);
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      const ctx = findComposeContext(e.target);
      if (ctx && trackingEnabledFor(ctx.root)) injectPixel(ctx);
    }
  }, true);

  // --- compose toolbar chip (tracking on/off) -------------------------------
  function addChip(sendBtn) {
    const bar = sendBtn.parentElement;
    if (!bar || bar.querySelector('.mt-chip')) return;
    const root = sendBtn.closest('[role="dialog"]') || document.body;
    const chip = document.createElement('div');
    chip.className = 'mt-chip';
    const paint = () => {
      const on = trackingEnabledFor(root);
      chip.textContent = on ? '● Tracking on' : '○ Tracking off';
      chip.style.cssText =
        'display:inline-flex;align-items:center;gap:6px;margin-left:10px;padding:6px 12px;border-radius:16px;' +
        'font:600 12px/1 Onest,system-ui,Arial,sans-serif;cursor:pointer;user-select:none;white-space:nowrap;' +
        (on ? 'color:#0e7a57;background:rgba(14,122,87,.12);' : 'color:#8a8375;background:rgba(0,0,0,.06);');
      chip.title = 'Mailtrace read-receipt tracking for this message';
    };
    chip.addEventListener('click', (e) => {
      e.preventDefault(); e.stopPropagation();
      root.dataset.mtTracking = trackingEnabledFor(root) ? 'off' : 'on';
      paint();
    });
    paint();
    bar.appendChild(chip);
  }

  const mo = new MutationObserver(() => {
    document.querySelectorAll('[role="button"]').forEach((b) => { if (isSendButton(b)) addChip(b); });
  });
  mo.observe(document.body, { childList: true, subtree: true });
  console.log(LOG, 'read-receipt content script ready');
})();
