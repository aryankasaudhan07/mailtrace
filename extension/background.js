/**
 * Background service worker.
 *
 * Owns both sessions — the Mailtrace one (base URL + bearer token in
 * chrome.storage) and the Gmail OAuth grant — and makes every network call,
 * because content scripts on mail.google.com are subject to Gmail's strict page
 * CSP and can't fetch our API directly. The content script, popup and
 * onboarding page talk to us over chrome.runtime messages.
 *
 * Two things trigger an inbox scan:
 *   - a chrome.alarms tick, which keeps working with Gmail closed but is
 *     floored at 30s by Chrome; and
 *   - a "tick" message from the Gmail content script, which is what makes the
 *     sub-30s poll intervals real while the user actually has Gmail open.
 */

import { DEFAULTS, ackAll, bandStyle, clearScored, getScored, getState, setState } from './store.js';
import { disconnect, getToken, clientIdConfigured, isConnected } from './gmail.js';
import { analyzeSessionMessage, refreshBadge, scanOnce, scanRecent } from './scanner.js';

const ALARM = 'mt-inbox-scan';

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/**
 * Validate and canonicalise a backend URL, or null if it isn't usable.
 *
 * This is the destination for the full raw bytes of every scanned message and
 * for the Mailtrace bearer token, so plaintext is only tolerated on loopback.
 * host_permissions does not help here — it governs reading the response, not
 * whether the request body leaves the browser.
 */
function normalizeBase(raw) {
  let u;
  try {
    u = new URL(String(raw).trim());
  } catch {
    return null;
  }
  const loopback = u.protocol === 'http:' && LOOPBACK.has(u.hostname);
  if (u.protocol !== 'https:' && !loopback) return null;
  return u.origin + u.pathname.replace(/\/+$/, '');
}

async function api(path, { method = 'GET', body, auth = true } = {}) {
  const { base, token } = await getState();
  const headers = { 'content-type': 'application/json' };
  if (auth && token) headers.authorization = 'Bearer ' + token;
  const res = await fetch(base.replace(/\/$/, '') + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* pixel/no-body */ }
  return { ok: res.ok, status: res.status, data };
}

// ---------------------------------------------------------------------------
// Scan scheduling
// ---------------------------------------------------------------------------

async function rescheduleAlarm() {
  const { scanOn, pollSeconds } = await getState();
  await chrome.alarms.clear(ALARM);
  if (!scanOn) return;
  // Chrome floors alarm periods at 30s; the content-script tick covers anything
  // faster than that.
  const minutes = Math.max(0.5, pollSeconds / 60);
  chrome.alarms.create(ALARM, { periodInMinutes: minutes, delayInMinutes: minutes });
}

/**
 * Forward a request to the Gmail tab's content script.
 *
 * The session fetch has to happen on mail.google.com so it is same-origin and
 * carries the user's cookies — the worker cannot do it, and that is the whole
 * point of the approach.
 */
async function askGmailTab(message) {
  const tabs = await chrome.tabs.query({ url: 'https://mail.google.com/*' });
  if (!tabs.length) {
    return { ok: false, __noTab: true, error: 'Open Gmail in a tab first — session access runs on the Gmail page.' };
  }
  for (const tab of tabs) {
    try {
      const r = await chrome.tabs.sendMessage(tab.id, message);
      if (r) return r;
    } catch {
      // Tab exists but has no content script yet (still loading, or the
      // extension was reloaded without refreshing Gmail).
    }
  }
  return { ok: false, error: 'Gmail is open but not responding. Reload the Gmail tab and try again.' };
}

let lastTick = 0;

/** Content-script ticks are throttled so several open Gmail tabs don't pile up. */
async function onTick() {
  const { scanOn, pollSeconds } = await getState();
  if (!scanOn) return { ok: true, skipped: 'scanning off' };
  const gap = Math.max(2000, pollSeconds * 1000 * 0.8);
  if (Date.now() - lastTick < gap) return { ok: true, skipped: 'throttled' };
  lastTick = Date.now();
  return scanOnce();
}

chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === ALARM) scanOnce();
});

chrome.runtime.onInstalled.addListener(({ reason }) => {
  // Ask for Gmail access up front rather than silently sitting inert. The
  // consent screen itself needs a user gesture, so this page explains the ask
  // and provides the button.
  if (reason === 'install') {
    chrome.tabs.create({ url: chrome.runtime.getURL('onboarding.html') });
  }
  rescheduleAlarm();
  refreshBadge();
});

chrome.runtime.onStartup.addListener(() => {
  rescheduleAlarm();
  refreshBadge();
});

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

const handlers = {
  async getState() {
    const s = await getState();
    return {
      base: s.base,
      email: s.email,
      loggedIn: Boolean(s.token),
      trackingOn: s.trackingOn,
      scanOn: s.scanOn,
      pollSeconds: s.pollSeconds,
      gmailAddress: s.gmailAddress,
      gmailConnected: await isConnected(),
      clientIdConfigured: clientIdConfigured(),
      baselined: Boolean(s.historyId),
      lastScanAt: s.lastScanAt,
      lastError: s.lastError,
    };
  },

  async setBase({ base }) {
    const clean = normalizeBase(base || DEFAULTS.base);
    if (!clean) {
      return { ok: false, error: 'Backend URL must be https:// (or http:// on localhost).' };
    }
    await setState({ base: clean });
    return { ok: true, base: clean };
  },

  async setTracking({ on }) {
    await setState({ trackingOn: Boolean(on) });
    return { ok: true, trackingOn: Boolean(on) };
  },

  async login({ email, password }) {
    const r = await api('/api/auth/login', { method: 'POST', auth: false, body: { email, password } });
    if (!r.ok) return { ok: false, error: r.data?.detail || `login failed (${r.status})` };
    await setState({ token: r.data.token, email: r.data.user?.email || email });
    return { ok: true, email: r.data.user?.email || email };
  },

  async logout() {
    await setState({ token: '', email: '' });
    return { ok: true };
  },

  // --- Gmail ---------------------------------------------------------------

  /**
   * Turn scanning on once consent exists.
   *
   * Extension pages hold the user gesture, so they call getToken(interactive)
   * themselves and then call this. Separating the two keeps the consent prompt
   * attached to the click that asked for it.
   */
  async enableScanning() {
    // Baseline the cursor now so we score mail arriving from this point on
    // rather than back-filling the whole mailbox.
    await setState({ scanOn: true, historyId: '', lastError: '' });
    const first = await scanOnce();
    await rescheduleAlarm();
    const s = await getState();
    return { ok: true, gmailAddress: s.gmailAddress, first };
  },

  /** Popup fallback path: prompt for consent, then enable. */
  async gmailConnect() {
    try {
      await getToken({ interactive: true });
    } catch (e) {
      return { ok: false, error: String(e?.message || e), needsSetup: Boolean(e?.needsSetup) };
    }
    return handlers.enableScanning();
  },

  async gmailDisconnect() {
    await disconnect();
    await setState({ scanOn: false, historyId: '', gmailAddress: '' });
    await chrome.alarms.clear(ALARM);
    await refreshBadge();
    return { ok: true };
  },

  async setScan({ on }) {
    await setState({ scanOn: Boolean(on) });
    await rescheduleAlarm();
    if (on) scanOnce();
    return { ok: true, scanOn: Boolean(on) };
  },

  async setPollSeconds({ seconds }) {
    const allowed = [3, 5, 15, 30, 60];
    const pollSeconds = allowed.includes(Number(seconds)) ? Number(seconds) : DEFAULTS.pollSeconds;
    await setState({ pollSeconds });
    await rescheduleAlarm();
    return { ok: true, pollSeconds };
  },

  tick: onTick,
  // Explicit user action, so it runs even while the automatic scan is paused.
  scanNow: () => scanOnce({ force: true }),
  scanRecent: ({ count }) => scanRecent(Number(count) || 25),

  // --- experimental: no-OAuth session path ---------------------------------

  /**
   * Ask the Gmail tab whether it can read raw message source from the user's
   * own session. Returns a diagnostic, not a verdict.
   */
  async sessionProbe() {
    const r = await askGmailTab({ type: 'sessionProbe' });
    if (!r.ok && r.__noTab) return r;
    return r;
  },

  /** Fetch one message via the session and score it. */
  async sessionAnalyze({ decimal }) {
    const got = await askGmailTab({ type: 'sessionFetch', decimal });
    if (!got.ok) return got;
    return analyzeSessionMessage(got);
  },

  sessionList: () => askGmailTab({ type: 'sessionList' }),

  async scored() {
    return { ok: true, scored: await getScored() };
  },

  /**
   * The Gmail content script asks which visible threads already have a verdict.
   * Presentation comes from store.js so the content script holds no band
   * constants of its own.
   */
  async verdictsFor({ threadIds }) {
    const wanted = new Set(threadIds || []);
    const newest = new Map();
    for (const r of await getScored()) {
      if (!r.threadId || !wanted.has(r.threadId) || !r.band) continue;
      const prev = newest.get(r.threadId);
      if (!prev || prev.at < r.at) newest.set(r.threadId, r);
    }
    const verdicts = {};
    for (const [threadId, r] of newest) {
      verdicts[threadId] = {
        band: r.band,
        score: r.score,
        confidence: r.confidence,
        lanesUnavailable: r.lanesUnavailable || [],
        suppressedNegatives: r.suppressedNegatives || [],
        summary: r.summary,
        caseId: r.caseId,
        style: bandStyle(r.band),
      };
    }
    return { ok: true, verdicts };
  },

  async ack() {
    await ackAll();
    await refreshBadge();
    return { ok: true };
  },

  async clear() {
    await clearScored();
    await refreshBadge();
    return { ok: true };
  },

  // --- read receipts (unchanged) -------------------------------------------

  async register({ id, subject, to }) {
    const { token } = await getState();
    if (!token) return { ok: false, error: 'not logged in' };
    const r = await api('/api/track', { method: 'POST', body: { id, subject, to } });
    return { ok: r.ok, error: r.ok ? undefined : (r.data?.detail || `register failed (${r.status})`) };
  },

  async list() {
    const { token } = await getState();
    if (!token) return { ok: false, error: 'not logged in' };
    const r = await api('/api/track');
    if (!r.ok) return { ok: false, error: r.data?.detail || `list failed (${r.status})` };
    return { ok: true, tracks: r.data.tracks || [] };
  },
};

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  const fn = handlers[msg?.type];
  if (!fn) { sendResponse({ ok: false, error: 'unknown message' }); return false; }
  Promise.resolve(fn(msg))
    .then(sendResponse)
    .catch((e) => sendResponse({ ok: false, error: String(e?.message || e) }));
  return true; // async response
});
