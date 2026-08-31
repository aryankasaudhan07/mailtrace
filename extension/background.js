/**
 * Background service worker.
 *
 * Owns the Mailtrace session (base URL + bearer token in chrome.storage) and
 * makes every backend call, because content scripts on mail.google.com are
 * subject to Gmail's strict page CSP and can't fetch our API directly. The
 * content script and popup talk to us over chrome.runtime messages.
 */

const DEFAULTS = { base: 'https://mailtrace-zeta.vercel.app', token: '', email: '', trackingOn: true };

async function state() {
  const s = await chrome.storage.local.get(DEFAULTS);
  return { ...DEFAULTS, ...s };
}

async function api(path, { method = 'GET', body, auth = true } = {}) {
  const { base, token } = await state();
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

const handlers = {
  async getState() {
    const s = await state();
    return { base: s.base, email: s.email, loggedIn: Boolean(s.token), trackingOn: s.trackingOn };
  },

  async setBase({ base }) {
    await chrome.storage.local.set({ base: (base || DEFAULTS.base).trim() });
    return { ok: true };
  },

  async setTracking({ on }) {
    await chrome.storage.local.set({ trackingOn: Boolean(on) });
    return { ok: true, trackingOn: Boolean(on) };
  },

  async login({ email, password }) {
    const r = await api('/api/auth/login', { method: 'POST', auth: false, body: { email, password } });
    if (!r.ok) return { ok: false, error: r.data?.detail || `login failed (${r.status})` };
    await chrome.storage.local.set({ token: r.data.token, email: r.data.user?.email || email });
    return { ok: true, email: r.data.user?.email || email };
  },

  async logout() {
    await chrome.storage.local.set({ token: '', email: '' });
    return { ok: true };
  },

  // Called by the content script right after it injects the pixel on Send.
  async register({ id, subject, to }) {
    const { token } = await state();
    if (!token) return { ok: false, error: 'not logged in' };
    const r = await api('/api/track', { method: 'POST', body: { id, subject, to } });
    return { ok: r.ok, error: r.ok ? undefined : (r.data?.detail || `register failed (${r.status})`) };
  },

  async list() {
    const { token } = await state();
    if (!token) return { ok: false, error: 'not logged in' };
    const r = await api('/api/track');
    if (!r.ok) return { ok: false, error: r.data?.detail || `list failed (${r.status})` };
    return { ok: true, tracks: r.data.tracks || [] };
  },
};

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  const fn = handlers[msg?.type];
  if (!fn) { sendResponse({ ok: false, error: 'unknown message' }); return false; }
  fn(msg).then(sendResponse).catch((e) => sendResponse({ ok: false, error: String(e?.message || e) }));
  return true; // async response
});
