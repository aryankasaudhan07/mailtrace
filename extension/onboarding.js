/**
 * Install-time setup: sign in to Mailtrace, then grant Gmail read access.
 *
 * getToken({ interactive: true }) is called from this page rather than from the
 * service worker so the consent prompt stays attached to the click that asked
 * for it. Chrome caches the resulting token extension-wide, so the worker can
 * mint it silently afterwards.
 */

import { getToken, clientIdConfigured } from './gmail.js';
import { BANDS } from './store.js';

const steps = document.getElementById('steps');
const send = (type, payload = {}) =>
  new Promise((res) => chrome.runtime.sendMessage({ type, ...payload }, (r) => res(r || { ok: false, error: 'no response' })));

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const bandChips = () =>
  ['BENIGN', 'SUSPICIOUS', 'HIGH_RISK', 'CRITICAL']
    .map((b) => {
      const s = BANDS[b];
      return `<span class="chip" style="color:${s.fg};background:${s.bg}"><span class="dot" style="background:${s.dot}"></span>${s.label}</span>`;
    })
    .join('');

async function render() {
  const st = await send('getState');
  steps.innerHTML = '';
  steps.appendChild(stepMailtrace(st));
  steps.appendChild(stepGmail(st));
  if (st.loggedIn && st.gmailConnected) steps.appendChild(stepDone(st));
}

// --- Step 1: Mailtrace account ---------------------------------------------

function stepMailtrace(st) {
  const el = document.createElement('div');
  el.className = 'card' + (st.loggedIn ? ' done' : '');

  if (st.loggedIn) {
    el.innerHTML = `
      <div class="step"><div class="num">✓</div><h2>Signed in to Mailtrace</h2></div>
      <p>Analysing as <b>${esc(st.email)}</b> against <code>${esc(st.base)}</code>.</p>
      <button class="btn ghost" id="signout">Use a different account</button>`;
    el.querySelector('#signout').onclick = async () => { await send('logout'); render(); };
    return el;
  }

  el.innerHTML = `
    <div class="step"><div class="num">1</div><h2>Sign in to Mailtrace</h2></div>
    <p>This is the account that runs the analysis and stores your cases &mdash; the
       same one you use on the Mailtrace web app.</p>
    <label for="email">Email</label>
    <input id="email" type="email" placeholder="you@example.com" autocomplete="username" />
    <label for="password">Password</label>
    <input id="password" type="password" placeholder="Your Mailtrace password" autocomplete="current-password" />
    <label for="base">Backend URL</label>
    <input id="base" type="text" value="${esc(st.base)}" />
    <div class="row" style="margin-top:14px"><button class="btn" id="login">Sign in</button></div>
    <div id="err"></div>`;

  const err = el.querySelector('#err');
  el.querySelector('#login').onclick = async (e) => {
    const email = el.querySelector('#email').value.trim();
    const password = el.querySelector('#password').value;
    const base = el.querySelector('#base').value.trim();
    err.innerHTML = '';
    if (!email || !password) { err.innerHTML = `<div class="err">Enter your email and password.</div>`; return; }
    e.target.disabled = true;
    e.target.textContent = 'Signing in…';
    const b = await send('setBase', { base });
    if (!b.ok) {
      err.innerHTML = `<div class="err">${esc(b.error)}</div>`;
      e.target.disabled = false;
      e.target.textContent = 'Sign in';
      return;
    }
    const r = await send('login', { email, password });
    if (!r.ok) {
      err.innerHTML = `<div class="err">${esc(r.error)}</div>`;
      e.target.disabled = false;
      e.target.textContent = 'Sign in';
      return;
    }
    render();
  };
  return el;
}

// --- Step 2: Gmail permission ----------------------------------------------

function stepGmail(st) {
  const el = document.createElement('div');
  el.className = 'card' + (st.gmailConnected ? ' done' : '');

  if (st.gmailConnected) {
    el.innerHTML = `
      <div class="step"><div class="num">✓</div><h2>Gmail connected</h2></div>
      <p>Reading new inbox mail for <b>${esc(st.gmailAddress || 'your mailbox')}</b>.</p>
      <button class="btn ghost" id="disconnect">Disconnect Gmail</button>`;
    el.querySelector('#disconnect').onclick = async (e) => {
      e.target.disabled = true;
      await send('gmailDisconnect');
      render();
    };
    return el;
  }

  if (!clientIdConfigured()) {
    el.innerHTML = `
      <div class="step"><div class="num">2</div><h2>Grant Gmail access</h2></div>
      <div class="err">
        This build has no Google OAuth client ID yet, so the permission prompt
        can't open. Create a <b>Chrome Extension</b> OAuth client for extension
        ID <code>${esc(chrome.runtime.id)}</code> and put it in
        <code>manifest.json</code> under <code>oauth2.client_id</code>.
        Full steps are in <code>extension/README.md</code>.
      </div>`;
    return el;
  }

  el.innerHTML = `
    <div class="step"><div class="num">2</div><h2>Grant Gmail access</h2></div>
    <p>Google will ask you to approve read-only access to your Gmail. Here is
       exactly what that is used for:</p>
    <ul class="grants">
      <li><span class="tick">✓</span><span><b>Read new inbox messages.</b> The full original message is needed
        because the analysis rebuilds the <code>Received:</code> delivery chain and re-checks
        the DKIM signature &mdash; neither survives Gmail's rendered view.</span></li>
      <li><span class="tick">✓</span><span><b>Send each message to your Mailtrace backend</b> for scoring, over HTTPS.</span></li>
      <li><span class="no">✗</span><span><b>No sending, deleting or modifying.</b> The scope granted is
        <code>gmail.readonly</code>, which cannot change your mailbox.</span></li>
      <li><span class="no">✗</span><span><b>No third parties.</b> Mail goes only to the backend URL you set in step 1.</span></li>
    </ul>
    <div class="row"><button class="btn" id="connect" ${st.loggedIn ? '' : 'disabled'}>Connect Gmail</button>
      ${st.loggedIn ? '' : '<span class="sub">Finish step 1 first</span>'}</div>
    <div id="err"></div>`;

  const err = el.querySelector('#err');
  el.querySelector('#connect').onclick = async (e) => {
    err.innerHTML = '';
    e.target.disabled = true;
    e.target.textContent = 'Waiting for Google…';
    try {
      await getToken({ interactive: true });
    } catch (ex) {
      err.innerHTML = `<div class="err">${esc(ex?.message || ex)}</div>`;
      e.target.disabled = false;
      e.target.textContent = 'Connect Gmail';
      return;
    }
    e.target.textContent = 'Starting first scan…';
    const r = await send('enableScanning');
    if (!r.ok) err.innerHTML = `<div class="err">${esc(r.error)}</div>`;
    render();
  };
  return el;
}

// --- Step 3: ready ----------------------------------------------------------

function stepDone(st) {
  const el = document.createElement('div');
  el.className = 'card';
  el.innerHTML = `
    <div class="step"><div class="num">✓</div><h2>You're set</h2></div>
    <p>New mail is scored automatically and labelled with one of four bands:</p>
    <div class="bands">${bandChips()}</div>
    <label for="poll" style="margin-top:18px">How often to check for new mail</label>
    <div class="row">
      <select id="poll">
        ${[3, 5, 15, 30, 60].map((s) => `<option value="${s}" ${st.pollSeconds === s ? 'selected' : ''}>every ${s} seconds</option>`).join('')}
      </select>
      <button class="btn ghost" id="recent">Score my recent inbox</button>
    </div>
    <p class="note" style="margin-top:12px">Intervals under 30 seconds apply while a Gmail
       tab is open; with Gmail closed Chrome checks every 30 seconds. Only mail that
       arrives from now on is scored &mdash; use the button above to try it on mail
       already in your inbox.</p>
    <div id="msg"></div>`;

  el.querySelector('#poll').onchange = (e) => send('setPollSeconds', { seconds: e.target.value });
  el.querySelector('#recent').onclick = async (e) => {
    const msg = el.querySelector('#msg');
    e.target.disabled = true;
    e.target.textContent = 'Scoring…';
    const r = await send('scanRecent', { count: 25 });
    if (!r.ok) {
      msg.innerHTML = `<div class="err">${esc(r.error)}</div>`;
    } else {
      const parts = [`Scored ${r.scored} of ${r.considered} message(s)`];
      if (r.skipped) parts.push(`${r.skipped} already scored`);
      if (r.failed) parts.push(`${r.failed} could not be analysed`);
      msg.innerHTML = `<div class="ok">${parts.join(' · ')}. Open the Mailtrace popup to see the results.</div>`;
    }
    e.target.disabled = false;
    e.target.textContent = 'Score my recent inbox';
  };
  return el;
}

render();
