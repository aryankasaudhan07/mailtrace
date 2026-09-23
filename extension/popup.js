/* Popup: two views over one Mailtrace session.
   - "Inbox risk"    — the score and band for mail arriving in your inbox.
   - "Read receipts" — the pre-existing open-tracking list for mail you sent.
   The background worker holds both tokens; everything here goes over messages. */

import { bandStyle } from './store.js';

const app = document.getElementById('app');
const tabs = document.getElementById('tabs');
const headsub = document.getElementById('headsub');

const send = (type, payload = {}) =>
  new Promise((res) => chrome.runtime.sendMessage({ type, ...payload }, (r) => res(r || { ok: false, error: 'no response' })));

// Maps a band to the card's severity class.
const bandClass = (band) =>
  ({ CRITICAL: 'crit', HIGH_RISK: 'high', SUSPICIOUS: 'susp', BENIGN: 'ok' }[band] || '');

// Analyzer IDs and signal keys are internal names. Users see plain English.
const LANE_NAMES = {
  M2: 'header & relay', M3: 'authentication', M4: 'content', M5: 'network & location',
  M6: 'domain', M7: 'correlation', M8: 'sender history',
};
const humanLane = (id) => LANE_NAMES[id] || String(id).toLowerCase();
const humanSignal = (key) => String(key).replace(/_/g, ' ');

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function ago(ms) {
  if (!ms) return '';
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

let tab = 'inbox';

tabs.onclick = (e) => {
  const t = e.target.closest('.tab');
  if (!t) return;
  tab = t.dataset.tab;
  [...tabs.children].forEach((c) => c.classList.toggle('on', c === t));
  route();
};

async function route() {
  const st = await send('getState');
  // Only the inbox view owns a settings panel; hide the gear elsewhere so it
  // can never toggle a panel that isn't on screen.
  const gearEl = document.getElementById('gear');
  if (gearEl) { gearEl.style.display = 'none'; gearEl.classList.remove('on'); }
  if (!st.loggedIn) { tabs.style.display = 'none'; return renderLogin(st); }
  tabs.style.display = 'flex';
  headsub.textContent = st.email || 'Email threat intelligence';
  if (tab === 'sent') return renderReceipts(st);
  return renderInbox(st);
}

// --- sign in ---------------------------------------------------------------

async function renderLogin(st) {
  app.innerHTML = `
    <label>Email</label>
    <input id="email" type="email" placeholder="you@example.com" autocomplete="username" />
    <label>Password</label>
    <input id="password" type="password" placeholder="Your Mailtrace password" autocomplete="current-password" />
    <button class="btn" id="login">Sign in</button>
    <span class="adv" id="advToggle">Advanced ▾</span>
    <div id="adv" style="display:none">
      <label>Backend URL</label>
      <input id="base" type="text" value="${esc(st.base)}" />
    </div>
    <div id="err"></div>
    <hr class="d" />
    <div class="dim">Sign in with your Mailtrace account. This is the backend that
      analyses your mail and stores your cases.</div>`;

  document.getElementById('advToggle').onclick = () => {
    const a = document.getElementById('adv');
    a.style.display = a.style.display === 'none' ? 'block' : 'none';
  };
  document.getElementById('login').onclick = async (ev) => {
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const base = document.getElementById('base').value.trim();
    const err = document.getElementById('err');
    err.innerHTML = '';
    if (!email || !password) { err.innerHTML = `<div class="err">Enter your email and password.</div>`; return; }
    ev.target.disabled = true;
    const b = await send('setBase', { base });
    if (!b.ok) { err.innerHTML = `<div class="err">${esc(b.error)}</div>`; ev.target.disabled = false; return; }
    const r = await send('login', { email, password });
    if (!r.ok) { err.innerHTML = `<div class="err">${esc(r.error)}</div>`; ev.target.disabled = false; return; }
    route();
  };
}

// --- inbox risk ------------------------------------------------------------

async function renderInbox(st) {
  if (!st.gmailConnected) return renderConnectGmail(st);

  app.innerHTML = `
    <div class="summary" id="summary"></div>
    <div class="statusline">
      <span class="live ${st.scanOn ? '' : 'off'}"></span>
      <span id="last"></span>
      <span class="acct" title="${esc(st.gmailAddress || '')}">${esc(st.gmailAddress || 'inbox')}</span>
    </div>
    <div id="notice"></div>

    <div class="panel" id="settings" style="display:none">
      <div class="row">
        <div><div class="muted">Scan new mail</div><div class="dim">Score messages as they arrive</div></div>
        <label class="switch"><input type="checkbox" id="scanToggle" ${st.scanOn ? 'checked' : ''}/><span class="slider"></span></label>
      </div>
      <div class="row">
        <div class="muted">Check every</div>
        <select id="poll">
          ${[3, 5, 15, 30, 60].map((n) => `<option value="${n}" ${st.pollSeconds === n ? 'selected' : ''}>${n}s</option>`).join('')}
        </select>
      </div>
      <hr class="hr" />
      <div class="row">
        <span class="link" id="disconnect">Disconnect Gmail</span>
        <span class="link" id="probe">Run diagnostic</span>
        <span class="link danger" id="clear">Clear history</span>
      </div>
      <div id="probeOut"></div>
    </div>

    <div class="row" style="margin-bottom:8px">
      <span class="sec">Recent mail</span>
      <div style="display:flex;gap:6px;align-items:center">
        <select id="recentN" title="How many recent messages to score">
          ${[5, 10, 25, 50].map((n) => `<option value="${n}" ${n === 25 ? 'selected' : ''}>last ${n}</option>`).join('')}
        </select>
        <button class="btn sm ghost" id="recent">Scan</button>
        <button class="btn sm ghost" id="refresh">Refresh</button>
      </div>
    </div>
    <div class="list" id="list"><div class="empty">Loading…</div></div>`;

  // Settings live behind the gear so the results are what you see first.
  const gear = document.getElementById('gear');
  if (gear) {
    gear.style.display = '';
    gear.onclick = () => {
      const panel = document.getElementById('settings');
      const open = panel.style.display === 'none';
      panel.style.display = open ? '' : 'none';
      gear.classList.toggle('on', open);
    };
  }

  const last = document.getElementById('last');
  last.textContent = st.scanOn
    ? (st.lastScanAt ? `Watching · checked ${ago(st.lastScanAt)}` : 'Watching for new mail')
    : 'Paused';

  const notice = document.getElementById('notice');
  if (st.lastError) notice.innerHTML = `<div class="err">${esc(st.lastError)}</div>`;
  else if (!st.scanOn) notice.innerHTML = `<div class="warn">Scanning is paused — new mail won't be scored.</div>`;

  document.getElementById('scanToggle').onchange = async (e) => { await send('setScan', { on: e.target.checked }); route(); };
  document.getElementById('poll').onchange = (e) => send('setPollSeconds', { seconds: e.target.value });
  document.getElementById('refresh').onclick = async (e) => {
    e.target.disabled = true; e.target.textContent = 'Checking…';
    const r = await send('scanNow');
    // scanOnce returns some failures without persisting them to lastError, so a
    // plain re-render would make a failed check look like a successful one.
    if (!r.ok) {
      notice.innerHTML = `<div class="err">${esc(r.error)}</div>`;
      e.target.disabled = false;
      e.target.textContent = 'Refresh';
      await loadScored();
      return;
    }
    route();
  };
  document.getElementById('recent').onclick = async (e) => {
    const count = Number(document.getElementById('recentN').value);
    e.target.disabled = true; e.target.textContent = 'Scoring…';
    const r = await send('scanRecent', { count });
    if (!r.ok) {
      notice.innerHTML = `<div class="err">${esc(r.error)}</div>`;
      e.target.disabled = false;
      e.target.textContent = 'Scan';
      await loadScored();
      return;
    }
    route();
  };
  document.getElementById('disconnect').onclick = async () => { await send('gmailDisconnect'); route(); };
  // Clearing wipes every scored record with no undo, so require a second click.
  // A native confirm() can dismiss the popup itself, hence the inline pattern.
  const clearBtn = document.getElementById('clear');
  let clearArmed = false;
  clearBtn.onclick = async () => {
    if (!clearArmed) {
      clearArmed = true;
      clearBtn.textContent = 'Click again to clear';
      setTimeout(() => {
        if (!clearArmed) return;
        clearArmed = false;
        clearBtn.textContent = 'Clear history';
      }, 4000);
      return;
    }
    await send('clear');
    route();
  };
  document.getElementById('probe').onclick = () => runProbe();

  await loadScored();
  send('ack'); // opening the popup clears the toolbar badge
}

function renderConnectGmail(st) {
  const tick = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>`;
  app.innerHTML = `
    <div class="hero">
      <div class="ic">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
      <h2>Check your inbox for threats</h2>
      <p>Connect Gmail and Mailtrace will score incoming mail for phishing and impersonation — and tell you why.</p>
    </div>
    <ul class="trust">
      <li>${tick}<span><b>Read-only.</b> Mailtrace can never send, delete or change your mail.</span></li>
      <li>${tick}<span>Only messages it scores are analysed — nothing else is read or stored.</span></li>
      <li>${tick}<span>You can disconnect at any time, from this popup.</span></li>
    </ul>
    ${st.clientIdConfigured
      ? '<button class="btn" id="connect" style="margin-top:14px">Connect Gmail</button>'
      : `<div class="warn">This build has no Google client ID, so Gmail can't be connected yet.
           The setup page walks through creating one.</div>`}
    <div id="err"></div>
    <div class="dim" style="text-align:center;margin-top:10px">
      New here? <a href="#" id="openOnboarding">See how it works</a>
    </div>`;


  document.getElementById('openOnboarding').onclick = (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: chrome.runtime.getURL('onboarding.html') });
  };
  const btn = document.getElementById('connect');
  if (btn && st.clientIdConfigured) {
    btn.onclick = async (e) => {
      e.target.disabled = true;
      e.target.textContent = 'Waiting for Google…';
      const r = await send('gmailConnect');
      if (!r.ok) {
        document.getElementById('err').innerHTML = `<div class="err">${esc(r.error)}</div>`;
        e.target.disabled = false;
        e.target.textContent = 'Connect Gmail';
        return;
      }
      route();
    };
  }
}

/**
 * Experimental: report whether raw message source can be read from the user's
 * own Gmail session, with no OAuth. Prints a diagnostic rather than a verdict,
 * because the endpoints are undocumented and the answer varies by account.
 */
async function runProbe() {
  const out = document.getElementById('probeOut');
  if (!out) return;
  out.innerHTML = `<div class="warn">Probing the Gmail tab…</div>`;
  const r = await send('sessionProbe');

  if (!r.ok) {
    const tried = (r.attempts || []).map((a) => `${a.form}: ${a.note || a.status}`).join('<br/>');
    out.innerHTML = `<div class="err"><b>Session mode unavailable</b><br/>${esc(r.error)}
      ${r.ikFound === false ? '<br/>Session key (ik) not found on the page.' : ''}
      ${tried ? `<br/><br/><span class="dim">Tried:<br/>${tried}</span>` : ''}</div>`;
    return;
  }

  const good = r.dkimSafe;
  out.innerHTML = `
    <div class="${good ? 'warn' : 'err'}">
      <b>Session mode works${good ? '' : ' with a caveat'}</b><br/>
      Endpoint: <code>${esc(r.form)}</code><br/>
      Bytes: ${r.bytes} · line endings: ${r.crlf ? 'CRLF' : 'LF only'}<br/>
      Fidelity: ${esc(r.fidelity)}<br/>
      ${good
        ? 'Bytes look exact, so DKIM re-verification is trustworthy.'
        : 'Bytes were recovered from HTML or lost CRLF, so <b>DKIM results cannot be trusted</b> on this path — M3 could report a failure on correctly signed mail.'}
    </div>`;
}

async function loadScored() {
  const list = document.getElementById('list');
  if (!list) return;
  const r = await send('scored');
  const rows = (r.scored || []).filter((x) => x.band || x.error);

  // At-a-glance counts, so the popup answers "am I OK?" before any reading.
  const sum = document.getElementById('summary');
  if (sum) {
    // One box per band. Merging High Risk with Suspicious would hide a
    // distinction the scorer makes and the rest of the product shows.
    const n = (b) => rows.filter((x) => x.band === b).length;
    sum.innerHTML = [
      ['crit', 'CRITICAL', n('CRITICAL')],
      ['high', 'HIGH RISK', n('HIGH_RISK')],
      ['susp', 'SUSPICIOUS', n('SUSPICIOUS')],
      ['ok', 'CLEAN', n('BENIGN')],
    ].map(([cls, label, count]) =>
      `<div class="sbox ${cls}"><div class="n">${count}</div><div class="l">${label}</div></div>`).join('');
  }

  if (!rows.length) {
    list.innerHTML = `<div class="empty">Nothing scored yet.<br/>New mail is checked automatically — or press <b>Scan</b> to check your recent messages now.</div>`;
    return;
  }
  list.innerHTML = rows.map(row).join('');
}

function row(r) {
  if (r.error) {
    return `<div class="item">
      <div class="s">${esc(r.subject)}</div>
      <div class="from">${esc(r.error)}</div>
      <div class="meta"><span class="when">${esc(ago(r.at))}</span></div>
    </div>`;
  }
  const st = bandStyle(r.band);
  const cls = bandClass(r.band);
  const who = r.fromName ? `${r.fromName} · ${r.from}` : r.from;
  // Say why confidence is short and why passing authentication did not lower
  // the score — both are invisible otherwise, and both change how much to trust it.
  const notes = [];
  if (r.source === 'session' && !r.dkimTrustworthy) notes.push('Read from the Gmail page, so the signature check is less reliable');
  if (r.lanesUnavailable?.length) notes.push(`Couldn't check ${r.lanesUnavailable.map(humanLane).join(', ')}`);
  if (r.suppressedNegatives?.length) notes.push('This mail passed its authentication checks, but that did not lower the score because signs of forgery were found');
  return `<div class="item ${cls}">
    <div class="s">${esc(r.subject)}</div>
    <div class="from">${esc(who || 'unknown sender')}</div>
    <div class="meta">
      <span class="pill ${cls}"><span class="dot"></span>${esc(st.label)}</span>
      <span class="when">${r.score ?? '–'}/100${r.confidence != null && r.confidence < 1 ? ` · ${Math.round(r.confidence * 100)}% sure` : ''} · ${esc(ago(r.at))}</span>
    </div>
    ${r.top?.length ? `<div class="why">${esc(r.top.map(humanSignal).join(' · '))}</div>` : ''}
    ${notes.length ? `<div class="note">${esc(notes.join(' · '))}</div>` : ''}
  </div>`;
}

// --- read receipts (unchanged behaviour) -----------------------------------

async function renderReceipts(st) {
  app.innerHTML = `
    <div class="row">
      <div class="sec-title">Track new emails by default</div>
      <label class="switch"><input type="checkbox" id="trackToggle" ${st.trackingOn ? 'checked' : ''}/><span class="slider"></span></label>
    </div>
    <hr class="d" />
    <div class="row"><div class="sec-title">Your tracked emails</div><button class="btn sm ghost" id="refresh">Refresh</button></div>
    <div class="list" id="list"><div class="empty">Loading…</div></div>
    <hr class="d" />
    <div class="row"><div class="muted">Signed in as <b>${esc(st.email)}</b></div>
      <button class="btn sm ghost" id="logout">Log out</button></div>`;

  document.getElementById('trackToggle').onchange = (e) => send('setTracking', { on: e.target.checked });
  document.getElementById('refresh').onclick = loadTracks;
  document.getElementById('logout').onclick = async () => { await send('logout'); route(); };
  loadTracks();
}

async function loadTracks() {
  const list = document.getElementById('list');
  if (!list) return;
  list.innerHTML = `<div class="empty">Loading…</div>`;
  const r = await send('list');
  if (!r.ok) { list.innerHTML = `<div class="err">${esc(r.error)}</div>`; return; }
  if (!r.tracks.length) { list.innerHTML = `<div class="empty">No tracked emails yet.<br/>Send one from Gmail with tracking on.</div>`; return; }
  list.innerHTML = r.tracks.map((t) => `
    <div class="item">
      <div class="s">${esc(t.subject || '(no subject)')}</div>
      <div class="to">${esc(t.to || 'unknown recipient')}</div>
      ${t.opened
        ? `<div class="stat open">✓ Opened${t.opens > 1 ? ` · ${t.opens}×` : ''} · ${esc(agoIso(t.last_open))}</div>`
        : `<div class="stat unopen">○ Not opened yet</div>`}
    </div>`).join('');
}

const agoIso = (iso) => (iso ? ago(new Date(iso).getTime()) : '');

route();
