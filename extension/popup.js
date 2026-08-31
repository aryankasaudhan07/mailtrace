/* Popup: Mailtrace login + a dashboard of your tracked emails. Talks to the
   background worker over chrome.runtime messages (it holds the token). */

const app = document.getElementById('app');
const send = (type, payload = {}) =>
  new Promise((res) => chrome.runtime.sendMessage({ type, ...payload }, (r) => res(r || { ok: false, error: 'no response' })));

const esc = (s) => (s || '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
function ago(iso) {
  if (!iso) return '';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

async function renderLogin(prefillBase) {
  const st = await send('getState');
  app.innerHTML = `
    <label>Email</label>
    <input id="email" type="email" placeholder="you@example.com" autocomplete="username" />
    <label>Password</label>
    <input id="password" type="password" placeholder="Your Mailtrace password" autocomplete="current-password" />
    <button class="btn" id="login">Sign in</button>
    <span class="adv" id="advToggle">Advanced ▾</span>
    <div id="adv" style="display:none">
      <label>Backend URL</label>
      <input id="base" type="text" value="${esc(prefillBase || st.base)}" />
    </div>
    <div id="err"></div>
    <hr class="d" />
    <div class="dim">Sign in with the same account you use at mailtrace-zeta.vercel.app. This connects the extension to your tracked emails.</div>
  `;
  document.getElementById('advToggle').onclick = () => {
    const a = document.getElementById('adv');
    a.style.display = a.style.display === 'none' ? 'block' : 'none';
  };
  document.getElementById('login').onclick = async () => {
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const base = document.getElementById('base').value.trim();
    const err = document.getElementById('err');
    err.innerHTML = '';
    if (!email || !password) { err.innerHTML = `<div class="err">Enter your email and password.</div>`; return; }
    await send('setBase', { base });
    const r = await send('login', { email, password });
    if (!r.ok) { err.innerHTML = `<div class="err">${esc(r.error)}</div>`; return; }
    renderDashboard();
  };
}

async function renderDashboard() {
  const st = await send('getState');
  if (!st.loggedIn) return renderLogin();
  app.innerHTML = `
    <div class="row">
      <div class="muted">Signed in as <b>${esc(st.email)}</b></div>
      <button class="btn sm ghost" id="logout">Log out</button>
    </div>
    <hr class="d" />
    <div class="row">
      <div class="sec-title">Track new emails by default</div>
      <label class="switch"><input type="checkbox" id="trackToggle" ${st.trackingOn ? 'checked' : ''}/><span class="slider"></span></label>
    </div>
    <hr class="d" />
    <div class="row"><div class="sec-title">Your tracked emails</div><button class="btn sm ghost" id="refresh">Refresh</button></div>
    <div class="list" id="list"><div class="empty">Loading…</div></div>
  `;
  document.getElementById('logout').onclick = async () => { await send('logout'); renderLogin(st.base); };
  document.getElementById('trackToggle').onchange = (e) => send('setTracking', { on: e.target.checked });
  document.getElementById('refresh').onclick = loadList;
  loadList();
}

async function loadList() {
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
        ? `<div class="stat open">✓ Opened${t.opens > 1 ? ` · ${t.opens}×` : ''} · ${esc(ago(t.last_open))}</div>`
        : `<div class="stat unopen">○ Not opened yet</div>`}
    </div>
  `).join('');
}

renderDashboard();
