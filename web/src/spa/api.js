// Thin client over the Mailtrace FastAPI backend (proxied at /api in dev).

const TOKEN_KEY = 'mt_token'
export const getToken = () => localStorage.getItem(TOKEN_KEY)
export const setToken = (t) => (t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY))

async function j(url, opts = {}) {
  const headers = { ...(opts.headers || {}) }
  const tok = getToken()
  if (tok) headers.Authorization = `Bearer ${tok}`
  const r = await fetch(url, { ...opts, headers })
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`
    try { const b = await r.json(); if (b.detail) msg = b.detail } catch { /* ignore */ }
    throw new Error(msg)
  }
  return r.json()
}

export const api = {
  // auth
  login: (email, password) => j('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) }),
  registerRequest: (email, password, name) => j('/api/auth/register/request', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password, name }) }),
  registerVerify: (email, otp) => j('/api/auth/register/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, otp }) }),
  resetRequest: (email) => j('/api/auth/reset/request', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }) }),
  resetVerify: (email, otp, password) => j('/api/auth/reset/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, otp, password }) }),
  me: () => j('/api/auth/me'),
  updateProfile: (name) => j('/api/auth/profile', { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) }),
  // data
  health: () => j('/api/health'),
  stats: () => j('/api/stats'),
  listCases: (limit = 200) => j(`/api/cases?limit=${limit}`),
  getCase: (id) => j(`/api/cases/${id}`),
  trace: (id) => j(`/api/cases/${id}/trace`),
  evidence: (id) => j(`/api/cases/${id}/evidence`),
  artifacts: (id) => j(`/api/cases/${id}/artifacts`),
  headers: (id) => j(`/api/cases/${id}/headers`),
  campaigns: () => j('/api/cases/graph/campaigns'),
  graphLive: () => j('/api/cases/graph/live'),
  graphEntities: (ids) => j('/api/cases/graph/entities' + (ids && ids.length ? '?cases=' + ids.join(',') : '')),
  geo: (ip) => j(`/api/geo?ip=${encodeURIComponent(ip)}`),
  analyze: (file) => {
    const fd = new FormData()
    fd.append('file', file)
    return j('/api/cases', { method: 'POST', body: fd })
  },
  // The PDF report route is owner-scoped and requires the Bearer token, so it
  // can't be a plain <a href> (a browser navigation sends no Authorization).
  // Fetch it as an authenticated blob and trigger a client-side download.
  downloadReport: async (id, subject) => {
    const tok = getToken()
    const r = await fetch(`/api/cases/${id}/report`, { headers: tok ? { Authorization: `Bearer ${tok}` } : {} })
    if (!r.ok) {
      let msg = `${r.status} ${r.statusText}`
      try { const b = await r.json(); if (b.detail) msg = b.detail } catch { /* ignore */ }
      throw new Error(msg)
    }
    const blob = await r.blob()
    const safe = (subject || 'case').replace(/[^a-z0-9]+/gi, '-').slice(0, 40).replace(/^-|-$/g, '') || 'case'
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `mailtrace-${safe}-${String(id).slice(0, 8)}.pdf`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  },
}

// ---- shared derivations used across pages ----

export const BANDS = {
  CRITICAL:   { key: 'crit',   label: 'Critical',  risk: 'CRITICAL' },
  HIGH_RISK:  { key: 'high',   label: 'High Risk', risk: 'HIGH RISK' },
  SUSPICIOUS: { key: 'med',    label: 'Suspicious', risk: 'MEDIUM RISK' },
  BENIGN:     { key: 'benign', label: 'Clean',     risk: 'LOW RISK' },
}
export const bandInfo = (band) => BANDS[band] || BANDS.SUSPICIOUS

const CLASS_BY_SIGNAL = {
  payment_diversion_intent: 'Business Email Compromise',
  credential_harvest_intent: 'Credential Phishing',
  classifier_phishing_high: 'Phishing',
  executive_impersonation: 'Executive Impersonation',
  brand_lookalike_domain: 'Brand Impersonation',
  hidden_text_mismatch: 'Prompt Injection',
  forged_received_hop: 'Header Forgery',
  fake_reply: 'Thread Hijack',
  origin_anonymized: 'Anonymized Origin',
  campaign_infrastructure_reuse: 'Known Campaign',
}
export function classify(contributions = []) {
  const pos = contributions.filter((c) => c.points > 0).sort((a, b) => b.points - a.points)
  for (const c of pos) if (CLASS_BY_SIGNAL[c.signal]) return CLASS_BY_SIGNAL[c.signal]
  return pos.length ? 'Suspicious Email' : 'Clean'
}

export const timeAgo = (iso) => {
  if (!iso) return '—'
  const s = Math.max(0, (Date.now() - new Date(iso)) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} hr ago`
  return `${Math.floor(s / 86400)} d ago`
}
