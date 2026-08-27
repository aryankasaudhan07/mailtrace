import { useEffect, useState } from 'react'
import { User, SlidersHorizontal, Server, Shield, Check } from 'lucide-react'
import PageHead from '../components/PageHead.jsx'
import { useAuth } from '../auth.jsx'
import { api } from '../api.js'
import './settings.css'

const DEFAULT_PREFS = { realtime: true, aiContent: true, autoQuarantine: false }

function Toggle({ on, onClick }) {
  return <button className={'toggle-sw' + (on ? ' on' : '')} onClick={onClick}><span /></button>
}

export default function Settings() {
  const { user, updateProfile } = useAuth() || {}
  const [health, setHealth] = useState(null)
  const [prefs, setPrefs] = useState(() => {
    try { return { ...DEFAULT_PREFS, ...JSON.parse(localStorage.getItem('mt_prefs') || '{}') } } catch { return { ...DEFAULT_PREFS } }
  })
  const set = (k) => () => setPrefs((p) => {
    const next = { ...p, [k]: !p[k] }
    try { localStorage.setItem('mt_prefs', JSON.stringify(next)) } catch { /* storage unavailable */ }
    return next
  })

  // profile edit
  const [editing, setEditing] = useState(false)
  const [name, setName] = useState('')
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState(null)
  const startEdit = () => { setName(user?.name || ''); setMsg(null); setEditing(true) }
  const saveProfile = async () => {
    setSaving(true); setMsg(null)
    try {
      await updateProfile(name.trim())
      setEditing(false); setMsg('Profile updated.')
    } catch (e) {
      setMsg(String(e.message || e))
    } finally { setSaving(false) }
  }

  useEffect(() => { api.health().then(setHealth).catch(() => {}) }, [])

  return (
    <div>
      <PageHead title="Settings" subtitle="Manage your account, detection preferences and system" />

      <div className="set-grid">
        <div className="card">
          <div className="card-title"><User size={16} style={{ verticalAlign: -3, marginRight: 7 }} />Profile</div>
          <div className="prof">
            <div className="avatar lg"><User size={30} /></div>
            <div><div className="prof-name">{user?.name || 'Admin User'}</div>
              <div className="muted">{user?.email || 'admin@mailtrace.io'}</div>
              <span className="badge violet" style={{ marginTop: 6 }}>{user?.role || 'Administrator'}</span></div>
          </div>
          {editing ? (
            <div className="prof-edit">
              <label className="pref-t" htmlFor="dn">Display name</label>
              <input id="dn" className="prof-input" value={name} onChange={(e) => setName(e.target.value)}
                placeholder="Your name" autoFocus />
              <div className="inforows" style={{ marginTop: 14 }}>
                <div className="inforow"><span className="dim">Email</span><span className="infoval">{user?.email || '—'}</span> </div>
                <div className="inforow"><span className="dim">Role</span><span className="infoval">{user?.role || '—'}</span></div>
              </div>
              <div className="prof-actions">
                <button className="btn" disabled={saving || !name.trim()} onClick={saveProfile} style={{ opacity: saving || !name.trim() ? 0.6 : 1 }}>
                  <Check size={15} /> {saving ? 'Saving…' : 'Save'}
                </button>
                <button className="btn ghost" onClick={() => setEditing(false)} disabled={saving}>Cancel</button>
              </div>
            </div>
          ) : (
            <>
              <div className="inforows" style={{ marginTop: 18 }}>
                <div className="inforow"><span className="dim">Display name</span><span className="infoval">{user?.name || '—'}</span></div>
                <div className="inforow"><span className="dim">Email</span><span className="infoval">{user?.email || '—'}</span></div>
                <div className="inforow"><span className="dim">Role</span><span className="infoval">{user?.role || '—'}</span></div>
              </div>
              <button className="btn ghost" style={{ marginTop: 16 }} onClick={startEdit}>Edit profile</button>
            </>
          )}
          {msg && <div className="set-saved" style={{ color: msg.includes('updated') ? 'var(--low)' : 'var(--crit)' }}><Check size={14} /> {msg}</div>}
        </div>

        <div className="card">
          <div className="card-title"><SlidersHorizontal size={16} style={{ verticalAlign: -3, marginRight: 7 }} />Detection Preferences</div>
          {[
            ['realtime', 'Real-time analysis', 'Score every inbound message on arrival'],
            ['aiContent', 'AI content analysis (M4)', 'Use the NLP classifier for social-engineering intent'],
            ['autoQuarantine', 'Auto-quarantine CRITICAL', 'Hold messages scoring 75+ for review'],
          ].map(([k, t, d]) => (
            <div className="pref" key={k}>
              <div><div className="pref-t">{t}</div><div className="muted" style={{ fontSize: '.8rem' }}>{d}</div></div>
              <Toggle on={prefs[k]} onClick={set(k)} />
            </div>
          ))}
          <div className="set-saved"><Check size={14} /> Preferences saved automatically</div>
        </div>

        <div className="card">
          <div className="card-title"><Server size={16} style={{ verticalAlign: -3, marginRight: 7 }} />System</div>
          <div className="inforows">
            <div className="inforow"><span className="dim">Status</span><span className="infoval" style={{ color: 'var(--low)' }}>{health?.status === 'ok' ? 'Operational' : '—'}</span></div>
            <div className="inforow"><span className="dim">Scorer version</span><span className="infoval">v{health?.scorer_version || '—'}</span></div>
            <div className="inforow"><span className="dim">Signals defined</span><span className="infoval">{health?.signals_defined ?? '—'}</span></div>
            <div className="inforow"><span className="dim">Fixture mode</span><span className="infoval">{health ? String(health.fixture_mode) : '—'}</span></div>
          </div>
          <div className="card-title" style={{ marginTop: 20, fontSize: '.9rem' }}>Analyzers registered</div>
          <div className="anlist">
            {(health?.analyzers_registered || []).map((a) => (
              <span className="anpill" key={a}><Shield size={12} /> {a}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
