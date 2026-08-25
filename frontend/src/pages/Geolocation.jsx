import { useState, useEffect } from 'react'
import { Search, Copy, MapPin, Loader2, Info, History } from 'lucide-react'
import PageHead from '../components/PageHead.jsx'
import WorldMap from '../components/WorldMap.jsx'
import { api } from '../api.js'
import './geolocation.css'

const FLAG = (cc) => cc ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 127397 + c.charCodeAt(0))) : '🏳️'

export default function Geolocation() {
  const [ip, setIp] = useState('171.25.193.25')
  const [q, setQ] = useState('171.25.193.25')
  const [data, setData] = useState(null)
  const [err, setErr] = useState(null)
  const [busy, setBusy] = useState(false)

  function lookup(target) {
    setBusy(true); setErr(null)
    api.geo(target).then((d) => { setData(d); setQ(target) })
      .catch((e) => setErr(String(e.message || e))).finally(() => setBusy(false))
  }
  useEffect(() => { lookup('171.25.193.25') }, [])

  const rep = data?.reputation
  const abuse = rep?.abuse_confidence ?? 0
  const riskTone = abuse >= 70 ? 'crit' : abuse >= 35 ? 'med' : 'low'

  return (
    <div>
      <PageHead title="IP Geolocation" subtitle="Locate IP address and analyze geographical intelligence" />

      <div className="card geo-bar">
        <div className="geo-input-group">
          <div className="geo-field">
            <div className="dim" style={{ fontSize: '.75rem' }}>IP Address</div>
            <input value={ip} onChange={(e) => setIp(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && lookup(ip)} className="geo-ip" />
          </div>
          <button className="iconbtn" onClick={() => navigator.clipboard?.writeText(ip)}><Copy size={16} /></button>
          <div className="geo-field">
            <div className="dim" style={{ fontSize: '.75rem' }}>Risk Score</div>
            <div className="geo-risk">
              <span style={{ color: `var(--${riskTone})`, fontWeight: 700 }}>{rep?.risk || '—'} Risk</span>
              {rep && <span className={'badge ' + riskTone}>{abuse}/100</span>}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn" onClick={() => lookup(ip)} disabled={busy}>
            {busy ? <Loader2 size={16} className="spin" /> : <Search size={16} />} Lookup IP
          </button>
          <button className="btn ghost"><History size={16} /> History</button>
        </div>
      </div>

      {err && <div className="card err-banner" style={{ marginTop: 18 }}>Lookup failed: {err}</div>}

      <div className="geo-grid">
        <div className="card">
          <div className="geo-details">
            {[
              ['Country', data?.country ? `${FLAG(data.country)}  ${data.country}` : '—'],
              ['City', data?.city || '—'],
              ['Latitude', data?.latitude ?? '—'],
              ['Longitude', data?.longitude ?? '—'],
              ['ISP', data?.isp || '—'],
              ['Usage type', rep?.usage_type || (rep?.hosting ? 'Data center / hosting' : '—')],
              ['Origin type', rep?.tor_exit ? 'Tor exit node' : rep?.hosting ? 'Datacenter / hosting' : 'Network host'],
            ].map(([k, v]) => (
              <div className="geo-row" key={k}><span className="dim">{k}</span><span className="geo-val">{v}</span></div>
            ))}
          </div>
        </div>

        <div className="card geo-map-card">
          <WorldMap lat={data?.latitude} lon={data?.longitude}
            label={<><MapPin size={13} /> {data?.city ? `${data.city}, ` : ''}{data?.country || 'Locating…'}</>} />
        </div>
      </div>

      <div className="card" style={{ marginTop: 20 }}>
        <div className="card-title">IP Reputation</div>
        <div className="rep-grid">
          <div className="rep-abuse">
            <div className="dim" style={{ fontSize: '.85rem' }}>Abuse Confidence</div>
            <div style={{ color: `var(--${riskTone})`, fontSize: '1.6rem', fontWeight: 800 }}>{abuse}%</div>
            <div className="abuse-bar"><div style={{ width: `${abuse}%`, background: `var(--${riskTone})` }} /></div>
          </div>
          <RepCell label="Tor Exit Node" val={rep?.tor_exit} yes="Yes" no="No" danger={rep?.tor_exit} />
          <RepCell label="Hosting" val={rep?.hosting} yes="Yes" no="No" danger={rep?.hosting} />
          {rep?.total_reports != null
            ? <RepCell label="Abuse Reports" text={String(rep.total_reports)} danger={rep.total_reports >= 20} />
            : <RepCell label="VPN / Proxy" val={rep?.vpn_proxy} yes="Yes" no="No" danger={rep?.vpn_proxy} />}
          <RepCell label="Recent Abuse" text={rep?.recent_abuse} danger={rep?.recent_abuse === 'High'} />
        </div>
        <div className="rep-note"><Info size={15} />
          {rep?.source?.startsWith('AbuseIPDB') ? (
            <span>Live reputation from <b>AbuseIPDB</b> — crowd-sourced abuse reports, cached 6h.
              {rep.last_reported ? ` Last reported ${new Date(rep.last_reported).toLocaleDateString()}.` : ''}
              {' '}Coordinates from offline GeoLite2.</span>
          ) : (
            <span>Country, coordinates and Tor/VPN/datacenter flags are real (offline GeoLite2 + intel lists).
              Abuse-confidence is a <b>heuristic estimate</b> — add an <span className="mono">ABUSEIPDB_KEY</span> to <span className="mono">.env</span> for live crowd-sourced scores.</span>
          )}
        </div>
      </div>
    </div>
  )
}

function RepCell({ label, val, text, yes = 'Yes', no = 'No', danger }) {
  const display = text ?? (val ? yes : no)
  return (
    <div className="rep-cell">
      <div className="dim" style={{ fontSize: '.82rem' }}>{label}</div>
      <div style={{ fontSize: '1.05rem', fontWeight: 700, color: danger ? 'var(--crit)' : 'var(--text)' }}>{display}</div>
    </div>
  )
}
