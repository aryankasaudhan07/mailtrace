import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { MapPin, Info, Mail, Loader2 } from 'lucide-react'
import PageHead from '../components/PageHead.jsx'
import WorldMap from '../components/WorldMap.jsx'
import { api, bandInfo, timeAgo } from '../api.js'
import './geolocation.css'

const FLAG = (cc) => cc ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 127397 + c.charCodeAt(0))) : '🏳️'

export default function Geolocation() {
  const nav = useNavigate()
  const [cases, setCases] = useState(null)
  const [sel, setSel] = useState(null)
  const [data, setData] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)

  useEffect(() => {
    api.listCases(50)
      .then((r) => {
        const items = r.items || []
        setCases(items)
        const first = items.find((c) => c.origin_ip)
        if (first) pick(first)
      })
      .catch(() => setCases([]))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function pick(c) {
    setSel(c); setErr(null); setData(null)
    if (!c.origin_ip) return
    setBusy(true)
    api.geo(c.origin_ip).then(setData).catch((e) => setErr(String(e.message || e))).finally(() => setBusy(false))
  }

  const rep = data?.reputation
  const abuse = rep?.abuse_confidence ?? 0
  const riskTone = abuse >= 70 ? 'crit' : abuse >= 35 ? 'med' : 'low'

  if (cases === null) {
    return <div><PageHead title="IP Geolocation" subtitle="Origin location of analyzed messages" />
      <div className="card center" style={{ padding: 40 }}><Loader2 className="spin" /> Loading…</div></div>
  }
  if (!cases.length) {
    return <div><PageHead title="IP Geolocation" subtitle="Origin location of analyzed messages" />
      <div className="card center" style={{ padding: 40 }}>No analyses yet — <a className="violet-link" onClick={() => nav('/analyze')}>analyze an email</a> to trace its origin.</div></div>
  }

  return (
    <div>
      <PageHead title="IP Geolocation" subtitle="Origin location of analyzed messages" />

      {sel && (
        <div className="card geo-selbar">
          <div className="geo-sel-main">
            <div className={'geo-sel-ic ' + bandInfo(sel.band).key}><Mail size={18} /></div>
            <div style={{ minWidth: 0 }}>
              <div className="geo-sel-subj">{sel.subject}</div>
              <div className="dim geo-sel-sub">Authenticated origin <b className="mono">{sel.origin_ip || '—'}</b> · {timeAgo(sel.analyzed_at)}</div>
            </div>
          </div>
          <span className={'badge ' + bandInfo(sel.band).key}>{bandInfo(sel.band).label}</span>
        </div>
      )}

      {err && <div className="card err-banner" style={{ marginTop: 18 }}>Lookup failed: {err}</div>}

      <div className="geo-grid">
        <div className="card">
          {busy ? <div className="center" style={{ padding: 24 }}><Loader2 className="spin" /> Locating…</div>
            : !sel?.origin_ip ? <div className="muted center" style={{ padding: 24 }}>This message has no routable origin IP (webmail provider strips it, or a private relay).</div>
              : !data?.country ? <div className="muted center" style={{ padding: 24 }}>Origin <span className="mono">{sel.origin_ip}</span> is a reserved / documentation range — not geolocatable.</div>
                : (
                  <div className="geo-details">
                    {[
                      ['Country', `${FLAG(data.country)}  ${data.country}`],
                      ['City', data.city || '—'],
                      ['Latitude', data.latitude ?? '—'],
                      ['Longitude', data.longitude ?? '—'],
                      ['ISP', data.isp || '—'],
                      ['Origin type', rep?.tor_exit ? 'Tor exit node' : rep?.hosting ? 'Datacenter / hosting' : 'Network host'],
                    ].map(([k, v]) => (
                      <div className="geo-row" key={k}><span className="dim">{k}</span><span className="geo-val">{v}</span></div>
                    ))}
                  </div>
                )}
        </div>

        <div className="card geo-map-card">
          <WorldMap lat={data?.latitude} lon={data?.longitude}
            label={<><MapPin size={13} /> {data?.city ? `${data.city}, ` : ''}{data?.country || 'No location'}</>} />
        </div>
      </div>

      {data?.country && (
        <div className="card" style={{ marginTop: 20 }}>
          <div className="card-title">IP Reputation</div>
          <div className="rep-grid">
            <div className="rep-abuse">
              <div className="dim" style={{ fontSize: '.85rem' }}>Abuse Confidence</div>
              <div style={{ color: `var(--${riskTone})`, fontSize: '1.6rem', fontWeight: 800 }}>{abuse}%</div>
              <div className="abuse-bar"><div style={{ width: `${abuse}%`, background: `var(--${riskTone})` }} /></div>
            </div>
            <RepCell label="Tor Exit Node" val={rep?.tor_exit} danger={rep?.tor_exit} />
            <RepCell label="Hosting / Datacenter" val={rep?.hosting} danger={rep?.hosting} />
            <RepCell label="VPN / Proxy" val={rep?.vpn_proxy} danger={rep?.vpn_proxy} />
            <RepCell label="Recent Abuse" text={rep?.recent_abuse} danger={rep?.recent_abuse === 'High'} />
          </div>
          <div className="rep-note"><Info size={15} />
            <span>Location via <b>{data?.geo_source || 'ip-api.com'}</b>. Reputation: {rep?.source}.</span>
          </div>
        </div>
      )}

      <div className="card" style={{ marginTop: 20 }}>
        <div className="card-title">Analyzed messages</div>
        <div className="geo-hist">
          {cases.map((c) => {
            const info = bandInfo(c.band)
            return (
              <button key={c.case_id} className={'geo-hist-row' + (sel?.case_id === c.case_id ? ' on' : '')} onClick={() => pick(c)}>
                <div className={'geo-hist-ic ' + info.key}><Mail size={15} /></div>
                <div className="geo-hist-main">
                  <div className="geo-hist-subj">{c.subject}</div>
                  <div className="dim mono geo-hist-ip">{c.origin_ip || 'no routable origin'}</div>
                </div>
                <span className={'badge ' + info.key}>{info.label}</span>
                <span className="dim geo-hist-time">{timeAgo(c.analyzed_at)}</span>
              </button>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function RepCell({ label, val, text, danger }) {
  const display = text ?? (val ? 'Yes' : 'No')
  return (
    <div className="rep-cell">
      <div className="dim" style={{ fontSize: '.82rem' }}>{label}</div>
      <div style={{ fontSize: '1.05rem', fontWeight: 700, color: danger ? 'var(--crit)' : 'var(--text)' }}>{display}</div>
    </div>
  )
}
