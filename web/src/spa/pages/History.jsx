import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Search, Mail, Paperclip, ChevronRight } from 'lucide-react'
import PageHead from '../components/PageHead.jsx'
import { api, bandInfo, timeAgo } from '../api.js'
import './history.css'

const FILTERS = ['All', 'CRITICAL', 'HIGH_RISK', 'SUSPICIOUS', 'BENIGN']

export default function History() {
  const nav = useNavigate()
  const [params] = useSearchParams()
  const [items, setItems] = useState(null)
  const [q, setQ] = useState(params.get('q') || '')
  const [f, setF] = useState('All')

  // keep the search box in sync when the topbar search navigates here with ?q=
  useEffect(() => { setQ(params.get('q') || '') }, [params])

  useEffect(() => { api.listCases().then((r) => setItems(r.items || [])).catch(() => setItems([])) }, [])

  const rows = (items || []).filter((r) =>
    (f === 'All' || r.band === f) &&
    (!q || (r.subject || '').toLowerCase().includes(q.toLowerCase()) || (r.from_addr || '').toLowerCase().includes(q.toLowerCase())))

  return (
    <div>
      <PageHead title="Analysis History" subtitle="Every message analyzed on this platform" />

      <div className="card">
        <div className="hist-bar">
          <div className="search"><Search size={16} />
            <input placeholder="Search subject or sender…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
          <div className="filters">
            {FILTERS.map((x) => (
              <button key={x} className={'chip' + (f === x ? ' on' : '')} onClick={() => setF(x)}>
                {x === 'All' ? 'All' : bandInfo(x).label}
              </button>
            ))}
          </div>
        </div>

        {items === null ? <div className="muted center" style={{ padding: 30 }}>Loading…</div> : (
          <div className="tscroll"><table className="dtable hist-table">
            <thead><tr><th>Message</th><th>Sender</th><th>Score</th><th>Verdict</th><th>IOCs</th><th>Analyzed</th><th /></tr></thead>
            <tbody>
              {rows.map((r) => {
                const info = bandInfo(r.band)
                return (
                  <tr key={r.case_id} className="click" onClick={() => nav(`/result/${r.case_id}`)}>
                    <td><div className="hcell"><div className={'hicon ' + info.key}><Mail size={15} /></div>
                      <span className="hsubj">{r.subject}</span></div></td>
                    <td className="muted">{r.from_addr || '—'}</td>
                    <td><b style={{ color: `var(--${info.key === 'benign' ? 'benign' : info.key})` }}>{r.score}</b></td>
                    <td><span className={'badge ' + info.key}>{info.label}</span></td>
                    <td className="muted">{(r.urls || 0) + (r.attachments || 0)}{r.attachments ? <Paperclip size={12} style={{ marginLeft: 5, verticalAlign: 'middle' }} /> : null}</td>
                    <td className="muted">{timeAgo(r.analyzed_at)}</td>
                    <td><ChevronRight size={16} className="dim" /></td>
                  </tr>
                )
              })}
              {!rows.length && <tr><td colSpan="7" className="muted center" style={{ padding: 30 }}>No matching analyses. <a className="violet-link" onClick={() => nav('/analyze')}>Analyze an email →</a></td></tr>}
            </tbody>
          </table></div>
        )}
      </div>
    </div>
  )
}
