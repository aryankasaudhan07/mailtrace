import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { FileText, Download, FileSearch, ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react'
import PageHead from '../components/PageHead.jsx'
import { api, bandInfo, timeAgo } from '../api.js'
import './reports.css'

export default function Reports() {
  const nav = useNavigate()
  const [items, setItems] = useState(null)
  const [stats, setStats] = useState(null)

  useEffect(() => {
    api.listCases().then((r) => setItems(r.items || [])).catch(() => setItems([]))
    api.stats().then(setStats).catch(() => {})
  }, [])

  const b = stats?.buckets || {}
  const cards = [
    { icon: FileText, tone: 'info', label: 'Total Reports', n: stats ? stats.total : '—' },
    { icon: ShieldAlert, tone: 'crit', label: 'Critical', n: stats ? (b.critical || 0) : '—' },
    { icon: ShieldAlert, tone: 'high', label: 'High Risk', n: stats ? (b.high || 0) : '—' },
    { icon: AlertTriangle, tone: 'med', label: 'Suspicious', n: stats ? (b.medium || 0) : '—' },
    { icon: ShieldCheck, tone: 'low', label: 'Clean', n: stats ? (b.low || 0) : '—' },
  ]

  return (
    <div>
      <PageHead title="Reports" subtitle="Forensic reports generated from analyzed messages" />

      <div className="rep-cards">
        {cards.map(({ icon: Icon, tone, label, n }) => (
          <div className="rep-stat" key={label}>
            <div className={'stat-ic ' + tone}><Icon size={20} /></div>
            <div><div className="muted" style={{ fontSize: '.83rem' }}>{label}</div><div className="stat-n">{n}</div></div>
          </div>
        ))}
      </div>

      <div className="card">
        <div className="card-title">Generated Reports</div>
        {items === null ? <div className="muted center" style={{ padding: 30 }}>Loading…</div> :
          items.length ? (
            <div className="rep-list">
              {items.map((r) => {
                const info = bandInfo(r.band)
                return (
                  <div className="rep-row" key={r.case_id}>
                    <div className={'rep-ic ' + info.key}><FileText size={19} /></div>
                    <div className="rep-body">
                      <div className="rep-title">{r.subject}</div>
                      <div className="muted" style={{ fontSize: '.8rem' }}>{r.from_addr} · {timeAgo(r.analyzed_at)}</div>
                    </div>
                    <span className={'badge ' + info.key}>{info.label} · {r.score}</span>
                    <div className="rep-actions">
                      <a className="btn ghost sm" href={`/api/cases/${r.case_id}/report`} target="_blank" rel="noreferrer"><Download size={14} /> Report</a>
                      <button className="btn ghost sm" onClick={() => nav(`/forensic/${r.case_id}`)}><FileSearch size={14} /> Forensic</button>
                    </div>
                  </div>
                )
              })}
            </div>
          ) : <div className="muted center" style={{ padding: 30 }}>No reports yet — <a className="violet-link" onClick={() => nav('/analyze')}>analyze an email →</a></div>}
      </div>
    </div>
  )
}
