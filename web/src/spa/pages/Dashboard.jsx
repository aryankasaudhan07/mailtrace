import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import {
  Mail, ShieldAlert, AlertTriangle, ShieldCheck, Anchor, Bug, Inbox,
  Crosshair, MoreHorizontal, Circle,
} from 'lucide-react'
import PageHead from '../components/PageHead.jsx'
import { api, bandInfo } from '../api.js'
import './dashboard.css'

const TYPE_ICON = { Phishing: Anchor, BEC: Anchor, Malware: Bug, Injection: Bug, Spoofing: Crosshair, Spam: Inbox, Anonymized: Crosshair, Campaign: Crosshair, Suspicious: MoreHorizontal, Clean: ShieldCheck }
const TT_TONES = ['crit', 'high', 'med', 'violet', 'info']
const timeAgo = (iso) => {
  const s = Math.max(0, (Date.now() - new Date(iso)) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} hr ago`
  return `${Math.floor(s / 86400)} d ago`
}

export default function Dashboard() {
  const nav = useNavigate()
  const [s, setS] = useState(null)
  const [health, setHealth] = useState(null)

  useEffect(() => {
    api.stats().then(setS).catch(() => setS({ total: 0, buckets: {}, threat_types: [], trend: [], recent: [] }))
    api.health().then(setHealth).catch(() => {})
  }, [])

  if (!s) return <div><PageHead title="Dashboard" /><div className="card">Loading…</div></div>

  const b = s.buckets || {}
  const crit = b.critical || 0, high = b.high || 0, med = b.medium || 0, low = b.low || 0
  const donut = [
    { name: 'Critical', value: crit, color: 'var(--crit)' },
    { name: 'High Risk', value: high, color: 'var(--high)' },
    { name: 'Suspicious', value: med, color: 'var(--med)' },
    { name: 'Clean', value: low, color: 'var(--low)' },
  ]
  const pct = (n) => (s.total ? Math.round((n / s.total) * 100) : 0)
  const typeTotal = s.threat_types.reduce((a, [, n]) => a + n, 0) || 1

  const stats = [
    { icon: Mail, tone: 'info', label: 'Total Analyses', n: s.total },
    { icon: ShieldAlert, tone: 'crit', label: 'Critical', n: crit },
    { icon: AlertTriangle, tone: 'high', label: 'High Risk', n: high },
    { icon: AlertTriangle, tone: 'med', label: 'Suspicious', n: med },
    { icon: ShieldCheck, tone: 'low', label: 'Clean', n: low },
  ]

  return (
    <div>
      <PageHead title="Dashboard" subtitle="Overview of your email threat intelligence" />

      <div className="stat-cards">
        {stats.map(({ icon: Icon, tone, label, n }) => (
          <div className="stat-card" key={label}>
            <div className={'stat-ic ' + tone}><Icon size={22} /></div>
            <div className="stat-meta"><div className="muted" style={{ fontSize: '.85rem' }}>{label}</div>
              <div className="stat-n">{n}</div>
              <div className="stat-live"><Circle size={7} fill="var(--low)" color="var(--low)" /> live</div></div>
            <Spark trend={s.trend} tone={tone} />
          </div>
        ))}
      </div>

      <div className="dash-grid">
        <div className="card">
          <div className="card-title">Threat Overview</div>
          <div className="donut-row">
            <div style={{ position: 'relative', width: 190, height: 190 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={s.total ? donut : [{ name: 'none', value: 1, color: 'var(--line-2)' }]}
                    dataKey="value" innerRadius={62} outerRadius={88} paddingAngle={2} stroke="none">
                    {(s.total ? donut : [{ color: 'var(--line-2)' }]).map((d, i) => <Cell key={i} fill={d.color} />)}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="donut-center"><div className="donut-total">{s.total}</div><div className="dim">Total</div></div>
            </div>
            <div className="donut-legend">
              {donut.map((d) => (
                <div className="leg" key={d.name}>
                  <span className="leg-dot" style={{ background: d.color }} />
                  <span className="leg-l">{d.name} ({pct(d.value)}%)</span>
                  <b>{d.value}</b>
                </div>
              ))}
            </div>
          </div>
          <div className="card-title" style={{ marginTop: 24 }}>Top Threat Types</div>
          <div className="ttypes">
            {s.threat_types.length ? s.threat_types.slice(0, 5).map(([t, n], i) => {
              const Icon = TYPE_ICON[t] || MoreHorizontal
              const share = Math.round((n / typeTotal) * 100)
              const tone = TT_TONES[i] || 'info'
              return (
                <div className="ttype" key={t}>
                  <div className={'ttype-ic ' + tone}><Icon size={15} /></div>
                  <div className="ttype-main">
                    <div className="ttype-head"><span className="ttype-t">{t}</span><span className="ttype-n">{n} · {share}%</span></div>
                    <div className="ttype-bar"><span className={'ttype-fill ' + tone} style={{ width: `${Math.max(4, share)}%` }} /></div>
                  </div>
                </div>
              )
            }) : <div className="muted">No threats detected yet.</div>}
          </div>
        </div>

        <div className="card">
          <div className="dash-head"><div className="card-title" style={{ margin: 0 }}>Recent Analyses</div>
            <a className="violet-link" style={{ fontSize: '.85rem' }} onClick={() => nav('/analyze')}>Analyze new →</a></div>
          <div className="recent">
            {s.recent.length ? s.recent.map((r) => {
              const info = bandInfo(r.band)
              return (
                <div className="recent-item" key={r.case_id} onClick={() => nav(`/result/${r.case_id}`)}>
                  <div className={'recent-ic ' + info.key}><Mail size={17} /></div>
                  <div className="recent-body"><div className="recent-s">{r.subject}</div>
                    <div className="dim recent-sub">Score {r.score} · {info.label}</div></div>
                  <span className={'badge ' + info.key}>{info.label}</span>
                  <span className="dim" style={{ fontSize: '.78rem', minWidth: 62, textAlign: 'right' }}>{timeAgo(r.analyzed_at)}</span>
                </div>
              )
            }) : <div className="muted center" style={{ padding: 30 }}>No analyses yet — <a className="violet-link" onClick={() => nav('/analyze')}>analyze an email</a>.</div>}
          </div>
        </div>
      </div>

      <div className="dash-grid2">
        <div className="card">
          <div className="card-title">Threat Trend (7 days)</div>
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={s.trend} margin={{ left: -20, right: 10, top: 8 }}>
              <CartesianGrid stroke="var(--line)" vertical={false} />
              <XAxis dataKey="day" tick={{ fill: 'var(--text-3)', fontSize: 11 }} tickFormatter={(d) => d.slice(5)} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'var(--text-3)', fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip contentStyle={{ background: 'var(--raised)', border: '1px solid var(--line-2)', borderRadius: 10, fontSize: 12 }} />
              <Line type="monotone" dataKey="critical" stroke="var(--crit)" strokeWidth={2} dot={{ r: 3 }} name="Critical" />
              <Line type="monotone" dataKey="high" stroke="var(--high)" strokeWidth={2} dot={{ r: 3 }} name="High Risk" />
              <Line type="monotone" dataKey="medium" stroke="var(--med)" strokeWidth={2} dot={{ r: 3 }} name="Suspicious" />
              <Line type="monotone" dataKey="low" stroke="var(--low)" strokeWidth={2} dot={{ r: 3 }} name="Clean" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div className="card-title">System Status</div>
          <div className="sysrows">
            {[['Email Analyzer', true], ['Threat Intelligence DB', true], ['Geolocation Service', true],
              ['Report Generator', true], ['AI Detection Engine (M4)', true]].map(([name]) => (
              <div className="sysrow" key={name}><span>{name}</span>
                <span className="sysup"><Circle size={7} fill="var(--low)" color="var(--low)" /> Online</span></div>
            ))}
          </div>
          {health && <div className="dim" style={{ fontSize: '.78rem', marginTop: 14 }}>
            {health.analyzers_registered?.length} analyzers · scorer v{health.scorer_version} · {health.signals_defined} signals
          </div>}
        </div>
      </div>
    </div>
  )
}

function Spark({ trend, tone }) {
  const key = tone === 'crit' ? 'critical' : tone === 'high' ? 'high' : tone === 'med' ? 'medium' : tone === 'low' ? 'low' : 'critical'
  const color = tone === 'crit' ? 'var(--crit)' : tone === 'high' ? 'var(--high)' : tone === 'med' ? 'var(--med)' : tone === 'low' ? 'var(--low)' : 'var(--info)'
  const data = (trend || []).map((d) => ({ v: tone === 'info' ? d.critical + d.high + d.medium + d.low : d[key] }))
  return (
    <div style={{ width: 74, height: 40 }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}><Line type="monotone" dataKey="v" stroke={color} strokeWidth={2} dot={false} /></LineChart>
      </ResponsiveContainer>
    </div>
  )
}
