import { useEffect, useState } from 'react'
import { Network, Fingerprint, Share2, GitBranch, Globe, Link2, Server, Hash, ExternalLink } from 'lucide-react'
import PageHead from '../components/PageHead.jsx'
import { api } from '../api.js'
import './threat.css'

const KIND_ICON = { ip: Server, url: Link2, urlreg: Globe, domain: Globe, hash: Hash }
const KIND_LABEL = { ip: 'Relay IP', url: 'URL host', urlreg: 'URL domain', domain: 'Domain', hash: 'File hash' }

export default function ThreatIntel() {
  const [camp, setCamp] = useState(null)
  const [graph, setGraph] = useState(null)

  useEffect(() => {
    api.campaigns().then(setCamp).catch(() => setCamp({ clusters: [] }))
    api.graphLive().then(setGraph).catch(() => setGraph({ cases: [], edges: [] }))
  }, [])

  // shared IOCs = indicators appearing across 2+ cases
  const share = {}
  for (const e of (graph?.edges || [])) {
    const k = `${e.kind}:${e.value}`
    ;(share[k] = share[k] || { kind: e.kind, value: e.value, cases: new Set() }).cases.add(e.case_id)
  }
  const iocs = Object.values(share).map((s) => ({ ...s, n: s.cases.size })).filter((s) => s.n >= 2).sort((a, b) => b.n - a.n)
  const clusters = camp?.clusters || []

  const cards = [
    { icon: Network, tone: 'crit', label: 'Active Campaigns', n: clusters.length },
    { icon: Fingerprint, tone: 'info', label: 'Tracked Indicators', n: Object.keys(share).length },
    { icon: Share2, tone: 'med', label: 'Shared IOCs', n: iocs.length },
    { icon: GitBranch, tone: 'low', label: 'Linked Cases', n: (graph?.cases || []).length },
  ]

  return (
    <div>
      <PageHead title="Threat Intelligence" subtitle="Campaign correlation and shared indicators of compromise"
        actions={<a className="btn ghost" href="/live" target="_blank" rel="noreferrer"><ExternalLink size={15} /> Live Graph</a>} />

      <div className="ti-cards">
        {cards.map(({ icon: Icon, tone, label, n }) => (
          <div className="ti-stat" key={label}>
            <div className={'stat-ic ' + tone}><Icon size={20} /></div>
            <div><div className="muted" style={{ fontSize: '.83rem' }}>{label}</div><div className="stat-n">{n}</div></div>
          </div>
        ))}
      </div>

      <div className="ti-grid">
        <div className="card">
          <div className="card-title">Detected Campaigns</div>
          {clusters.length ? (
            <div className="camp-list">
              {clusters.map((c, i) => (
                <div className="camp" key={c.cluster_id}>
                  <div className="camp-head">
                    <span className="camp-name">Campaign {String.fromCharCode(65 + i)}</span>
                    <span className="badge crit">{c.size} cases</span>
                    <span className="badge violet">cohesion {c.cohesion_score}</span>
                  </div>
                  <div className="camp-iocs">
                    {Object.entries(c.core_indicators || {}).flatMap(([kind, vals]) =>
                      (vals || []).slice(0, 4).map((v) => {
                        const Icon = KIND_ICON[kind] || Fingerprint
                        return <span className="ioc-pill" key={kind + v}><Icon size={12} /> {v}</span>
                      }))}
                  </div>
                </div>
              ))}
            </div>
          ) : <div className="muted center" style={{ padding: 26 }}>No multi-case campaigns yet. Analyze related emails to correlate.</div>}
        </div>

        <div className="card">
          <div className="card-title">Shared Infrastructure (IOCs)</div>
          {iocs.length ? (
            <table className="breakdown">
              <thead><tr><th>Type</th><th>Indicator</th><th>Cases</th></tr></thead>
              <tbody>
                {iocs.slice(0, 12).map((s) => {
                  const Icon = KIND_ICON[s.kind] || Fingerprint
                  return (
                    <tr key={s.kind + s.value}>
                      <td><span className="ioc-type"><Icon size={13} /> {KIND_LABEL[s.kind] || s.kind}</span></td>
                      <td className="mono">{s.value}</td>
                      <td><span className="badge crit">{s.n}</span></td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          ) : <div className="muted center" style={{ padding: 26 }}>No shared indicators across cases yet.</div>}
        </div>
      </div>
    </div>
  )
}
