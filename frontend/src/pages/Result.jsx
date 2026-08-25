import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { Download, FileSearch, Loader2, Anchor, Globe, Link2, Paperclip, AlertCircle, ArrowRight } from 'lucide-react'
import PageHead from '../components/PageHead.jsx'
import ScoreGauge from '../components/ScoreGauge.jsx'
import { api, bandInfo, classify } from '../api.js'
import './result.css'

const RECO = {
  reply_to_domain_mismatch: 'Block sender domain',
  payment_diversion_intent: 'Verify via known contact',
  credential_harvest_intent: 'Do not enter credentials',
  classifier_phishing_high: 'Do not click links',
  executive_impersonation: 'Verify sender identity',
  forged_received_hop: 'Reject — forged headers',
  private_ip_in_public_chain: 'Reject — injected hop',
  timestamp_regression: 'Reject — fabricated headers',
  brand_lookalike_domain: 'Block lookalike domain',
  domain_age_lt_30d: 'Treat as untrusted',
  domain_no_mx: 'Flag as suspicious',
  domain_does_not_resolve: 'Flag as suspicious',
  spf_fail_hard: 'Reject email',
  dmarc_fail_strict: 'Reject email',
  dkim_fail: 'Reject email',
  hidden_text_mismatch: 'Quarantine — hidden payload',
  fake_reply: 'Verify thread authenticity',
  origin_anonymized: 'Flag anonymized origin',
  campaign_infrastructure_reuse: 'Correlate with campaign',
}
const riskLevel = (p) => (p >= 18 ? ['High', 'crit'] : p >= 10 ? ['Medium', 'med'] : ['Low', 'low'])
const REP = { CRITICAL: 'Very Low', HIGH_RISK: 'Low', SUSPICIOUS: 'Moderate', BENIGN: 'Good' }

export default function Result() {
  const { id } = useParams()
  const [data, setData] = useState(null)
  const [err, setErr] = useState(null)

  useEffect(() => {
    let ok = true
    Promise.all([api.getCase(id), api.evidence(id), api.artifacts(id)])
      .then(([c, e, a]) => ok && setData({ c, ev: e.records, art: a }))
      .catch((x) => ok && setErr(String(x.message || x)))
    return () => { ok = false }
  }, [id])

  if (err) return <div><PageHead title="Analysis Result" back={{ to: '/analyze', label: 'Back' }} /><div className="card err-banner">Could not load case: {err}</div></div>
  if (!data) return <div><PageHead title="Analysis Result" /><div className="card center"><Loader2 className="spin" /> Loading…</div></div>

  const { c, ev, art } = data
  const v = c.verdict
  const info = bandInfo(v.band)
  const contribs = v.contributions || []
  const positive = contribs.filter((x) => x.points > 0)
  const chips = positive.slice(0, 6)
  const cls = classify(contribs)
  const conf = Math.round((v.confidence || 0) * 100)

  const trig = (sig) => ev.find((r) => r.signal === sig && r.status === 'TRIGGERED')
  const authFails = ['spf_fail_hard', 'dkim_fail', 'dmarc_fail_strict'].filter(trig)
  const authText = authFails.length
    ? `Failed (${authFails.map((s) => s.split('_')[0].toUpperCase()).join(', ')})`
    : 'Passed / not enforced'
  const ageEv = trig('domain_age_lt_30d')
  const domainAge = ageEv ? `${ageEv.detail?.age_days ?? '<30'} days` : '—'
  const headerIssues = ev.filter((r) => r.analyzer === 'M2' && r.status === 'TRIGGERED').length

  return (
    <div>
      <PageHead title="Analysis Result" back={{ to: '/analyze', label: 'Back to Analyze' }}
        actions={<Link to={`/forensic/${id}`} className="btn ghost"><FileSearch size={16} /> Forensic View</Link>} />

      <div className="res-top">
        <div className="card">
          <div className="card-title">Threat Score</div>
          <div className="score-row">
            <ScoreGauge score={v.score} band={v.band} />
            <div className="summary">
              <div className="card-title" style={{ marginBottom: 8 }}>Summary</div>
              <p className="muted" style={{ lineHeight: 1.55, margin: '0 0 14px' }}>{v.summary}</p>
              <div className="chips">
                {chips.map((x) => <span className={'badge ' + info.key} key={x.signal}>{x.label}</span>)}
              </div>
            </div>
          </div>
        </div>

        <div className="card classify">
          <div className="card-title">Classification</div>
          <div className={'class-ic ' + info.key}><Anchor size={30} /></div>
          <div className="class-name">{cls}</div>
          <div className="muted">Confidence: <b style={{ color: 'var(--low)' }}>{conf}%</b></div>
          <div className="class-meta">
            <div className="dim">Scorer</div><div>v{v.scorer_version}</div>
            <div className="dim">Verdict</div><div><span className={'badge ' + info.key}>{info.risk}</span></div>
          </div>
        </div>
      </div>

      <div className="res-mid">
        <InfoCard title="Sender Information" rows={[
          ['From', c.from_addr || '—'],
          ['Reply-To', c.reply_to || '—'],
          ['Return-Path', c.return_path || '—'],
          ['Domain age', domainAge],
          ['Reputation', <span style={{ color: v.band === 'BENIGN' ? 'var(--low)' : 'var(--crit)' }}>{REP[v.band]}</span>],
        ]} />
        <InfoCard title="Email Information" rows={[
          ['Subject', c.subject || '—'],
          ['Received', c.received_at ? new Date(c.received_at).toLocaleString() : '—'],
          ['Size', c.size_bytes ? `${(c.size_bytes / 1024).toFixed(1)} KB` : '—'],
          ['Format', c.body_format],
          ['Authentication', <span style={{ color: authFails.length ? 'var(--crit)' : 'var(--low)' }}>{authText}</span>],
        ]} />
        <div className="card">
          <div className="card-title">Threat Indicators</div>
          <div className="indicators">
            <Indicator icon={Globe} color="var(--info)" label="IP Addresses" n={art.ips.length} />
            <Indicator icon={Globe} color="var(--high)" label="Domains" n={art.domains.length} />
            <Indicator icon={Link2} color="var(--violet)" label="URLs" n={c.url_count} />
            <Indicator icon={Paperclip} color="var(--low)" label="Attachments" n={c.attachment_count} />
            <Indicator icon={AlertCircle} color="var(--info)" label="Header Issues" n={headerIssues} />
          </div>
        </div>
      </div>

      <div className="card">
        <div className="res-break-head">
          <div className="card-title" style={{ margin: 0 }}>AI Analysis Breakdown</div>
          <Link to={`/forensic/${id}`} className="violet-link" style={{ fontSize: '.85rem' }}>View Details →</Link>
        </div>
        <table className="breakdown">
          <thead><tr><th>Indicator</th><th>Details</th><th>Risk</th><th>Weight</th><th>Recommendation</th></tr></thead>
          <tbody>
            {positive.map((x) => {
              const [lvl, tone] = riskLevel(x.points)
              return (
                <tr key={x.signal}>
                  <td style={{ fontWeight: 600 }}>{x.label}</td>
                  <td className="muted">{(x.detail?.explanation || x.rationale || '').slice(0, 120)}</td>
                  <td><span className={'badge ' + tone}>{lvl}</span></td>
                  <td className="muted">+{x.points.toFixed(0)}</td>
                  <td className="muted">{RECO[x.signal] || 'Review manually'}</td>
                </tr>
              )
            })}
            {!positive.length && <tr><td colSpan="5" className="muted center">No threat indicators — message assessed clean.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function InfoCard({ title, rows }) {
  return (
    <div className="card">
      <div className="card-title">{title}</div>
      <div className="inforows">
        {rows.map(([k, val], i) => (
          <div className="inforow" key={i}><span className="dim">{k}</span><span className="infoval">{val}</span></div>
        ))}
      </div>
    </div>
  )
}

function Indicator({ icon: Icon, color, label, n }) {
  return (
    <div className="indi">
      <div className="indi-left"><Icon size={17} style={{ color }} /><span>{label}</span></div>
      <b>{n}</b>
    </div>
  )
}
