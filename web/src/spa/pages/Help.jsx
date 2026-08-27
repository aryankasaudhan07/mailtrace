import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Rocket, ChevronDown, BookOpen } from 'lucide-react'
import PageHead from '../components/PageHead.jsx'
import './help.css'

const FAQ = [
  ['How is the threat score calculated?', 'Six analyzers each emit evidence (header forensics, SPF/DKIM/DMARC, NLP content, network, domain, and campaign correlation). A single explainable weight table combines them into a 0–100 score and a band. Every point is traceable in the AI Analysis Breakdown.'],
  ['Why did a legitimate-looking email score high?', 'The most damaging attacks authenticate correctly. The scorer never lets good authentication cancel evidence of deception — a valid signature reduces risk only on an otherwise clean message.'],
  ['What do the verdict bands mean?', 'CLEAN (1–25), SUSPICIOUS (26–50), HIGH RISK (51–75), CRITICAL (76–100). Confidence is separate and reflects how many analyzers ran.'],
  ['Is my email data stored?', 'In this demo, analyzed messages live in memory for the session. Evidence and audit logs are append-only by design; nothing is sent to third parties.'],
  ['What are IOCs and campaigns?', 'Indicators of Compromise are the IPs, domains, URLs and file hashes extracted from a message. When two cases share attacker infrastructure, they are correlated into a campaign under Threat Intelligence.'],
]

export default function Help() {
  const nav = useNavigate()
  const [open, setOpen] = useState(0)
  return (
    <div>
      <PageHead title="Help & Support" subtitle="Guides, answers and how the platform works" />

      <div className="help-grid">
        <div>
          <div className="card help-hero">
            <div className="help-ic"><Rocket size={22} /></div>
            <div><div className="card-title" style={{ margin: 0 }}>Quick start</div>
              <div className="muted" style={{ fontSize: '.88rem', marginTop: 4 }}>Upload a raw .eml on the Analyze page (or try a sample), then review the verdict and drill into the forensic view.</div></div>
            <button className="btn" onClick={() => nav('/analyze')}>Analyze an email</button>
          </div>

          <div className="card" style={{ marginTop: 20 }}>
            <div className="card-title">Frequently asked</div>
            {FAQ.map(([q, a], i) => (
              <div className={'faq' + (open === i ? ' open' : '')} key={i}>
                <button className="faq-q" onClick={() => setOpen(open === i ? -1 : i)}>
                  <span>{q}</span><ChevronDown size={17} className="faq-chev" />
                </button>
                {open === i && <div className="faq-a muted">{a}</div>}
              </div>
            ))}
          </div>
        </div>

        <div>
          <div className="card">
            <div className="card-title"><BookOpen size={16} style={{ verticalAlign: -3, marginRight: 7 }} />The analyzers</div>
            <div className="an-help">
              {[
                ['M2', 'Header & relay forensics', 'Forged hops, private IPs, reply-to diversion, fake replies, trust boundary'],
                ['M3', 'Authentication', 'Re-verifies SPF / DKIM / DMARC from raw bytes'],
                ['M4', 'Content intelligence', 'NLP detection of phishing, BEC and hidden-text injection'],
                ['M5', 'Network intelligence', 'Tor / VPN / datacenter origin, GeoLite2 geolocation'],
                ['M6', 'Domain intelligence', 'Domain age, DNS, homograph / lookalike detection'],
                ['M7', 'Campaign correlation', 'Links cases through shared attacker infrastructure'],
              ].map(([id, t, d]) => (
                <div className="an-help-row" key={id}>
                  <span className="an-badge">{id}</span>
                  <div><div style={{ fontWeight: 600, fontSize: '.88rem' }}>{t}</div><div className="muted" style={{ fontSize: '.8rem' }}>{d}</div></div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
