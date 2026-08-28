import { useEffect, useState } from 'react'
import { Share2, Loader2 } from 'lucide-react'
import PageHead from '../components/PageHead.jsx'
import { api } from '../api.js'
import './graph.css'

export default function Graph() {
  const [g, setG] = useState(null)

  useEffect(() => {
    api.graphLive().then(setG).catch(() => setG({ cases: [], edges: [] }))
  }, [])

  const cases = g?.cases || []
  const edges = g?.edges || []
  const indicators = new Set(edges.map((e) => `${e.kind}:${e.value}`)).size

  return (
    <div>
      <PageHead title="Graph" subtitle="Relationship graph of cases and shared infrastructure" />

      <div className="graph-stub card">
        <div className="graph-ic"><Share2 size={30} /></div>
        <div className="graph-stub-title">Relationship graph</div>
        {g === null ? (
          <div className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Loader2 className="spin" size={16} /> Loading graph data…
          </div>
        ) : (
          <div className="muted graph-stub-text">
            {cases.length} case node{cases.length === 1 ? '' : 's'} · {indicators} indicator{indicators === 1 ? '' : 's'} · {edges.length} edge{edges.length === 1 ? '' : 's'} ready to visualise.
            <br />The visualisation is being built — tell me what it should show and how it should look.
          </div>
        )}
      </div>
    </div>
  )
}
