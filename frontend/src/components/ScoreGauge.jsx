import { bandInfo } from '../api.js'

// 270° arc gauge. score 0-100, color by band.
export default function ScoreGauge({ score = 0, band = 'SUSPICIOUS', size = 190 }) {
  const info = bandInfo(band)
  const color = `var(--${info.key === 'benign' ? 'benign' : info.key})`
  const r = size / 2 - 14
  const cx = size / 2, cy = size / 2
  const start = 135, sweep = 270
  const end = start + sweep * (score / 100)
  const pol = (a) => {
    const rad = (a - 90) * Math.PI / 180
    return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)]
  }
  const arc = (a0, a1) => {
    const [x0, y0] = pol(a0), [x1, y1] = pol(a1)
    const large = a1 - a0 > 180 ? 1 : 0
    return `M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1}`
  }
  return (
    <div style={{ position: 'relative', width: size, height: size }}>
      <svg width={size} height={size}>
        <path d={arc(start, start + sweep)} fill="none" stroke="var(--line-2)" strokeWidth="12" strokeLinecap="round" />
        {score > 0 && (
          <path d={arc(start, end)} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 6px ${color})` }} />
        )}
      </svg>
      <div style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', textAlign: 'center' }}>
        <div>
          <div style={{ fontSize: size * 0.28, fontWeight: 800, lineHeight: 1 }}>{score}</div>
          <div className="dim" style={{ fontSize: '.9rem', fontWeight: 600 }}>/100</div>
          <div style={{ color, fontWeight: 750, fontSize: '.8rem', letterSpacing: '.5px', marginTop: 6 }}>{info.risk}</div>
        </div>
      </div>
    </div>
  )
}
