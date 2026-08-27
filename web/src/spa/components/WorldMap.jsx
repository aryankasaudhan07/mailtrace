import { useMemo } from 'react'
import { geoNaturalEarth1, geoPath, geoGraticule10 } from 'd3-geo'
import { feature } from 'topojson-client'
import world from 'world-atlas/countries-110m.json'

// Real vector world map (bundled topojson) with a projected marker overlay.
export default function WorldMap({ lat, lon, label }) {
  const W = 820, H = 420
  const { paths, graticule, projection } = useMemo(() => {
    const proj = geoNaturalEarth1().fitExtent([[8, 8], [W - 8, H - 8]], { type: 'Sphere' })
    const path = geoPath(proj)
    const land = feature(world, world.objects.countries).features
    return { paths: land.map((f) => path(f)), graticule: path(geoGraticule10()), projection: proj }
  }, [])

  const pt = lat != null && lon != null ? projection([lon, lat]) : null

  return (
    <div className="worldmap">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
        <defs>
          <radialGradient id="glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#ff4d5e" stopOpacity="0.5" />
            <stop offset="100%" stopColor="#ff4d5e" stopOpacity="0" />
          </radialGradient>
        </defs>
        <path d={graticule} className="wm-grat" fill="none" strokeWidth="0.5" />
        {paths.map((d, i) => (
          <path key={i} d={d} className="wm-land" strokeWidth="0.4" />
        ))}
        {pt && (
          <g transform={`translate(${pt[0]},${pt[1]})`}>
            <circle r="34" fill="url(#glow)" />
            <circle r="5" fill="#ff4d5e" />
            <circle r="5" fill="none" stroke="#ff4d5e" strokeWidth="1.5">
              <animate attributeName="r" from="5" to="26" dur="2s" repeatCount="indefinite" />
              <animate attributeName="opacity" from="0.8" to="0" dur="2s" repeatCount="indefinite" />
            </circle>
          </g>
        )}
      </svg>
      {label && <div className="map-caption">{label}</div>}
    </div>
  )
}
