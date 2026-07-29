import type { Severity } from '../lib/types'
import { severityColor, severityLabel } from '../lib/severity'

interface Props {
  score: number
  severity: Severity
  size?: number
}

export function RiskGauge({ score, severity, size = 96 }: Props) {
  const color = severityColor[severity]
  const radius = (size - 10) / 2
  const circumference = 2 * Math.PI * radius
  const pct = Math.min(score / 150, 1) // 150 treated as practical ceiling for the arc
  const dash = circumference * pct

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--border-hairline)"
          strokeWidth="8"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference}`}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ filter: `drop-shadow(0 0 4px ${color})`, transition: 'stroke-dasharray 0.6s ease' }}
        />
        <text
          x="50%" y="47%"
          textAnchor="middle"
          className="mono"
          fontSize={size * 0.26}
          fontWeight={700}
          fill="var(--text-primary)"
        >
          {score}
        </text>
        <text
          x="50%" y="65%"
          textAnchor="middle"
          fontSize={size * 0.11}
          fill="var(--text-muted)"
        >
          risk score
        </text>
      </svg>
      <span
        style={{
          fontSize: 11,
          fontWeight: 600,
          textTransform: 'uppercase',
          letterSpacing: 0.8,
          color,
        }}
      >
        {severityLabel[severity]}
      </span>
    </div>
  )
}
