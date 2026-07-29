import type { MitreTechnique, Severity } from '../lib/types'
import { severityColor } from '../lib/severity'

interface Props {
  techniques: MitreTechnique[]
  severity: Severity
}

/**
 * The signature visual for the incident detail view.
 *
 * A correlated incident *is* a chain of tactics -- that's the whole premise
 * of the correlation engine (don't show 7 alerts, show 1 attack story). So
 * the timeline here isn't decorative sequencing, it's the actual ordered
 * MITRE tactic chain, rendered like a trace on an oscilloscope: a glowing
 * vertical line with a node per stage, brightening as the chain progresses
 * toward the current (most severe / most recent) stage.
 */
export function KillChainTrace({ techniques, severity }: Props) {
  const color = severityColor[severity]

  if (techniques.length === 0) {
    return (
      <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '12px 0' }}>
        No MITRE techniques mapped yet.
      </div>
    )
  }

  return (
    <div style={{ position: 'relative', paddingLeft: 28 }}>
      <svg
        width="2"
        height="100%"
        style={{ position: 'absolute', left: 5, top: 6, bottom: 0, height: 'calc(100% - 12px)' }}
      >
        <line
          x1="1" y1="0" x2="1" y2="100%"
          stroke={color}
          strokeOpacity="0.25"
          strokeWidth="2"
        />
      </svg>

      {techniques.map((t, i) => {
        const isLast = i === techniques.length - 1
        return (
          <div
            key={t.technique_id + i}
            style={{
              position: 'relative',
              paddingBottom: isLast ? 0 : 22,
            }}
          >
            <span
              aria-hidden
              style={{
                position: 'absolute',
                left: -28,
                top: 3,
                width: 12,
                height: 12,
                borderRadius: '50%',
                background: isLast ? color : 'var(--bg-raised)',
                border: `2px solid ${color}`,
                boxShadow: isLast ? `0 0 10px 2px ${color}` : 'none',
              }}
            />
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
              <span
                className="mono"
                style={{
                  fontSize: 12,
                  fontWeight: 600,
                  color,
                  background: 'var(--bg-raised)',
                  border: '1px solid var(--border-hairline)',
                  borderRadius: 4,
                  padding: '1px 6px',
                }}
              >
                {t.technique_id}
              </span>
              <span style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-primary)' }}>
                {t.name}
              </span>
              <span
                style={{
                  fontSize: 11,
                  textTransform: 'uppercase',
                  letterSpacing: 0.6,
                  color: 'var(--text-muted)',
                }}
              >
                {t.tactic}
              </span>
            </div>
          </div>
        )
      })}
    </div>
  )
}
