import type { IncidentSummary } from '../lib/types'
import { severityColor, severityDim, severityLabel, formatTimeAgo } from '../lib/severity'

interface Props {
  incidents: IncidentSummary[]
  selectedId: string | null
  onSelect: (id: string) => void
  pulsingIds?: Set<string>
}

export function IncidentTable({ incidents, selectedId, onSelect, pulsingIds }: Props) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {incidents.map((inc) => {
        const isSelected = inc.id === selectedId
        const isPulsing = pulsingIds?.has(inc.id) ?? false
        return (
          <button
            key={inc.id}
            onClick={() => onSelect(inc.id)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 14,
              textAlign: 'left',
              padding: '12px 14px',
              borderRadius: 8,
              border: `1px solid ${isSelected ? severityColor[inc.severity] : 'var(--border-hairline)'}`,
              background: isSelected ? severityDim[inc.severity] : 'var(--bg-surface)',
              boxShadow: isPulsing ? `0 0 0 2px ${severityColor[inc.severity]}` : 'none',
              transition: 'background 0.15s ease, border-color 0.15s ease, box-shadow 0.3s ease',
            }}
          >
            <span
              aria-hidden
              style={{
                width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                background: severityColor[inc.severity],
                boxShadow: `0 0 6px 1px ${severityColor[inc.severity]}`,
              }}
            />
            <span className="mono" style={{ fontSize: 12, color: 'var(--text-muted)', width: 62, flexShrink: 0 }}>
              {inc.id}
            </span>
            <span style={{ flex: 1, fontSize: 14, fontWeight: 500, color: 'var(--text-primary)' }}>
              {inc.title}
            </span>
            {inc.top_technique && (
              <span
                className="mono"
                style={{
                  fontSize: 11, color: 'var(--text-secondary)',
                  border: '1px solid var(--border-hairline)', borderRadius: 4, padding: '1px 6px',
                  flexShrink: 0,
                }}
              >
                {inc.top_technique}
              </span>
            )}
            <span style={{ fontSize: 12, color: 'var(--text-muted)', width: 60, flexShrink: 0 }}>
              {inc.alert_count} alerts
            </span>
            <span
              className="mono"
              style={{ fontSize: 13, fontWeight: 700, color: severityColor[inc.severity], width: 34, textAlign: 'right', flexShrink: 0 }}
            >
              {inc.risk_score}
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-dim)', width: 58, textAlign: 'right', flexShrink: 0 }}>
              {formatTimeAgo(inc.created_at)}
            </span>
          </button>
        )
      })}
      {incidents.length === 0 && (
        <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 20, textAlign: 'center' }}>
          No incidents. Quiet shift.
        </div>
      )}
    </div>
  )
}
