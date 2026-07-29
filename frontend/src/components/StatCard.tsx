interface Props {
  label: string
  value: string | number
  accent?: string
  suffix?: string
}

export function StatCard({ label, value, accent = 'var(--accent-signal)', suffix }: Props) {
  return (
    <div
      style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-hairline)',
        borderRadius: 10,
        padding: '14px 18px',
        flex: 1,
        minWidth: 140,
      }}
    >
      <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.6, marginBottom: 6 }}>
        {label}
      </div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
        <span className="mono" style={{ fontSize: 26, fontWeight: 700, color: accent }}>
          {value}
        </span>
        {suffix && <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{suffix}</span>}
      </div>
    </div>
  )
}
