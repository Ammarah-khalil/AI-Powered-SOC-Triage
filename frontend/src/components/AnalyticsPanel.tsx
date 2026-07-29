import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, CartesianGrid } from 'recharts'
import type { Analytics } from '../lib/types'
import { StatCard } from './StatCard'

interface Props {
  analytics: Analytics
}

export function AnalyticsPanel({ analytics }: Props) {
  const chartData = analytics.top_techniques.map(([name, count]) => ({
    name: name.split(' ')[0], // just the technique ID for axis brevity
    fullName: name,
    count,
  }))

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <StatCard label="Active Incidents" value={analytics.active_incidents} accent="var(--accent-signal)" />
        <StatCard label="High Risk" value={analytics.high_risk_incidents} accent="var(--accent-critical)" />
        <StatCard label="Mean Time to Detect" value={analytics.mttd_minutes} suffix="min" accent="var(--accent-signal)" />
        <StatCard label="Mean Time to Respond" value={analytics.mttr_minutes} suffix="min" accent="var(--accent-warn)" />
      </div>

      <div
        style={{
          background: 'var(--bg-surface)', border: '1px solid var(--border-hairline)',
          borderRadius: 10, padding: 18,
        }}
      >
        <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8, color: 'var(--text-muted)', marginBottom: 14 }}>
          Most Common MITRE Techniques
        </div>
        <div style={{ width: '100%', height: 220 }}>
          <ResponsiveContainer>
            <BarChart data={chartData} layout="vertical" margin={{ left: 8, right: 16 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-hairline-soft)" horizontal={false} />
              <XAxis type="number" allowDecimals={false} tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
              <YAxis
                type="category"
                dataKey="name"
                width={60}
                tick={{ fill: 'var(--text-secondary)', fontSize: 12, fontFamily: 'var(--font-mono)' }}
              />
              <Tooltip
                contentStyle={{ background: 'var(--bg-raised)', border: '1px solid var(--border-hairline)', borderRadius: 6 }}
                labelStyle={{ color: 'var(--text-primary)' }}
                formatter={(value: number, _name, item) => [value, item.payload.fullName]}
              />
              <Bar dataKey="count" fill="var(--accent-signal)" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div
        style={{
          background: 'var(--bg-surface)', border: '1px solid var(--border-hairline)',
          borderRadius: 10, padding: 18,
        }}
      >
        <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8, color: 'var(--text-muted)', marginBottom: 12 }}>
          Most Targeted Hosts
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {analytics.most_targeted_hosts.map(([host, count]) => (
            <div key={host} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13 }}>
              <span className="mono" style={{ color: 'var(--text-primary)' }}>{host}</span>
              <span style={{ color: 'var(--text-muted)' }}>{count} incident{count !== 1 ? 's' : ''}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
