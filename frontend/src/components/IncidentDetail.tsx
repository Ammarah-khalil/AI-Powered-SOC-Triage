import { useState } from 'react'
import type { Incident } from '../lib/types'
import { severityColor, severityDim, severityLabel } from '../lib/severity'
import { RiskGauge } from './RiskGauge'
import { KillChainTrace } from './KillChainTrace'
import { api } from '../lib/api'

interface Props {
  incident: Incident
  onUpdated: (incident: Incident) => void
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8,
        color: 'var(--text-muted)', marginBottom: 10,
      }}
    >
      {children}
    </div>
  )
}

function Panel({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-hairline)',
        borderRadius: 10,
        padding: 18,
      }}
    >
      {children}
    </div>
  )
}

export function IncidentDetail({ incident, onUpdated }: Props) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleInvestigate() {
    setLoading(true)
    setError(null)
    try {
      const updated = await api.runInvestigation(incident.id)
      onUpdated(updated)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Investigation failed')
    } finally {
      setLoading(false)
    }
  }

  const inv = incident.ai_investigation

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16 }}>
        <div>
          <div className="mono" style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>
            {incident.id}
          </div>
          <h2 style={{ margin: 0, fontFamily: 'var(--font-display)', fontSize: 22, lineHeight: 1.3 }}>
            {incident.title}
          </h2>
          <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
            <span
              style={{
                fontSize: 11, fontWeight: 600, padding: '3px 9px', borderRadius: 20,
                background: severityDim[incident.severity], color: severityColor[incident.severity],
                textTransform: 'uppercase', letterSpacing: 0.5,
              }}
            >
              {severityLabel[incident.severity]}
            </span>
            <span
              style={{
                fontSize: 11, fontWeight: 500, padding: '3px 9px', borderRadius: 20,
                background: 'var(--bg-raised)', color: 'var(--text-secondary)',
                textTransform: 'capitalize',
              }}
            >
              {incident.status}
            </span>
            {incident.assigned_analyst && (
              <span style={{ fontSize: 11, color: 'var(--text-muted)', padding: '3px 0' }}>
                assigned to {incident.assigned_analyst}
              </span>
            )}
          </div>
        </div>
        <RiskGauge score={incident.risk_score.total} severity={incident.severity} />
      </div>

      {/* AI Investigation */}
      <Panel>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <SectionLabel>AI Investigation</SectionLabel>
          <button
            onClick={handleInvestigate}
            disabled={loading}
            style={{
              fontSize: 12, fontWeight: 600, padding: '6px 12px', borderRadius: 6,
              border: `1px solid var(--accent-signal)`,
              background: loading ? 'var(--bg-raised)' : 'transparent',
              color: 'var(--accent-signal)',
              opacity: loading ? 0.6 : 1,
            }}
          >
            {loading ? 'Investigating…' : inv ? 'Re-run investigation' : 'Run investigation'}
          </button>
        </div>

        {error && (
          <div style={{ fontSize: 13, color: 'var(--accent-critical)', marginBottom: 10 }}>
            {error}
          </div>
        )}

        {!inv && !loading && !error && (
          <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            No investigation yet. Run it to get an AI-generated summary, prioritized response
            actions, and the ordered MITRE technique chain for this incident.
          </div>
        )}

        {inv && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <p style={{ margin: 0, fontSize: 14, lineHeight: 1.6, color: 'var(--text-primary)' }}>
              {inv.summary}
            </p>

            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>
                Suggested actions
              </div>
              <ol style={{ margin: 0, paddingLeft: 20, display: 'flex', flexDirection: 'column', gap: 6 }}>
                {inv.suggested_actions.map((a, i) => (
                  <li key={i} style={{ fontSize: 13, lineHeight: 1.5, color: 'var(--text-primary)' }}>
                    {a}
                  </li>
                ))}
              </ol>
            </div>

            <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-dim)' }}>
              <span>confidence: {inv.confidence}%</span>
              <span className="mono">{inv.model}</span>
              <span>{new Date(inv.generated_at).toLocaleString()}</span>
            </div>
          </div>
        )}
      </Panel>

      {/* Kill chain trace */}
      <Panel>
        <SectionLabel>Attack Chain (MITRE ATT&amp;CK)</SectionLabel>
        <KillChainTrace
          techniques={incident.mitre_techniques}
          severity={incident.severity}
        />
      </Panel>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Risk breakdown */}
        <Panel>
          <SectionLabel>Risk Score Breakdown</SectionLabel>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {incident.risk_score.breakdown.map((b, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13 }}>
                <span style={{ color: 'var(--text-secondary)' }}>{b.factor}</span>
                <span className="mono" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                  +{b.points}
                </span>
              </div>
            ))}
            <div
              style={{
                display: 'flex', justifyContent: 'space-between', fontSize: 13, fontWeight: 700,
                borderTop: '1px solid var(--border-hairline)', marginTop: 4, paddingTop: 8,
              }}
            >
              <span>Total</span>
              <span className="mono" style={{ color: severityColor[incident.severity] }}>
                {incident.risk_score.total}
              </span>
            </div>
          </div>
        </Panel>

        {/* Threat intel */}
        <Panel>
          <SectionLabel>Threat Intelligence</SectionLabel>
          {incident.threat_intel.length === 0 ? (
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>No IOC matches.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {incident.threat_intel.map((hit, i) => (
                <div key={i}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                    <span className="mono" style={{ fontSize: 13, fontWeight: 600 }}>{hit.indicator}</span>
                    <span style={{ fontSize: 11, color: 'var(--accent-critical)', fontWeight: 600 }}>
                      {hit.confidence}%
                    </span>
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                    {hit.verdict} &middot; via {hit.source}
                    {hit.threat_actor && ` \u2014 attributed to ${hit.threat_actor}`}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {/* Alert timeline */}
      <Panel>
        <SectionLabel>Correlated Alerts ({incident.alerts.length})</SectionLabel>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          {incident.alerts.map((a, i) => (
            <div
              key={a.id}
              style={{
                display: 'flex', gap: 14, padding: '8px 0',
                borderTop: i === 0 ? 'none' : '1px solid var(--border-hairline-soft)',
                fontSize: 13,
              }}
            >
              <span className="mono" style={{ color: 'var(--text-dim)', width: 70, flexShrink: 0 }}>
                {new Date(a.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>
              <span style={{ color: 'var(--text-muted)', width: 90, flexShrink: 0 }}>{a.source}</span>
              <span style={{ color: 'var(--text-primary)', flex: 1 }}>{a.event_type}</span>
              <span className="mono" style={{ color: 'var(--text-secondary)' }}>{a.host}</span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )
}
