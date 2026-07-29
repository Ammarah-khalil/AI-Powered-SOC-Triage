import type { Incident, IncidentSummary, Severity } from './types'

export function toSummary(inc: Incident): IncidentSummary {
  return {
    id: inc.id,
    title: inc.title,
    status: inc.status,
    severity: inc.severity,
    risk_score: inc.risk_score.total,
    alert_count: inc.alerts.length,
    created_at: inc.created_at,
    top_technique: inc.mitre_techniques[0]?.technique_id ?? null,
  }
}

export const severityColor: Record<Severity, string> = {
  low: 'var(--accent-ok)',
  medium: 'var(--accent-warn)',
  high: 'var(--accent-warn)',
  critical: 'var(--accent-critical)',
}

export const severityDim: Record<Severity, string> = {
  low: 'var(--accent-ok-dim)',
  medium: 'var(--accent-warn-dim)',
  high: 'var(--accent-warn-dim)',
  critical: 'var(--accent-critical-dim)',
}

export const severityLabel: Record<Severity, string> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
}

export function formatTimeAgo(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime()
  const mins = Math.round(diffMs / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.round(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.round(hrs / 24)}d ago`
}
