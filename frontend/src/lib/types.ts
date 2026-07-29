export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type IncidentStatus = 'new' | 'investigating' | 'contained' | 'closed'

export interface Alert {
  id: string
  timestamp: string
  source: string
  event_type: string
  host: string
  user?: string | null
  process?: string | null
  src_ip?: string | null
  dst_ip?: string | null
  raw_detail?: string | null
}

export interface MitreTechnique {
  technique_id: string
  name: string
  tactic: string
}

export interface ThreatIntelHit {
  indicator: string
  indicator_type: string
  source: string
  verdict: string
  confidence: number
  threat_actor?: string | null
}

export interface RiskScoreBreakdown {
  factor: string
  points: number
}

export interface RiskScore {
  total: number
  level: Severity
  breakdown: RiskScoreBreakdown[]
}

export interface AIInvestigation {
  summary: string
  suggested_actions: string[]
  mitre_chain: string[]
  confidence: number
  generated_at: string
  model: string
}

export interface Incident {
  id: string
  title: string
  status: IncidentStatus
  severity: Severity
  created_at: string
  updated_at: string
  affected_hosts: string[]
  affected_users: string[]
  alerts: Alert[]
  mitre_techniques: MitreTechnique[]
  threat_intel: ThreatIntelHit[]
  risk_score: RiskScore
  ai_investigation?: AIInvestigation | null
  assigned_analyst?: string | null
}

export interface IncidentSummary {
  id: string
  title: string
  status: IncidentStatus
  severity: Severity
  risk_score: number
  alert_count: number
  created_at: string
  top_technique?: string | null
}

export interface Analytics {
  total_incidents: number
  active_incidents: number
  high_risk_incidents: number
  top_techniques: [string, number][]
  most_targeted_hosts: [string, number][]
  mttd_minutes: number
  mttr_minutes: number
}
