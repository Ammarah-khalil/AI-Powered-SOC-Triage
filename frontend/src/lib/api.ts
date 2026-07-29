import type { Analytics, Incident, IncidentSummary } from './types'

const BASE = '/api'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, init)
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.detail || `Request to ${path} failed with ${res.status}`)
  }
  return res.json()
}

export const api = {
  listIncidents: () => request<IncidentSummary[]>('/incidents'),
  getIncident: (id: string) => request<Incident>(`/incidents/${id}`),
  runInvestigation: (id: string) =>
    request<Incident>(`/incidents/${id}/investigate`, { method: 'POST' }),
  getAnalytics: () => request<Analytics>('/analytics'),
}
