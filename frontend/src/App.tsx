import { useEffect, useState, useCallback } from 'react'
import type { Analytics, Incident, IncidentSummary } from './lib/types'
import { api } from './lib/api'
import { toSummary } from './lib/severity'
import { useIncidentSocket } from './lib/useIncidentSocket'
import { IncidentTable } from './components/IncidentTable'
import { IncidentDetail } from './components/IncidentDetail'
import { AnalyticsPanel } from './components/AnalyticsPanel'
import { StatCard } from './components/StatCard'

type Tab = 'incidents' | 'analytics'

export default function App() {
  const [tab, setTab] = useState<Tab>('incidents')
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [selected, setSelected] = useState<Incident | null>(null)
  const [analytics, setAnalytics] = useState<Analytics | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [pulsingIds, setPulsingIds] = useState<Set<string>>(new Set())

  useEffect(() => {
    api.listIncidents()
      .then((list) => {
        setIncidents(list)
        if (list.length > 0) handleSelect(list[0].id)
      })
      .catch((e) => setLoadError(e.message))
    api.getAnalytics().then(setAnalytics).catch(() => {})
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const flashRow = useCallback((id: string) => {
    setPulsingIds((prev) => new Set(prev).add(id))
    setTimeout(() => {
      setPulsingIds((prev) => {
        const next = new Set(prev)
        next.delete(id)
        return next
      })
    }, 1200)
  }, [])

  const { connected } = useIncidentSocket(
    useCallback(
      (event) => {
        const summary = toSummary(event.incident)

        setIncidents((prev) => {
          const withoutThis = prev.filter((i) => i.id !== summary.id)
          return [...withoutThis, summary].sort((a, b) => b.risk_score - a.risk_score)
        })

        setSelected((prev) => (prev && prev.id === event.incident.id ? event.incident : prev))

        api.getAnalytics().then(setAnalytics).catch(() => {})
        flashRow(summary.id)
      },
      [flashRow],
    ),
  )

  async function handleSelect(id: string) {
    try {
      const inc = await api.getIncident(id)
      setSelected(inc)
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : 'Failed to load incident')
    }
  }

  return (
    <div style={{ display: 'flex', height: '100%', minHeight: '100vh' }}>
      {/* Nav rail */}
      <nav
        style={{
          width: 64, flexShrink: 0, borderRight: '1px solid var(--border-hairline)',
          display: 'flex', flexDirection: 'column', alignItems: 'center', paddingTop: 20, gap: 4,
          background: 'var(--bg-surface)',
        }}
      >
        <div
          aria-hidden
          style={{
            width: 30, height: 30, borderRadius: 8, marginBottom: 18,
            background: 'linear-gradient(135deg, var(--accent-signal), var(--accent-critical))',
          }}
        />
        {(['incidents', 'analytics'] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            title={t}
            style={{
              width: 40, height: 40, borderRadius: 8, border: 'none',
              background: tab === t ? 'var(--bg-raised)' : 'transparent',
              color: tab === t ? 'var(--accent-signal)' : 'var(--text-muted)',
              fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5,
            }}
          >
            {t === 'incidents' ? 'INC' : 'AN'}
          </button>
        ))}

        <div style={{ marginTop: 'auto', marginBottom: 16, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
          <span
            aria-hidden
            style={{
              width: 8, height: 8, borderRadius: '50%',
              background: connected ? 'var(--accent-ok)' : 'var(--text-dim)',
              boxShadow: connected ? '0 0 6px 1px var(--accent-ok)' : 'none',
            }}
          />
          <span style={{ fontSize: 9, color: connected ? 'var(--accent-ok)' : 'var(--text-dim)', letterSpacing: 0.5 }}>
            {connected ? 'LIVE' : 'OFF'}
          </span>
        </div>
      </nav>

      {/* Incident list column */}
      <div
        style={{
          width: tab === 'incidents' ? 460 : 0, flexShrink: 0, overflow: 'hidden',
          borderRight: tab === 'incidents' ? '1px solid var(--border-hairline)' : 'none',
          transition: 'width 0.2s ease', display: 'flex', flexDirection: 'column',
        }}
      >
        <div style={{ padding: '20px 20px 12px' }}>
          <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 18, margin: '0 0 4px' }}>
            Incident Console
          </h1>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
            Correlated incidents, prioritized by risk score
          </p>
        </div>
        <div style={{ padding: '0 20px 20px', flex: 1, overflowY: 'auto' }}>
          <IncidentTable
            incidents={incidents}
            selectedId={selected?.id ?? null}
            onSelect={handleSelect}
            pulsingIds={pulsingIds}
          />
        </div>
      </div>

      {/* Main content */}
      <main style={{ flex: 1, padding: 28, overflowY: 'auto' }}>
        {loadError && (
          <div
            style={{
              background: 'var(--accent-critical-dim)', border: '1px solid var(--accent-critical)',
              color: 'var(--text-primary)', borderRadius: 8, padding: 14, marginBottom: 16, fontSize: 13,
            }}
          >
            {loadError}. Is the backend running at <span className="mono">http://localhost:8000</span>?
          </div>
        )}

        {tab === 'incidents' && (
          selected ? (
            <IncidentDetail incident={selected} onUpdated={setSelected} />
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 14 }}>
              Select an incident from the list.
            </div>
          )
        )}

        {tab === 'analytics' && (
          analytics ? (
            <AnalyticsPanel analytics={analytics} />
          ) : (
            <div style={{ display: 'flex', gap: 12 }}>
              <StatCard label="Loading" value="…" />
            </div>
          )
        )}
      </main>
    </div>
  )
}
