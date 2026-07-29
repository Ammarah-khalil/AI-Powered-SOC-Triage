import { useEffect, useRef, useState } from 'react'
import type { Incident } from './types'

export type LiveEvent = { type: 'incident_created' | 'incident_updated'; incident: Incident }

/**
 * Connects to the backend's live incident feed. Auto-reconnects with a
 * short backoff if the connection drops (backend restart, network blip),
 * since this is meant to run unattended on a SOC wall display.
 */
export function useIncidentSocket(onEvent: (event: LiveEvent) => void) {
  const [connected, setConnected] = useState(false)
  const onEventRef = useRef(onEvent)
  onEventRef.current = onEvent

  useEffect(() => {
    let socket: WebSocket | null = null
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null
    let cancelled = false

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      socket = new WebSocket(`${protocol}//${window.location.host}/ws/incidents`)

      socket.onopen = () => setConnected(true)

      socket.onmessage = (msg) => {
        try {
          const parsed = JSON.parse(msg.data) as LiveEvent
          onEventRef.current(parsed)
        } catch {
          // ignore malformed frames
        }
      }

      socket.onclose = () => {
        setConnected(false)
        if (!cancelled) {
          reconnectTimer = setTimeout(connect, 2000)
        }
      }

      socket.onerror = () => {
        socket?.close()
      }
    }

    connect()

    return () => {
      cancelled = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      socket?.close()
    }
  }, [])

  return { connected }
}
