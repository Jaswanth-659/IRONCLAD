import React from 'react'
import { Wifi, WifiOff, Activity } from 'lucide-react'
import { useWebSocket } from '../hooks/useWebSocket'

export default function Header() {
  const { connected } = useWebSocket('ws://localhost:8000/ws')

  return (
    <header className="h-13 bg-panel border-b border-border flex items-center justify-between px-6 shrink-0">
      <div className="text-xs text-muted tracking-wide">
        INTELLIGENT NETWORK TELEMETRY &amp; CRYPTOGRAPHIC DEFENCE ENGINE
      </div>
      <div className="flex items-center gap-5">
        <div className={`flex items-center gap-1.5 text-xs ${connected ? 'text-success' : 'text-danger'}`}>
          {connected ? <Wifi size={13} /> : <WifiOff size={13} />}
          {connected ? 'Live Telemetry' : 'Reconnecting…'}
        </div>
        <div className="flex items-center gap-1.5 text-xs text-muted">
          <Activity size={13} className="text-accent" />
          Real-time
        </div>
      </div>
    </header>
  )
}
