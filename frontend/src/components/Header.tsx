import React from 'react'
import { Wifi, WifiOff, Activity } from 'lucide-react'
import { useWebSocket } from '../hooks/useWebSocket'

export default function Header() {
  const { connected } = useWebSocket('ws://localhost:8000/ws')

  return (
    <header className="h-12 bg-panel border-b border-border flex items-center justify-between px-6 shrink-0">
      <div className="text-[11px] text-zinc-400 font-mono tracking-widest uppercase">
        INTELLIGENT NETWORK TELEMETRY &amp; CRYPTOGRAPHIC DEFENCE ENGINE
      </div>
      <div className="flex items-center gap-5 font-mono text-xs">
        <div className={`flex items-center gap-1.5 ${connected ? 'text-emerald-400' : 'text-red-400'}`}>
          {connected ? <Wifi size={13} /> : <WifiOff size={13} />}
          <span>{connected ? 'Live Telemetry' : 'Reconnecting…'}</span>
        </div>
        <div className="flex items-center gap-1.5 text-zinc-400">
          <Activity size={13} className="text-indigo-400" />
          <span>Real-time</span>
        </div>
      </div>
    </header>
  )
}
