import React from 'react'
import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Cpu, Search, Shield,
  Network, AlertTriangle, Lock, Gauge,
} from 'lucide-react'

const NAV = [
  { to: '/', icon: LayoutDashboard, label: 'Overview' },
  { to: '/telemetry', icon: Gauge, label: 'Data Loss & Rates' },
  { to: '/engines', icon: Cpu, label: 'Detection Engines' },
  { to: '/sub-engines', icon: Search, label: 'Sub-Engines' },
  { to: '/threat-intel', icon: Shield, label: 'Threat Intel' },
  { to: '/topology', icon: Network, label: 'Topology' },
  { to: '/incidents', icon: AlertTriangle, label: 'Incidents' },
  { to: '/containment', icon: Lock, label: 'Containment' },
]

export default function Sidebar() {
  return (
    <aside className="w-52 shrink-0 bg-panel border-r border-border flex flex-col h-screen sticky top-0 z-30">
      <div className="p-4 border-b border-border">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded border border-zinc-800 bg-black flex items-center justify-center">
            <Shield size={14} className="text-white" />
          </div>
          <div>
            <div className="text-sm font-bold text-white tracking-widest font-mono">IRONCLAD</div>
            <div className="text-xs text-zinc-400">Defence Engine</div>
          </div>
        </div>
      </div>

      <nav className="flex-1 py-3 overflow-y-auto space-y-1">
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3.5 py-2 text-sm transition-colors mx-2 rounded-md ${
                isActive
                  ? 'bg-white text-black font-semibold shadow-sm'
                  : 'text-zinc-400 hover:text-white hover:bg-zinc-900/60 font-medium'
              }`
            }
          >
            <Icon size={15} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="p-3 border-t border-border text-xs text-zinc-500 font-mono">
        v1.0.0 · IRONCLAD Engine
      </div>
    </aside>
  )
}
