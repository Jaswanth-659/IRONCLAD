import React, { useState } from 'react'
import { Search } from 'lucide-react'
import { useApi } from '../hooks/useApi'
import RiskBadge from '../components/RiskBadge'
import type { ThreatIndicator } from '../types'

interface ThreatResponse { indicators: ThreatIndicator[] }

export default function ThreatIntelligence() {
  const { data, loading, error } = useApi<ThreatResponse>('/api/threat-intel')
  const [search, setSearch] = useState('')

  if (loading) return <div className="p-6 text-sm text-muted">Loading threat intelligence…</div>
  if (error)   return <div className="p-6 text-sm text-danger">Error: {error}</div>

  const indicators = (data?.indicators ?? []).filter(
    (ind) => !search || ind.indicator.includes(search) || ind.threat_type.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-white">Threat Intelligence</h1>
          <p className="text-xs text-muted mt-0.5">Curated IOC feed — verified malicious infrastructure indicators</p>
        </div>
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            placeholder="Search IP or threat type…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-panel border border-border rounded px-8 py-1.5 text-xs text-white placeholder-muted outline-none focus:border-accent w-56"
          />
        </div>
      </div>

      <div className="bg-panel border border-border rounded-lg overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border">
              {['Indicator', 'Type', 'Threat', 'Confidence', 'Source', 'Last Seen'].map((h) => (
                <th key={h} className="text-left text-muted font-medium px-4 py-3">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {indicators.map((ind) => (
              <tr
                key={ind.id}
                className={`hover:bg-white/5 transition-colors ${ind.confidence >= 90 ? 'border-l-2 border-l-danger' : ''}`}
              >
                <td className="px-4 py-3">
                  <span className="font-mono text-white">{ind.indicator}</span>
                </td>
                <td className="px-4 py-3 text-muted">{ind.indicator_type}</td>
                <td className="px-4 py-3">
                  <RiskBadge value={ind.threat_type.replace(/[^A-Z0-9]/gi, '_').toUpperCase()} />
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="w-16 bg-border rounded-full h-1.5">
                      <div
                        className="h-1.5 rounded-full"
                        style={{
                          width: `${ind.confidence}%`,
                          backgroundColor: ind.confidence >= 90 ? '#ef4444' : '#f59e0b',
                        }}
                      />
                    </div>
                    <span className="font-mono">{ind.confidence}%</span>
                  </div>
                </td>
                <td className="px-4 py-3 text-muted">{ind.source}</td>
                <td className="px-4 py-3 text-muted">{ind.last_seen}</td>
              </tr>
            ))}
            {indicators.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-muted">No indicators match your search.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
