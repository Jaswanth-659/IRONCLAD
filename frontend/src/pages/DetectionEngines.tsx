import React from 'react'
import { RadialBarChart, RadialBar, ResponsiveContainer } from 'recharts'
import { useApi } from '../hooks/useApi'
import RiskBadge from '../components/RiskBadge'
import type { PrimaryEngineDetail } from '../types'

interface EnginesResponse { engines: PrimaryEngineDetail[] }

function EngineCard({ engine }: { engine: PrimaryEngineDetail }) {
  const riskColor = engine.risk_score >= 7 ? '#ef4444' : engine.risk_score >= 5 ? '#f59e0b' : '#22c55e'
  const radialData = [{ value: (engine.risk_score / 10) * 100, fill: riskColor }]

  return (
    <div className="bg-panel border border-border rounded-lg p-5">
      <div className="flex items-start justify-between mb-4">
        <div>
          <div className="text-xs text-muted mb-1">{engine.engine_id}</div>
          <div className="text-sm font-semibold text-white">{engine.name}</div>
        </div>
        <RiskBadge value={engine.escalation} />
      </div>

      {/* Radial gauge */}
      <div className="flex items-center gap-6 mb-4">
        <div className="relative w-24 h-24">
          <ResponsiveContainer width="100%" height="100%">
            <RadialBarChart cx="50%" cy="50%" innerRadius="60%" outerRadius="100%"
              startAngle={90} endAngle={-270} data={radialData}>
              <RadialBar dataKey="value" cornerRadius={4} background={{ fill: '#1e2a3a' }} />
            </RadialBarChart>
          </ResponsiveContainer>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-lg font-bold font-mono" style={{ color: riskColor }}>
              {engine.risk_score.toFixed(1)}
            </span>
          </div>
        </div>

        <div className="flex-1 space-y-2">
          <div>
            <div className="text-xs text-muted mb-1">Confidence</div>
            <div className="flex items-center gap-2">
              <div className="flex-1 bg-border rounded-full h-1.5">
                <div className="h-1.5 rounded-full bg-accent" style={{ width: `${engine.confidence_score}%` }} />
              </div>
              <span className="text-xs text-white font-mono w-9 text-right">{engine.confidence_score.toFixed(0)}%</span>
            </div>
          </div>
          <div>
            <div className="text-xs text-muted mb-1">Status</div>
            <RiskBadge value={engine.status} />
          </div>
          <div>
            <div className="text-xs text-muted">Exec time: {engine.execution_time_ms.toFixed(1)} ms</div>
          </div>
        </div>
      </div>

      <div className="border-t border-border pt-3">
        <div className="text-xs text-muted mb-1">Explanation</div>
        <p className="text-xs text-gray-300 leading-relaxed">{engine.explanation}</p>
      </div>

      {/* Evidence */}
      {Object.keys(engine.evidence).length > 0 && (
        <div className="mt-3 border-t border-border pt-3">
          <div className="text-xs text-muted mb-1.5">Evidence</div>
          <div className="grid grid-cols-2 gap-1.5">
            {Object.entries(engine.evidence).slice(0, 4).map(([k, v]) => (
              <div key={k} className="bg-bg rounded px-2 py-1">
                <div className="text-xs text-muted truncate">{k.replace(/_/g, ' ')}</div>
                <div className="text-xs text-white font-mono">{JSON.stringify(v)}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default function DetectionEngines() {
  const { data, loading, error } = useApi<EnginesResponse>('/api/engines')

  if (loading) return <div className="p-6 text-sm text-muted">Loading engine data…</div>
  if (error) return <div className="p-6 text-sm text-danger">Error: {error}</div>

  const engines = data?.engines ?? []

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-white">Detection Engines</h1>
        <p className="text-xs text-muted mt-0.5">Three independent primary threat-detection engines — ENGINE 1, 2 &amp; 3</p>
      </div>

      {engines.length === 0 && (
        <div className="bg-panel border border-border rounded-lg p-8 text-center text-muted text-sm">
          No engine results yet. Upload a PCAP on the Overview page.
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {engines.map((engine) => (
          <EngineCard key={engine.engine_id} engine={engine} />
        ))}
      </div>
    </div>
  )
}
