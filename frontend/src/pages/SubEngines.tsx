import React, { useState } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'
import { useApi } from '../hooks/useApi'
import RiskBadge from '../components/RiskBadge'
import type { SubEngineDetail } from '../types'

interface SubEnginesResponse { subengines: SubEngineDetail[] }

const ENGINE_LABELS: Record<string, string> = {
  ENGINE_1_TEMPORAL:    'ENGINE 1 — Temporal Behaviour',
  ENGINE_2_TRAFFIC:     'ENGINE 2 — Traffic Behaviour',
  ENGINE_3_CONNECTION:  'ENGINE 3 — Connection Behaviour',
}

function SubEngineCard({ se }: { se: SubEngineDetail }) {
  const [expanded, setExpanded] = useState(false)
  const riskColor = se.risk_score >= 7 ? 'text-danger' : se.risk_score >= 5 ? 'text-warning' : 'text-success'

  return (
    <div className="bg-panel border border-border rounded-lg overflow-hidden">
      <div
        className="flex items-center justify-between p-3 cursor-pointer hover:bg-white/5 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono bg-bg px-1.5 py-0.5 rounded text-accent">{se.subengine_id}</span>
          <span className="text-sm text-white">{se.name}</span>
        </div>
        <div className="flex items-center gap-3">
          <span className={`text-sm font-bold font-mono ${riskColor}`}>{se.risk_score.toFixed(1)}</span>
          <RiskBadge value={se.status} />
          {expanded ? <ChevronUp size={14} className="text-muted" /> : <ChevronDown size={14} className="text-muted" />}
        </div>
      </div>

      {/* Confidence bar */}
      <div className="px-3 pb-2">
        <div className="flex items-center gap-2">
          <div className="flex-1 bg-border rounded-full h-1">
            <div
              className="h-1 rounded-full transition-all"
              style={{
                width: `${se.confidence_score}%`,
                backgroundColor: se.risk_score >= 7 ? '#ef4444' : se.risk_score >= 5 ? '#f59e0b' : '#22c55e',
              }}
            />
          </div>
          <span className="text-xs text-muted font-mono">{se.confidence_score.toFixed(0)}%</span>
        </div>
      </div>

      {expanded && (
        <div className="px-3 pb-3 border-t border-border pt-3 space-y-3">
          <div>
            <div className="text-xs text-muted mb-1">Explanation</div>
            <p className="text-xs text-gray-300 leading-relaxed">{se.explanation}</p>
          </div>
          {Object.keys(se.evidence).length > 0 && (
            <div>
              <div className="text-xs text-muted mb-1.5">Evidence</div>
              <div className="bg-bg rounded p-2 font-mono text-xs text-gray-400 overflow-auto max-h-32">
                {JSON.stringify(se.evidence, null, 2)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function SubEngines() {
  const { data, loading, error } = useApi<SubEnginesResponse>('/api/sub-engines')

  if (loading) return <div className="p-6 text-sm text-muted">Loading sub-engine data…</div>
  if (error)   return <div className="p-6 text-sm text-danger">Error: {error}</div>

  const subengines = data?.subengines ?? []

  // Group by parent engine
  const groups: Record<string, SubEngineDetail[]> = {}
  for (const se of subengines) {
    if (!groups[se.parent_engine]) groups[se.parent_engine] = []
    groups[se.parent_engine].push(se)
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-white">Sub-Engine Investigation</h1>
        <p className="text-xs text-muted mt-0.5">12 independent secondary analysis modules across 3 primary engines</p>
      </div>

      {subengines.length === 0 && (
        <div className="bg-panel border border-border rounded-lg p-8 text-center text-muted text-sm">
          No sub-engine results yet. Upload a PCAP on the Overview page.
        </div>
      )}

      {Object.entries(groups).map(([engineId, ses]) => (
        <div key={engineId} className="space-y-2">
          <h2 className="text-sm font-medium text-white px-1">
            {ENGINE_LABELS[engineId] ?? engineId}
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {ses.map((se) => (
              <SubEngineCard key={se.subengine_id} se={se} />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
