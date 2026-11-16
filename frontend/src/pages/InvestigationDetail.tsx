import React from 'react'
import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, ChevronRight } from 'lucide-react'
import { useApi } from '../hooks/useApi'
import RiskBadge from '../components/RiskBadge'
import type { IncidentDetail } from '../types'

export default function InvestigationDetail() {
  const { id } = useParams<{ id: string }>()
  const { data, loading, error } = useApi<IncidentDetail>(`/api/incidents/${id ?? ''}`)

  if (loading) return <div className="p-6 text-sm text-muted">Loading investigation…</div>
  if (error)   return <div className="p-6 text-sm text-danger">Error: {error}</div>
  if (!data)   return null

  const { incident: inc, primary_engine_findings, secondary_investigation_results,
          mathematical_evidence, escalation_history, cross_engine_correlation,
          final_decision_explanation, recommended_actions } = data

  return (
    <div className="p-6 space-y-6">
      {/* Back */}
      <Link to="/incidents" className="inline-flex items-center gap-1.5 text-xs text-muted hover:text-white">
        <ArrowLeft size={12} /> Back to Incidents
      </Link>

      {/* Header */}
      <div className="bg-panel border border-border rounded-lg p-5">
        <div className="flex items-start justify-between mb-3">
          <div>
            <div className="text-xs text-muted mb-1">Incident #{inc.id}</div>
            <h1 className="text-lg font-semibold text-white">
              {inc.source_ip} <ChevronRight size={14} className="inline text-muted" /> {inc.destination_ip}:{inc.port}
            </h1>
          </div>
          <RiskBadge value={inc.classification} />
        </div>
        <p className="text-sm text-gray-300">{inc.description}</p>
        <div className="flex gap-4 mt-3 text-xs text-muted flex-wrap">
          <span>Protocol: <span className="text-white">{inc.protocol}</span></span>
          <span>Risk: <span className="font-bold font-mono text-danger">{(inc.risk_score ?? 0).toFixed(1)}/10</span></span>
          <span>Engine: <span className="text-white">{inc.triggered_engine}</span></span>
          <span>Time: <span className="text-white font-mono">{inc.timestamp ? new Date(inc.timestamp).toLocaleString() : '—'}</span></span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Primary Engine Findings */}
        <div className="bg-panel border border-border rounded-lg p-4">
          <h2 className="text-sm font-medium text-white mb-3">Primary Engine Findings</h2>
          <div className="space-y-3">
            {primary_engine_findings.map((ef, i) => (
              <div key={i} className="border border-border rounded p-3">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs text-white font-medium">{String(ef.name || 'Detection Engine')}</span>
                  <RiskBadge value={String(ef.escalation || 'NORMAL')} />
                </div>
                <p className="text-xs text-gray-400">{String(ef.explanation || '')}</p>
                <div className="flex gap-3 mt-1.5 text-xs text-muted">
                  <span>Risk: <span className="text-white font-mono">{(Number(ef.risk_score) || 0).toFixed(1)}</span></span>
                  <span>Confidence: <span className="text-white font-mono">{(Number(ef.confidence_score) || 0).toFixed(0)}%</span></span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Mathematical Evidence */}
        <div className="bg-panel border border-border rounded-lg p-4">
          <h2 className="text-sm font-medium text-white mb-3">Mathematical Evidence</h2>
          <div className="space-y-1.5">
            {Object.entries(mathematical_evidence).map(([k, v]) => (
              <div key={k} className="flex justify-between text-xs">
                <span className="text-muted">{k.replace(/_/g, ' ')}</span>
                <span className="text-white font-mono">{JSON.stringify(v)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Sub-engine results */}
      <div className="bg-panel border border-border rounded-lg p-4">
        <h2 className="text-sm font-medium text-white mb-3">Secondary Investigation Results ({secondary_investigation_results.length} sub-engines)</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {secondary_investigation_results.map((se) => (
            <div key={se.subengine_id} className="border border-border rounded p-3">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-mono text-accent">{se.subengine_id}</span>
                <RiskBadge value={se.status} />
              </div>
              <div className="text-xs text-white font-medium mb-1">{se.name}</div>
              <p className="text-xs text-gray-400 leading-relaxed">{se.explanation}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Escalation Timeline */}
      <div className="bg-panel border border-border rounded-lg p-4">
        <h2 className="text-sm font-medium text-white mb-3">Escalation History</h2>
        <div className="relative pl-4">
          <div className="absolute left-0 top-0 bottom-0 w-px bg-border" />
          {escalation_history.map((ev, i) => (
            <div key={i} className="relative mb-4 pl-4">
              <div className="absolute -left-1.5 top-1 w-3 h-3 rounded-full border-2 border-panel" style={{
                backgroundColor: ev.level.includes('HIGH') ? '#ef4444' : ev.level.includes('SECONDARY') ? '#f59e0b' : '#3b82f6',
              }} />
              <div className="text-xs text-white font-medium">{ev.stage}</div>
              <div className="text-xs text-muted">{ev.detail}</div>
              <div className="text-xs text-muted mt-0.5">{ev.level}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Cross-Engine Correlation */}
      <div className="bg-panel border border-border rounded-lg p-4">
        <h2 className="text-sm font-medium text-white mb-3">Cross-Engine Correlation</h2>
        <div className="space-y-2">
          {cross_engine_correlation.map((item, i) => (
            <div key={i} className="flex items-center gap-3">
              <div className="text-xs text-muted w-32 shrink-0">{item.engine}</div>
              <div className="flex-1 bg-border rounded-full h-1.5">
                <div
                  className="h-1.5 rounded-full bg-accent"
                  style={{ width: `${(item.correlation_weight * 100).toFixed(0)}%` }}
                />
              </div>
              <div className="text-xs font-mono text-white w-10 text-right">
                {(item.correlation_weight * 100).toFixed(0)}%
              </div>
              <div className="text-xs text-muted flex-1">{item.signal}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Final Decision & Recommended Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="bg-panel border border-border rounded-lg p-4">
          <h2 className="text-sm font-medium text-white mb-2">Final Decision</h2>
          <p className="text-xs text-gray-300 leading-relaxed">{final_decision_explanation}</p>
        </div>
        <div className="bg-panel border border-border rounded-lg p-4">
          <h2 className="text-sm font-medium text-white mb-2">Recommended Actions</h2>
          <ul className="space-y-1.5">
            {recommended_actions.map((action, i) => (
              <li key={i} className="flex gap-2 text-xs text-gray-300">
                <span className="text-accent mt-0.5 shrink-0">→</span>
                {action}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}
