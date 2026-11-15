import React, { useState, useEffect } from 'react'
import {
  ChevronDown,
  ChevronUp,
  RefreshCw,
  CheckCircle2,
  Clock,
  AlertTriangle,
  XCircle,
  Database,
  Sliders,
  Layers,
  Activity,
  FileCode,
} from 'lucide-react'
import { useApi } from '../hooks/useApi'
import { useWebSocket } from '../hooks/useWebSocket'
import RiskBadge from '../components/RiskBadge'
import type { SubEngineDetail } from '../types'

interface SubEnginesResponse {
  subengines?: SubEngineDetail[]
}

interface SessionItem {
  task_id: string
  filename: string
  file_size: number
  status: string
  total_packets: number
  total_flows: number
  overall_risk_score: number
  final_classification: string
  created_at: string
  completed_at: string | null
}

interface CanonicalSubEngine {
  id: string
  name: string
  parent_engine: 'ENGINE_1_TEMPORAL' | 'ENGINE_2_TRAFFIC' | 'ENGINE_3_CONNECTION'
  description: string
}

const CANONICAL_SUBENGINES: CanonicalSubEngine[] = [
  // ENGINE 1 — TEMPORAL BEHAVIOUR
  {
    id: 'E1.1',
    name: 'Periodicity Validator',
    parent_engine: 'ENGINE_1_TEMPORAL',
    description: 'Evaluates packet arrival timing regularity and coefficient of variation for C2 beacons',
  },
  {
    id: 'E1.2',
    name: 'Jitter Analyzer',
    parent_engine: 'ENGINE_1_TEMPORAL',
    description: 'Analyzes microsecond arrival interval drift and variance to defeat beacon jitter cloaking',
  },
  {
    id: 'E1.3',
    name: 'Burst Pattern Analyzer',
    parent_engine: 'ENGINE_1_TEMPORAL',
    description: 'Evaluates temporal clustering and Poisson distribution fit across active time windows',
  },
  {
    id: 'E1.4',
    name: 'Historical Behaviour Comparator',
    parent_engine: 'ENGINE_1_TEMPORAL',
    description: 'Non-parametric Kolmogorov-Smirnov test against baseline temporal profiles',
  },
  // ENGINE 2 — TRAFFIC BEHAVIOUR
  {
    id: 'E2.1',
    name: 'Packet Size Analyzer',
    parent_engine: 'ENGINE_2_TRAFFIC',
    description: 'Detects payload homogeneity, fixed-length padding, and MTU anomalies indicative of tunnelling',
  },
  {
    id: 'E2.2',
    name: 'Traffic Volume Analyzer',
    parent_engine: 'ENGINE_2_TRAFFIC',
    description: 'Monitors volumetric byte thresholds and asymmetric cumulative transfer rates',
  },
  {
    id: 'E2.3',
    name: 'Directional Traffic Analyzer',
    parent_engine: 'ENGINE_2_TRAFFIC',
    description: 'Calculates outbound vs inbound byte ratios to isolate exfiltration and beacon check-ins',
  },
  {
    id: 'E2.4',
    name: 'Burst Detection Analyzer',
    parent_engine: 'ENGINE_2_TRAFFIC',
    description: 'Identifies sudden volumetric bursts and injection spikes across short interval bins',
  },
  // ENGINE 3 — CONNECTION BEHAVIOUR
  {
    id: 'E3.1',
    name: 'Destination Analyzer',
    parent_engine: 'ENGINE_3_CONNECTION',
    description: 'Quantifies fan-out ratios, unique endpoint entropy, and external destination dispersal',
  },
  {
    id: 'E3.2',
    name: 'Port and Protocol Analyzer',
    parent_engine: 'ENGINE_3_CONNECTION',
    description: 'Discovers horizontal/vertical scans and unexpected non-standard service port usage',
  },
  {
    id: 'E3.3',
    name: 'Connection Failure Analyzer',
    parent_engine: 'ENGINE_3_CONNECTION',
    description: 'Inspects TCP handshake completion, RST ratios, and half-open SYN session accumulation',
  },
  {
    id: 'E3.4',
    name: 'Threat Intelligence Checker',
    parent_engine: 'ENGINE_3_CONNECTION',
    description: 'Cross-checks endpoints against local high-confidence threat feed and known IOC indicators',
  },
]

const ENGINE_GROUPS: Array<{
  id: 'ENGINE_1_TEMPORAL' | 'ENGINE_2_TRAFFIC' | 'ENGINE_3_CONNECTION'
  title: string
  subtitle: string
}> = [
  {
    id: 'ENGINE_1_TEMPORAL',
    title: 'ENGINE 1 — Temporal Behaviour',
    subtitle: 'Periodicity, jitter variance, burst patterns, and baseline statistical divergence',
  },
  {
    id: 'ENGINE_2_TRAFFIC',
    title: 'ENGINE 2 — Traffic Behaviour',
    subtitle: 'Packet size homogeneity, volumetric byte transfer, directional asymmetry, and bursts',
  },
  {
    id: 'ENGINE_3_CONNECTION',
    title: 'ENGINE 3 — Connection Behaviour',
    subtitle: 'Destination entropy, port scanning, handshake failure rates, and threat intelligence matches',
  },
]

type ExecutionStatus = 'COMPLETED' | 'RUNNING' | 'NOT EXECUTED' | 'FAILED' | 'INSUFFICIENT DATA'

function formatEvidenceValue(val: unknown): string {
  if (val === null || val === undefined) return 'None'
  if (typeof val === 'number') {
    return Number.isInteger(val) ? val.toLocaleString() : val.toFixed(4)
  }
  if (typeof val === 'boolean') return val ? 'TRUE' : 'FALSE'
  if (Array.isArray(val)) return `[${val.length} items]`
  if (typeof val === 'object') return '{...}'
  return String(val)
}

function SubEngineCard({
  meta,
  detail,
  sessionInfo,
}: {
  meta: CanonicalSubEngine
  detail?: SubEngineDetail
  sessionInfo?: SessionItem
}) {
  const [expanded, setExpanded] = useState(false)

  // Determine execution status
  let execStatus: ExecutionStatus = 'NOT EXECUTED'
  if (detail) {
    const rawStatus = (detail.status || '').toUpperCase()
    const exp = (detail.explanation || '').toLowerCase()
    if (rawStatus === 'FAILED' || exp.includes('failed') || exp.includes('error')) {
      execStatus = 'FAILED'
    } else if (
      rawStatus === 'INSUFFICIENT_DATA' ||
      exp.includes('insufficient') ||
      exp.includes('no packets') ||
      exp.includes('no flows')
    ) {
      execStatus = 'INSUFFICIENT DATA'
    } else {
      execStatus = 'COMPLETED'
    }
  }

  // Status badge styling
  const statusBadge = {
    'COMPLETED': {
      bg: 'bg-success/15 border-success/30 text-success',
      icon: CheckCircle2,
      label: 'COMPLETED',
    },
    'RUNNING': {
      bg: 'bg-accent/15 border-accent/30 text-accent animate-pulse',
      icon: Activity,
      label: 'RUNNING',
    },
    'NOT EXECUTED': {
      bg: 'bg-muted/15 border-border text-muted',
      icon: Clock,
      label: 'NOT EXECUTED',
    },
    'FAILED': {
      bg: 'bg-danger/15 border-danger/30 text-danger',
      icon: XCircle,
      label: 'FAILED',
    },
    'INSUFFICIENT DATA': {
      bg: 'bg-warning/15 border-warning/30 text-warning',
      icon: AlertTriangle,
      label: 'INSUFFICIENT DATA',
    },
  }[execStatus]

  const StatusIcon = statusBadge.icon

  // Extract numerical evidence items (scalars)
  const evidenceEntries: Array<[string, unknown]> = []
  if (detail?.evidence && typeof detail.evidence === 'object') {
    for (const [k, v] of Object.entries(detail.evidence)) {
      if (typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') {
        evidenceEntries.push([k, v])
      } else if (Array.isArray(v)) {
        evidenceEntries.push([`${k} (count)`, v.length])
      }
    }
  }

  // Derive packets/flows analyzed
  let flowsAnalysed = '—'
  let packetsAnalysed = '—'
  if (detail && sessionInfo) {
    flowsAnalysed = sessionInfo.total_flows.toLocaleString()
    packetsAnalysed = sessionInfo.total_packets.toLocaleString()
  }
  if (detail?.evidence) {
    const ev = detail.evidence as Record<string, unknown>
    if (typeof ev.flows_evaluated === 'number') flowsAnalysed = ev.flows_evaluated.toLocaleString()
    if (typeof ev.evaluated_samples === 'number') flowsAnalysed = ev.evaluated_samples.toLocaleString()
    if (typeof ev.total_flows === 'number') flowsAnalysed = ev.total_flows.toLocaleString()
    if (typeof ev.total_packets === 'number') packetsAnalysed = ev.total_packets.toLocaleString()
  }

  const riskScore = detail ? detail.risk_score.toFixed(1) : '—'
  const confidenceScore = detail ? `${detail.confidence_score.toFixed(0)}%` : '—'
  const classification = detail ? detail.status : 'PENDING'

  const scoreColor =
    !detail
      ? 'text-muted'
      : detail.risk_score >= 7
      ? 'text-danger'
      : detail.risk_score >= 5
      ? 'text-warning'
      : 'text-success'

  return (
    <div className="bg-panel border border-border rounded-lg overflow-hidden flex flex-col justify-between transition-all hover:border-border/80">
      {/* Top Header */}
      <div>
        <div className="p-4 border-b border-border/50 flex items-start justify-between gap-3 bg-white/[0.01]">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold bg-bg px-2 py-0.5 rounded border border-border text-accent">
                {meta.id}
              </span>
              <h3 className="text-sm font-semibold text-white tracking-wide">{meta.name}</h3>
            </div>
            <p className="text-xs text-muted leading-tight">{meta.description}</p>
          </div>

          <div className="flex flex-col items-end gap-1.5 shrink-0">
            <div
              className={`flex items-center gap-1 px-2 py-0.5 rounded-full border text-[11px] font-mono font-semibold ${statusBadge.bg}`}
            >
              <StatusIcon size={12} />
              <span>{statusBadge.label}</span>
            </div>
            {detail && <RiskBadge value={classification} />}
          </div>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-4 divide-x divide-border border-b border-border bg-bg/40 text-center py-2.5">
          <div>
            <div className="text-[10px] text-muted uppercase font-mono tracking-wider">Risk Score</div>
            <div className={`text-base font-bold font-mono mt-0.5 ${scoreColor}`}>
              {riskScore}
              {detail && <span className="text-[10px] text-muted font-normal"> /10</span>}
            </div>
          </div>
          <div>
            <div className="text-[10px] text-muted uppercase font-mono tracking-wider">Confidence</div>
            <div className="text-base font-bold font-mono text-white mt-0.5">{confidenceScore}</div>
          </div>
          <div>
            <div className="text-[10px] text-muted uppercase font-mono tracking-wider">Flows</div>
            <div className="text-xs font-mono font-semibold text-gray-300 mt-1">{flowsAnalysed}</div>
          </div>
          <div>
            <div className="text-[10px] text-muted uppercase font-mono tracking-wider">Packets</div>
            <div className="text-xs font-mono font-semibold text-gray-300 mt-1">{packetsAnalysed}</div>
          </div>
        </div>

        {/* Confidence Bar */}
        {detail && (
          <div className="px-4 pt-2.5 pb-1">
            <div className="w-full bg-border rounded-full h-1 overflow-hidden">
              <div
                className="h-1 rounded-full transition-all duration-500"
                style={{
                  width: `${Math.min(100, Math.max(0, detail.confidence_score))}%`,
                  backgroundColor:
                    detail.risk_score >= 7 ? '#ef4444' : detail.risk_score >= 5 ? '#f59e0b' : '#22c55e',
                }}
              />
            </div>
          </div>
        )}

        {/* Numerical Detection Evidence (Inline Proofs) */}
        <div className="p-4 space-y-2.5">
          <div>
            <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <FileCode size={11} className="text-accent" />
              Numerical Evidence
            </div>
            {evidenceEntries.length > 0 ? (
              <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
                {evidenceEntries.map(([key, val]) => (
                  <span
                    key={key}
                    className="inline-flex items-center gap-1 px-2 py-0.5 bg-bg border border-border rounded text-[11px] font-mono"
                  >
                    <span className="text-muted">{key}:</span>
                    <span className="text-white font-medium">{formatEvidenceValue(val)}</span>
                  </span>
                ))}
              </div>
            ) : (
              <div className="text-xs text-muted italic bg-bg/50 px-2 py-1.5 rounded border border-border/40">
                {execStatus === 'NOT EXECUTED'
                  ? 'Awaiting PCAP ingestion to compute numerical metrics.'
                  : 'No scalar numerical telemetry flagged.'}
              </div>
            )}
          </div>

          {/* Explanation */}
          <div>
            <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1">
              Detection Explanation
            </div>
            <p className="text-xs text-gray-300 leading-relaxed bg-bg/30 p-2 rounded border border-border/30">
              {detail?.explanation || 'Module has not executed yet. Upload a PCAP file to initiate forensic analysis.'}
            </p>
          </div>
        </div>
      </div>

      {/* Expandable Forensics Section */}
      <div className="border-t border-border bg-bg/20">
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full flex items-center justify-between px-4 py-2 text-xs text-muted hover:text-white hover:bg-white/5 transition-colors font-mono"
        >
          <span>{expanded ? 'Hide Forensics Panel' : 'Expand Detailed Investigation'}</span>
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>

        {expanded && (
          <div className="p-4 border-t border-border space-y-3 bg-black/30">
            <div>
              <div className="text-[11px] text-muted font-mono uppercase mb-1">Module Forensic Metadata</div>
              <div className="text-xs font-mono text-gray-300 grid grid-cols-2 gap-2 bg-bg p-2.5 rounded border border-border">
                <div>
                  <span className="text-muted">Sub-Engine ID:</span> {meta.id}
                </div>
                <div>
                  <span className="text-muted">Parent Engine:</span> {meta.parent_engine}
                </div>
                <div>
                  <span className="text-muted">Classification:</span> {classification}
                </div>
                <div>
                  <span className="text-muted">Status:</span> {execStatus}
                </div>
              </div>
            </div>

            <div>
              <div className="text-[11px] text-muted font-mono uppercase mb-1">Raw Evidence Structure (JSON)</div>
              {detail && detail.evidence && Object.keys(detail.evidence).length > 0 ? (
                <pre className="bg-bg rounded p-3 font-mono text-[11px] text-gray-300 overflow-x-auto max-h-48 border border-border scrollbar-thin">
                  {JSON.stringify(detail.evidence, null, 2)}
                </pre>
              ) : (
                <div className="text-xs text-muted italic bg-bg p-3 rounded border border-border">
                  No structured evidence object available for this module.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function SubEngines() {
  const [selectedSessionId, setSelectedSessionId] = useState<string>('')

  // Query analysis sessions for selector
  const { data: sessionsData, refetch: refetchSessions } = useApi<SessionItem[]>('/api/sessions')
  const sessions = Array.isArray(sessionsData) ? sessionsData : []

  // Default to latest completed session if none selected
  useEffect(() => {
    if (!selectedSessionId && sessions.length > 0) {
      const latestCompleted = sessions.find((s) => s.status === 'COMPLETED') ?? sessions[0]
      if (latestCompleted) {
        setSelectedSessionId(latestCompleted.task_id)
      }
    }
  }, [sessions, selectedSessionId])

  // Query sub-engines with optional session_id filter
  const subenginesUrl = selectedSessionId
    ? `/api/sub-engines?session_id=${encodeURIComponent(selectedSessionId)}`
    : '/api/sub-engines'

  const {
    data: subenginesData,
    loading: subenginesLoading,
    error: subenginesError,
    refetch: refetchSubengines,
  } = useApi<SubEnginesResponse | SubEngineDetail[]>(subenginesUrl)

  // Listen to WebSocket for real-time completion
  const { lastMessage } = useWebSocket('ws://localhost:8000/ws')

  useEffect(() => {
    const t = String(lastMessage?.type ?? '').toUpperCase()
    if (t === 'ANALYSIS_COMPLETED' || t === 'ANALYSIS_COMPLETE') {
      void refetchSessions()
      void refetchSubengines()
    }
  }, [lastMessage, refetchSessions, refetchSubengines])

  // Defensive array unpacking
  const subengineList: SubEngineDetail[] = Array.isArray(subenginesData)
    ? subenginesData
    : (subenginesData?.subengines ?? [])

  // Map sub-engine results by canonical subengine_id (e.g. 'E1.1')
  const resultMap = new Map<string, SubEngineDetail>()
  for (const se of subengineList) {
    resultMap.set(se.subengine_id, se)
  }

  // Active session metadata
  const currentSession = sessions.find((s) => s.task_id === selectedSessionId)

  // Overall counts
  const totalCompleted = CANONICAL_SUBENGINES.filter((m) => resultMap.has(m.id)).length

  return (
    <div className="p-6 space-y-6">
      {/* Header with Title and Session Selector */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-semibold text-white">Sub-Engine Investigation</h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-accent/15 text-accent border border-accent/30 font-semibold">
              {totalCompleted} / 12 Executed
            </span>
          </div>
          <p className="text-xs text-muted mt-0.5">
            Individual inspection of all 12 secondary investigation modules grouped under their 3 primary engines
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Session Selector */}
          <div className="flex items-center gap-2 bg-panel border border-border rounded px-3 py-1.5">
            <Database size={13} className="text-muted" />
            <span className="text-xs text-muted">Analysis Session:</span>
            <select
              value={selectedSessionId}
              onChange={(e) => setSelectedSessionId(e.target.value)}
              className="bg-transparent text-xs text-white outline-none cursor-pointer font-mono"
            >
              {sessions.length === 0 && <option value="">No sessions recorded</option>}
              {sessions.map((s) => (
                <option key={s.task_id} value={s.task_id} className="bg-panel text-white">
                  {s.filename} ({s.task_id.slice(0, 8)}…) — {s.status} [Score: {s.overall_risk_score.toFixed(1)}]
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={() => {
              void refetchSessions()
              void refetchSubengines()
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-panel hover:bg-border text-xs text-gray-300 border border-border rounded transition-colors"
            title="Refresh sub-engine evaluations"
          >
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Active Session Info Banner */}
      {currentSession && (
        <div className="bg-panel/70 border border-border rounded-lg p-3 px-4 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
          <div className="flex items-center gap-3">
            <span className="text-muted">File:</span>
            <span className="text-white font-semibold">{currentSession.filename}</span>
            <span className="text-muted">|</span>
            <span className="text-muted">Session ID:</span>
            <span className="text-accent">{currentSession.task_id}</span>
          </div>
          <div className="flex items-center gap-4">
            <div>
              <span className="text-muted">Packets: </span>
              <span className="text-white font-bold">{currentSession.total_packets.toLocaleString()}</span>
            </div>
            <div>
              <span className="text-muted">Flows: </span>
              <span className="text-white font-bold">{currentSession.total_flows.toLocaleString()}</span>
            </div>
            <div>
              <span className="text-muted">Overall Risk: </span>
              <span
                className={`font-bold ${
                  currentSession.overall_risk_score >= 7
                    ? 'text-danger'
                    : currentSession.overall_risk_score >= 5
                    ? 'text-warning'
                    : 'text-success'
                }`}
              >
                {currentSession.overall_risk_score.toFixed(1)}/10
              </span>
            </div>
            <RiskBadge value={currentSession.final_classification} />
          </div>
        </div>
      )}

      {subenginesError && (
        <div className="bg-danger/10 border border-danger/30 text-danger p-4 rounded-lg text-xs">
          Error retrieving sub-engine telemetry: {subenginesError}
        </div>
      )}

      {/* Render 3 Primary Engine Groups containing all 12 canonical modules */}
      <div className="space-y-8">
        {ENGINE_GROUPS.map((group) => {
          const groupModules = CANONICAL_SUBENGINES.filter((m) => m.parent_engine === group.id)
          const executedCount = groupModules.filter((m) => resultMap.has(m.id)).length

          return (
            <div key={group.id} className="space-y-3">
              <div className="flex items-center justify-between border-b border-border/80 pb-2 px-1">
                <div>
                  <div className="flex items-center gap-2">
                    <Layers size={15} className="text-accent" />
                    <h2 className="text-sm font-semibold text-white tracking-wide">{group.title}</h2>
                  </div>
                  <p className="text-xs text-muted mt-0.5">{group.subtitle}</p>
                </div>
                <div className="text-xs font-mono text-muted">
                  <span className="text-white font-semibold">{executedCount}</span> / 4 Analyzed
                </div>
              </div>

              <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                {groupModules.map((meta) => {
                  const detail = resultMap.get(meta.id)
                  return (
                    <SubEngineCard
                      key={meta.id}
                      meta={meta}
                      detail={detail}
                      sessionInfo={currentSession}
                    />
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
