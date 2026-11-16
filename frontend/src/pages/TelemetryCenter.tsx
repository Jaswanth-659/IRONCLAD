import React, { useState, useEffect } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  CheckCircle2,
  Clock,
  Database,
  Gauge,
  Info,
  Layers,
  Percent,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  Sliders,
  TrendingDown,
  TrendingUp,
  XCircle,
  Zap,
  HardDrive,
} from 'lucide-react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  RadialBarChart,
  RadialBar,
} from 'recharts'
import { useApi } from '../hooks/useApi'
import { useWebSocket } from '../hooks/useWebSocket'
import RiskBadge from '../components/RiskBadge'
import type {
  DataLossReport,
  DynamicThresholdsData,
  TrafficRatesData,
  RiskFactorData,
  LossControlMetrics,
  RecoveryRecordItem,
  LossEventItem,
} from '../types'

interface SessionItem {
  task_id: string
  filename: string
  status: string
  total_packets: number
  overall_risk_score: number
  final_classification: string
  created_at: string
}

export default function TelemetryCenter() {
  const [selectedSession, setSelectedSession] = useState<string>('')
  const [activeTab, setActiveTab] = useState<'loss' | 'thresholds' | 'hosts' | 'risk' | 'controlled_loss'>('loss')

  // Controlled Loss & Recovery Testbed state
  const [lossPct, setLossPct] = useState<number>(10)
  const [lossMode, setLossMode] = useState<string>('DETERMINISTIC')
  const [burstLen, setBurstLen] = useState<number>(3)
  const [targetSource, setTargetSource] = useState<string>('BOTH')
  const [isSimulating, setIsSimulating] = useState<boolean>(false)
  const [simMessage, setSimMessage] = useState<string | null>(null)

  const { data: sessions, refetch: refetchSessions } = useApi<SessionItem[]>('/api/sessions')
  const { data: lossData, loading: lossLoading, refetch: refetchLoss } = useApi<DataLossReport>(
    selectedSession ? `/api/data-loss?session_id=${selectedSession}` : '/api/data-loss'
  )
  const { data: thresholdData, loading: threshLoading, refetch: refetchThresh } = useApi<DynamicThresholdsData>(
    selectedSession ? `/api/dynamic-thresholds?session_id=${selectedSession}` : '/api/dynamic-thresholds'
  )
  const { data: rateData, loading: rateLoading, refetch: refetchRates } = useApi<TrafficRatesData>(
    selectedSession ? `/api/traffic-rates?session_id=${selectedSession}` : '/api/traffic-rates'
  )
  const { data: riskData, loading: riskLoading, refetch: refetchRisk } = useApi<RiskFactorData>(
    selectedSession ? `/api/risk-factor?session_id=${selectedSession}` : '/api/risk-factor'
  )
  const { data: lossControlMetrics, refetch: refetchLossControl } = useApi<LossControlMetrics>(
    '/api/loss-control/metrics'
  )
  const { data: recoveryHistoryData, refetch: refetchRecoveryHistory } = useApi<{
    recovery_records: RecoveryRecordItem[]
    loss_detected_events: LossEventItem[]
  }>('/api/loss-control/recovery-history')

  const { lastMessage } = useWebSocket('ws://localhost:8000/ws')

  // Auto-select latest completed session
  useEffect(() => {
    if (sessions && sessions.length > 0 && !selectedSession) {
      const completed = sessions.find((s) => s.status === 'COMPLETED')
      if (completed) {
        setSelectedSession(completed.task_id)
      } else {
        setSelectedSession(sessions[0].task_id)
      }
    }
  }, [sessions, selectedSession])

  // WebSocket Live Updates
  useEffect(() => {
    const t = String(lastMessage?.type ?? '').toUpperCase()
    if (t === 'ANALYSIS_COMPLETED' || t === 'ANALYSIS_COMPLETE' || t === 'LOSS_DETECTED' || t === 'PACKET_RECOVERED') {
      void refetchLoss()
      void refetchThresh()
      void refetchRates()
      void refetchRisk()
      void refetchLossControl()
      void refetchRecoveryHistory()
      void refetchSessions()
    }
  }, [
    lastMessage,
    refetchLoss,
    refetchThresh,
    refetchRates,
    refetchRisk,
    refetchLossControl,
    refetchRecoveryHistory,
    refetchSessions,
  ])

  const refreshAll = () => {
    void refetchLoss()
    void refetchThresh()
    void refetchRates()
    void refetchRisk()
    void refetchLossControl()
    void refetchRecoveryHistory()
    void refetchSessions()
  }

  // Simulation Trigger
  const handleRunSimulation = async () => {
    setIsSimulating(true)
    setSimMessage(null)
    try {
      const targets =
        targetSource === 'PC2'
          ? ['192.168.1.52']
          : targetSource === 'PC3'
          ? ['192.168.1.53']
          : ['192.168.1.52', '192.168.1.53']

      const res = await fetch('/api/loss-control/simulate-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          test_name: `Multi-PC Controlled Loss (${lossPct}%)`,
          loss_pct: lossPct,
          loss_mode: lossMode,
          burst_length: burstLen,
          total_packets_per_pc: 40,
          target_sources: targets,
          inject_corrupted_recovery: true,
          inject_duplicates: true,
        }),
      })

      if (!res.ok) {
        throw new Error(`Simulation failed: HTTP ${res.status}`)
      }

      const data = await res.json()
      setSimMessage(
        `Simulation Completed: ${data.summary?.total_packets_sent} pkts transmitted · ${data.summary?.total_recovered_packets} recovered (${data.summary?.recovery_rate_pct}%) · Mean Latency: ${data.summary?.mean_recovery_latency_ms} ms`
      )
      void refetchLossControl()
      void refetchRecoveryHistory()
    } catch (e) {
      setSimMessage(e instanceof Error ? e.message : 'Simulation failed')
    } finally {
      setIsSimulating(false)
    }
  }

  const handleResetController = async () => {
    try {
      await fetch('/api/loss-control/reset', { method: 'POST' })
      setSimMessage(null)
      void refetchLossControl()
      void refetchRecoveryHistory()
    } catch (err) {
      console.error(err)
    }
  }

  // Format helper
  const fmtBytes = (bytes: number) => {
    if (!bytes || bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
  }

  const overallRisk = riskData?.overall_risk_score ?? 0
  const riskColor = overallRisk >= 7 ? '#ef4444' : overallRisk >= 5 ? '#f59e0b' : '#22c55e'
  const radialData = [{ value: (overallRisk / 10) * 100, fill: riskColor }]

  return (
    <div className="p-6 space-y-6">
      {/* Top Banner / Header (Matching Overview / Detection Engines header pattern) */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-lg font-semibold text-white tracking-wide">
              Network Telemetry & Data-Loss Intelligence
            </h1>
            <RiskBadge value={lossData?.measurement_status === 'CONFIRMED' ? 'NORMAL' : 'SECONDARY_INVESTIGATION'} />
          </div>
          <p className="text-xs text-muted mt-0.5">
            Real-time packet transmission integrity, adaptive empirical baselines, and transparent risk mathematics
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Session Selector */}
          <div className="flex items-center gap-2 bg-panel border border-border rounded px-3 py-1.5 text-xs">
            <Database size={13} className="text-muted" />
            <span className="text-muted font-mono uppercase text-[11px] tracking-wider">Session:</span>
            <select
              value={selectedSession}
              onChange={(e) => setSelectedSession(e.target.value)}
              className="bg-transparent text-white font-mono focus:outline-none cursor-pointer max-w-[220px] truncate"
            >
              <option value="" className="bg-panel">Latest Active Session</option>
              {sessions?.map((s) => (
                <option key={s.task_id} value={s.task_id} className="bg-panel">
                  {s.filename} ({s.status})
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={refreshAll}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-white/5 hover:bg-white/10 border border-border text-white rounded text-xs transition-colors cursor-pointer font-mono"
          >
            <RefreshCw size={13} className="text-accent" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-border">
        <button
          onClick={() => setActiveTab('loss')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors cursor-pointer ${
            activeTab === 'loss'
              ? 'border-accent text-accent bg-accent/5'
              : 'border-transparent text-muted hover:text-white'
          }`}
        >
          <TrendingDown size={14} />
          <span>Data-Loss Monitoring (Priority 1)</span>
        </button>

        <button
          onClick={() => setActiveTab('thresholds')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors cursor-pointer ${
            activeTab === 'thresholds'
              ? 'border-accent text-accent bg-accent/5'
              : 'border-transparent text-muted hover:text-white'
          }`}
        >
          <Sliders size={14} />
          <span>Dynamic Thresholds & Flags</span>
        </button>

        <button
          onClick={() => setActiveTab('hosts')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors cursor-pointer ${
            activeTab === 'hosts'
              ? 'border-accent text-accent bg-accent/5'
              : 'border-transparent text-muted hover:text-white'
          }`}
        >
          <Server size={14} />
          <span>Multi-Host Rate Velocity</span>
        </button>

        <button
          onClick={() => setActiveTab('risk')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors cursor-pointer ${
            activeTab === 'risk'
              ? 'border-accent text-accent bg-accent/5'
              : 'border-transparent text-muted hover:text-white'
          }`}
        >
          <Percent size={14} />
          <span>% Risk Factor Breakdown</span>
        </button>

        <button
          onClick={() => setActiveTab('controlled_loss')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors cursor-pointer ${
            activeTab === 'controlled_loss'
              ? 'border-accent text-accent bg-accent/5'
              : 'border-transparent text-muted hover:text-white'
          }`}
        >
          <Zap size={14} />
          <span>Controlled Loss & Recovery</span>
        </button>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: DATA-LOSS MONITORING                                               */}
      {/* ========================================================================= */}
      {activeTab === 'loss' && (
        <div className="space-y-6">
          {/* Metric Cards (Styled identically to Overview.tsx MetricCard) */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted uppercase tracking-wider">MEASUREMENT STATUS</span>
                <Activity size={15} className="text-accent" />
              </div>
              <div className="mt-1">
                <RiskBadge value={lossData?.measurement_status || 'UNAVAILABLE'} />
              </div>
              <div className="text-xs text-muted mt-2">
                {lossData?.measurement_status === 'CONFIRMED'
                  ? 'Deterministic sequence verification active'
                  : lossData?.measurement_status === 'INFERRED'
                  ? 'Inferred via TCP retransmission tracking'
                  : 'Untagged traffic continuous monitoring'}
              </div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted uppercase tracking-wider">TOTAL PACKETS</span>
                <Layers size={15} className="text-blue-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-white">
                {lossData?.total_packets_received?.toLocaleString() || 0}
                <span className="text-sm font-normal text-muted ml-1">
                  / {lossData?.total_packets_expected ? lossData.total_packets_expected.toLocaleString() : 'N/A'}
                </span>
              </div>
              <div className="text-xs text-muted mt-1">
                Lost Packets:{' '}
                <span
                  className={`font-mono font-semibold ${
                    (lossData?.total_packets_lost || 0) > 0 ? 'text-danger' : 'text-success'
                  }`}
                >
                  {lossData?.total_packets_lost !== null && lossData?.total_packets_lost !== undefined
                    ? lossData.total_packets_lost.toLocaleString()
                    : '0'}
                </span>
              </div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted uppercase tracking-wider">OVERALL PACKET LOSS</span>
                <TrendingDown
                  size={15}
                  className={
                    (lossData?.overall_loss_percentage || 0) > 10
                      ? 'text-danger'
                      : (lossData?.overall_loss_percentage || 0) > 2
                      ? 'text-warning'
                      : 'text-success'
                  }
                />
              </div>
              <div
                className={`text-2xl font-bold font-mono ${
                  (lossData?.overall_loss_percentage || 0) > 10
                    ? 'text-danger'
                    : (lossData?.overall_loss_percentage || 0) > 2
                    ? 'text-warning'
                    : 'text-success'
                }`}
              >
                {lossData?.overall_loss_percentage !== null && lossData?.overall_loss_percentage !== undefined
                  ? `${lossData.overall_loss_percentage.toFixed(2)}%`
                  : '0.00%'}
              </div>
              <div className="text-xs text-muted mt-1">Threshold: 2.0% (Warning) | 10.0% (Critical)</div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted uppercase tracking-wider">MISSING TRANSMISSION</span>
                <HardDrive
                  size={15}
                  className={(lossData?.estimated_missing_bytes || 0) > 0 ? 'text-danger' : 'text-muted'}
                />
              </div>
              <div className="text-2xl font-bold font-mono text-white">
                {fmtBytes(lossData?.estimated_missing_bytes || 0)}
              </div>
              <div className="text-xs text-muted mt-1">
                Received: <span className="font-mono text-gray-300">{fmtBytes(lossData?.data_volume_received_bytes || 0)}</span>
              </div>
            </div>
          </div>

          {/* Active Transmission Loss Alerts (Styled like Recent Events in Overview.tsx) */}
          {lossData?.data_loss_alerts && lossData.data_loss_alerts.length > 0 && (
            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="text-danger" size={16} />
                  <h2 className="text-sm font-semibold text-white">Active Transmission Loss Alerts</h2>
                </div>
                <span className="text-xs text-muted font-mono">{lossData.data_loss_alerts.length} active alerts</span>
              </div>
              <div className="space-y-2">
                {lossData.data_loss_alerts.map((al, idx) => {
                  const isObj = typeof al === 'object' && al !== null
                  const alertProto = (isObj && al.protocol ? String(al.protocol).trim() : '') || 'TCP'
                  const alertTitle =
                    (isObj ? (al as any).title || al.metric || (al as any).name : null) ||
                    (typeof al === 'string' ? al : 'Transmission Loss Anomaly')
                  const alertDesc = (isObj ? (al as any).detail || al.message || (al as any).description : null) || ''
                  const alertSeverity = (isObj && al.severity ? String(al.severity).toUpperCase() : '') || 'CRITICAL'
                  return (
                    <div
                      key={idx}
                      className="flex items-start justify-between bg-bg border border-border/60 rounded p-3 text-xs"
                    >
                      <div className="space-y-1">
                        <div className="font-semibold text-white">
                          <span className="text-accent font-mono mr-1.5">[{alertProto}]</span>
                          {alertTitle}
                        </div>
                        {alertDesc && <p className="text-xs text-gray-300 leading-relaxed">{alertDesc}</p>}
                      </div>
                      <div className="ml-3 shrink-0">
                        <RiskBadge value={alertSeverity} />
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Protocol-Wise Breakdown Table */}
          <div className="bg-panel border border-border rounded-lg p-4">
            <h2 className="text-sm font-semibold text-white mb-3">Protocol-Specific Transmission Telemetry</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="border-b border-border text-muted font-mono uppercase tracking-wider text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3">Protocol</th>
                    <th className="py-2.5 px-3">Packets Observed</th>
                    <th className="py-2.5 px-3">Expected</th>
                    <th className="py-2.5 px-3">Lost / Missing</th>
                    <th className="py-2.5 px-3">Loss %</th>
                    <th className="py-2.5 px-3">Retransmissions</th>
                    <th className="py-2.5 px-3">Sequence Gaps</th>
                    <th className="py-2.5 px-3">Throughput (PPS / BPS)</th>
                    <th className="py-2.5 px-3">Measurement Status</th>
                    <th className="py-2.5 px-3">Diagnostic Anomalies</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {lossData?.protocols && Object.keys(lossData.protocols).length > 0 ? (
                    Object.entries(lossData.protocols).map(([proto, met]) => (
                      <tr key={proto} className="hover:bg-white/5 transition-colors">
                        <td className="py-2.5 px-3 font-mono font-bold text-accent">{proto}</td>
                        <td className="py-2.5 px-3 font-mono text-white">{met.packets_observed.toLocaleString()}</td>
                        <td className="py-2.5 px-3 font-mono text-muted">
                          {met.expected_packets !== null ? met.expected_packets.toLocaleString() : '—'}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-danger font-semibold">
                          {met.lost_packets !== null ? met.lost_packets.toLocaleString() : '—'}
                        </td>
                        <td className="py-2.5 px-3 font-mono font-bold">
                          {met.loss_percentage !== null ? (
                            <span className={met.loss_percentage > 2 ? 'text-warning' : 'text-success'}>
                              {met.loss_percentage.toFixed(2)}%
                            </span>
                          ) : (
                            <span className="text-muted">N/A</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-white">{met.retransmissions}</td>
                        <td className="py-2.5 px-3 font-mono text-white">{met.sequence_gaps}</td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-muted">
                          {met.pps.toFixed(1)} pps · {fmtBytes(met.bps)}/s
                        </td>
                        <td className="py-2.5 px-3">
                          <RiskBadge value={met.measurement_status} />
                        </td>
                        <td className="py-2.5 px-3 text-xs">
                          {met.associated_anomalies && met.associated_anomalies.length > 0 ? (
                            <span className="text-warning leading-relaxed">{met.associated_anomalies.join(', ')}</span>
                          ) : (
                            <span className="text-success font-medium">Clean continuity</span>
                          )}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={10} className="py-6 text-center text-muted font-mono">
                        No protocol telemetry recorded for this session.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Loss Timeline Trend Chart */}
          {lossData?.timeline_loss_trend && lossData.timeline_loss_trend.length > 0 && (
            <div className="bg-panel border border-border rounded-lg p-4">
              <h2 className="text-sm font-semibold text-white mb-3">Transmission Degradation Timeline</h2>
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={lossData.timeline_loss_trend}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1c1c1c" />
                  <XAxis dataKey="timestamp" tick={{ fill: '#71717a', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#71717a', fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{
                      background: '#080808',
                      border: '1px solid #1c1c1c',
                      borderRadius: 6,
                      fontSize: 12,
                      color: '#fff',
                    }}
                  />
                  <Legend />
                  <Line type="monotone" dataKey="packets_received" stroke="#3b82f6" name="Received Pkts" dot={false} strokeWidth={2} />
                  <Line type="monotone" dataKey="lost_packets" stroke="#ef4444" name="Lost Pkts" dot={false} strokeWidth={2} />
                  <Line type="monotone" dataKey="retransmissions" stroke="#f59e0b" name="Retransmissions" dot={false} strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: DYNAMIC THRESHOLDS & ADAPTIVE FLAGS                                */}
      {/* ========================================================================= */}
      {activeTab === 'thresholds' && (
        <div className="space-y-6">
          {/* Contamination Protection Status */}
          <div className="bg-panel border border-border rounded-lg p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded bg-accent/20 flex items-center justify-center">
                <Shield className="text-accent" size={20} />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <span>Contamination Protection Engine</span>
                  <RiskBadge value="ACTIVE" />
                </h3>
                <p className="text-xs text-muted mt-0.5">
                  Empirical baselines filter out malicious or anomalous packet spikes so adversarial bursts cannot shift normal distribution parameters.
                </p>
              </div>
            </div>
            <div className="text-xs text-muted font-mono bg-bg px-3 py-1.5 rounded border border-border">
              Adaptive Baseline Mode: Two-Pass Trimmed &amp; Winsorized
            </div>
          </div>

          {/* Active Dynamic Anomaly Flags Table */}
          <div className="bg-panel border border-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-white">Active Dynamic Anomaly Flags</h2>
              <span className="text-xs text-muted font-mono">
                {thresholdData?.active_flags?.length || 0} anomaly events flagged
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="border-b border-border text-muted font-mono uppercase tracking-wider text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3">Category</th>
                    <th className="py-2.5 px-3">Associated Host</th>
                    <th className="py-2.5 px-3">Observed</th>
                    <th className="py-2.5 px-3">Baseline</th>
                    <th className="py-2.5 px-3">Threshold</th>
                    <th className="py-2.5 px-3">Deviation %</th>
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3">Confidence</th>
                    <th className="py-2.5 px-3">Diagnostic Explanation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {thresholdData?.active_flags && thresholdData.active_flags.length > 0 ? (
                    thresholdData.active_flags.map((flag, idx) => (
                      <tr key={idx} className="hover:bg-white/5 transition-colors">
                        <td className="py-2.5 px-3 font-semibold text-white">{flag.anomaly_category}</td>
                        <td className="py-2.5 px-3 font-mono text-accent">
                          <span className="bg-bg px-2 py-0.5 rounded border border-border/60">
                            {flag.associated_host || '—'}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono font-bold text-white">
                          {(flag.observed_value ?? 0).toFixed(2)}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-muted">
                          {(flag.expected_baseline ?? 0).toFixed(2)}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-muted">
                          {(flag.current_threshold ?? 0).toFixed(2)}
                        </td>
                        <td className="py-2.5 px-3 font-mono font-bold text-danger">
                          +{(flag.deviation_percentage ?? 0).toFixed(1)}%
                        </td>
                        <td className="py-2.5 px-3">
                          <RiskBadge value={flag.severity || 'LOW'} />
                        </td>
                        <td className="py-2.5 px-3 font-mono text-white">{(flag.confidence ?? 0).toFixed(0)}%</td>
                        <td className="py-2.5 px-3 text-xs text-gray-300 leading-relaxed">
                          {flag.detection_explanation || '—'}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={9} className="py-6 text-center text-muted font-mono">
                        No dynamic threshold violations in this session.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Statistical Baselines and Categories */}
          <div className="bg-panel border border-border rounded-lg p-4">
            <h2 className="text-sm font-semibold text-white mb-3">Adaptive Anomaly Thresholds Matrix (12 Categories)</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {thresholdData?.thresholds && Object.keys(thresholdData.thresholds).length > 0 ? (
                Object.entries(thresholdData.thresholds).map(([cat, bounds]) => (
                  <div key={cat} className="p-3.5 bg-bg border border-border/70 rounded-lg space-y-2">
                    <div className="text-xs font-mono font-semibold text-accent uppercase tracking-wider truncate">
                      {cat}
                    </div>
                    <div className="grid grid-cols-3 gap-1.5">
                      <div className="bg-panel/80 p-2 rounded border border-border/40 text-center">
                        <div className="text-muted text-[10px] uppercase font-mono tracking-wider">LOW</div>
                        <div className="font-mono text-xs text-white font-bold mt-0.5">
                          {bounds.LOW !== undefined ? bounds.LOW.toFixed(1) : '—'}
                        </div>
                      </div>
                      <div className="bg-panel/80 p-2 rounded border border-border/40 text-center">
                        <div className="text-muted text-[10px] uppercase font-mono tracking-wider">MED</div>
                        <div className="font-mono text-xs text-warning font-bold mt-0.5">
                          {bounds.MEDIUM !== undefined ? bounds.MEDIUM.toFixed(1) : '—'}
                        </div>
                      </div>
                      <div className="bg-panel/80 p-2 rounded border border-border/40 text-center">
                        <div className="text-muted text-[10px] uppercase font-mono tracking-wider">CRIT</div>
                        <div className="font-mono text-xs text-danger font-bold mt-0.5">
                          {bounds.CRITICAL !== undefined ? bounds.CRITICAL.toFixed(1) : '—'}
                        </div>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-xs text-muted col-span-3 font-mono">Statistical baselines initializing...</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: MULTI-HOST RATE VELOCITY                                           */}
      {/* ========================================================================= */}
      {activeTab === 'hosts' && (
        <div className="space-y-6">
          {/* Rate Overview Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted uppercase tracking-wider">OVERALL PPS</span>
                <Activity size={15} className="text-accent" />
              </div>
              <div className="text-2xl font-bold font-mono text-accent">
                {rateData?.overall_pps?.toFixed(1) || 0}
                <span className="text-xs text-muted font-normal ml-1">pkts/s</span>
              </div>
              <div className="text-xs text-muted mt-1">Aggregate packet frequency</div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted uppercase tracking-wider">OVERALL BPS</span>
                <TrendingUp size={15} className="text-blue-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-blue-400">
                {fmtBytes(rateData?.overall_bps || 0)}/s
              </div>
              <div className="text-xs text-muted mt-1">Network wire throughput</div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted uppercase tracking-wider">INBOUND TRANSFER</span>
                <ArrowDownRight size={15} className="text-green-400" />
              </div>
              <div className="text-xl font-bold font-mono text-white">
                {rateData?.inbound_pps?.toFixed(1) || 0} pps
              </div>
              <div className="text-xs text-muted mt-0.5">{fmtBytes(rateData?.inbound_bps || 0)}/s</div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted uppercase tracking-wider">OUTBOUND TRANSFER</span>
                <ArrowUpRight size={15} className="text-orange-400" />
              </div>
              <div className="text-xl font-bold font-mono text-white">
                {rateData?.outbound_pps?.toFixed(1) || 0} pps
              </div>
              <div className="text-xs text-muted mt-0.5">{fmtBytes(rateData?.outbound_bps || 0)}/s</div>
            </div>
          </div>

          {/* Multi-Host Activity Cards */}
          <div className="bg-panel border border-border rounded-lg p-4">
            <h2 className="text-sm font-semibold text-white mb-3">Multi-Host Rate Dynamics &amp; Directional Velocity</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {rateData?.host_rates && rateData.host_rates.length > 0 ? (
                rateData.host_rates.map((h) => (
                  <div key={h.host_ip} className="p-4 bg-bg border border-border/80 rounded-lg space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Server size={15} className="text-accent" />
                        <span className="font-mono text-sm font-bold text-white">{h.host_ip}</span>
                        {h.host_ip === '192.168.1.10' && (
                          <span className="text-[10px] font-mono bg-accent/15 text-accent border border-accent/30 px-2 py-0.5 rounded font-semibold uppercase">
                            PRIMARY SERVER
                          </span>
                        )}
                      </div>
                      <RiskBadge value={h.active_anomaly ? 'HIGH' : 'NORMAL'} />
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div className="bg-panel p-2.5 rounded border border-border/40">
                        <div className="text-muted flex items-center gap-1 text-[11px] uppercase font-mono">
                          <ArrowDownRight size={12} className="text-green-400" /> Inbound
                        </div>
                        <div className="text-white font-mono font-semibold mt-1">
                          {h.packets_in.toLocaleString()} pkts ({fmtBytes(h.bytes_in)})
                        </div>
                        <div className="text-[10px] font-mono text-muted mt-0.5">{h.inbound_pps.toFixed(1)} pps</div>
                      </div>

                      <div className="bg-panel p-2.5 rounded border border-border/40">
                        <div className="text-muted flex items-center gap-1 text-[11px] uppercase font-mono">
                          <ArrowUpRight size={12} className="text-blue-400" /> Outbound
                        </div>
                        <div className="text-white font-mono font-semibold mt-1">
                          {h.packets_out.toLocaleString()} pkts ({fmtBytes(h.bytes_out)})
                        </div>
                        <div className="text-[10px] font-mono text-muted mt-0.5">{h.outbound_pps.toFixed(1)} pps</div>
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-xs pt-2 border-t border-border/50 text-muted font-mono">
                      <span>Total: {h.total_packets.toLocaleString()} pkts</span>
                      <span className="text-white font-semibold">Velocity: {fmtBytes(h.bps)}/s</span>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-xs text-muted col-span-2 font-mono">No multi-host rates recorded yet.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: RISK FACTOR BREAKDOWN                                              */}
      {/* ========================================================================= */}
      {activeTab === 'risk' && (
        <div className="space-y-6">
          {/* Engine 4 Decision Correlation Card (Styled like DetectionEngines.tsx) */}
          <div className="bg-panel border border-border rounded-lg p-5">
            <div className="flex items-start justify-between mb-4">
              <div>
                <div className="text-xs text-muted font-mono mb-1">ENGINE_4_CORRELATION</div>
                <div className="text-sm font-semibold text-white">Engine 4 — Decision Correlation &amp; Unified Risk</div>
              </div>
              <RiskBadge value={riskData?.final_classification || 'BENIGN'} />
            </div>

            {/* Radial gauge + Factor Breakdown */}
            <div className="flex flex-col md:flex-row items-center gap-6 mb-4">
              <div className="relative w-28 h-28 shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <RadialBarChart
                    cx="50%"
                    cy="50%"
                    innerRadius="60%"
                    outerRadius="100%"
                    startAngle={90}
                    endAngle={-270}
                    data={radialData}
                  >
                    <RadialBar dataKey="value" cornerRadius={4} background={{ fill: '#1c1c1c' }} />
                  </RadialBarChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex items-center justify-center flex-col">
                  <span className="text-xl font-bold font-mono" style={{ color: riskColor }}>
                    {overallRisk.toFixed(1)}
                  </span>
                  <span className="text-[10px] text-muted font-mono">/ 10.0</span>
                </div>
              </div>

              {/* Factors */}
              <div className="flex-1 w-full space-y-3">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <div className="bg-bg rounded px-3 py-2 border border-border/60">
                    <div className="text-xs text-muted truncate">Primary Signal</div>
                    <div className="text-sm text-white font-mono font-bold mt-0.5">
                      {Object.values(riskData?.primary_signals || {}).length > 0
                        ? Math.max(...Object.values(riskData?.primary_signals || {})).toFixed(1)
                        : '0.0'}
                    </div>
                  </div>
                  <div className="bg-bg rounded px-3 py-2 border border-border/60">
                    <div className="text-xs text-muted truncate">Data Loss Addon</div>
                    <div className="text-sm text-accent font-mono font-bold mt-0.5">
                      +{riskData?.data_loss_contribution?.toFixed(2) || '0.00'}
                    </div>
                  </div>
                  <div className="bg-bg rounded px-3 py-2 border border-border/60">
                    <div className="text-xs text-muted truncate">Rate Surge Addon</div>
                    <div className="text-sm text-warning font-mono font-bold mt-0.5">
                      +{riskData?.traffic_rate_contribution?.toFixed(2) || '0.00'}
                    </div>
                  </div>
                  <div className="bg-bg rounded px-3 py-2 border border-border/60">
                    <div className="text-xs text-muted truncate">Multi-Host Penalty</div>
                    <div className="text-sm text-blue-400 font-mono font-bold mt-0.5">
                      +{riskData?.multi_host_contribution?.toFixed(2) || '0.00'}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4 text-xs text-muted">
                  <div>
                    Confidence:{' '}
                    <span className="text-white font-mono font-semibold">
                      {(riskData?.overall_confidence_score ?? 50).toFixed(0)}%
                    </span>
                  </div>
                  <div>
                    Classification Band:{' '}
                    <span className="text-white font-mono font-semibold">
                      {riskData?.classification_band || 'LOW'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="border-t border-border pt-3">
              <div className="text-xs text-muted mb-1">Unified Synthesis Explanation</div>
              <p className="text-xs text-gray-300 leading-relaxed">
                Aggregates the highest primary engine signal and dynamically compounds additive penalties for packet loss, anomalous throughput velocity, and multi-source attack coordination.
              </p>
            </div>
          </div>

          {/* Mathematical Audit Explanation Trail */}
          <div className="bg-panel border border-border rounded-lg p-4">
            <h2 className="text-sm font-semibold text-white mb-3">Mathematical Calculation Steps &amp; Audit Trail</h2>
            <div className="space-y-2">
              {riskData?.calculation_explanation && riskData.calculation_explanation.length > 0 ? (
                riskData.calculation_explanation.map((step, idx) => (
                  <div key={idx} className="flex items-start gap-2.5 text-xs bg-bg p-3 rounded border border-border/60">
                    <Info size={14} className="text-accent shrink-0 mt-0.5" />
                    <span className="text-gray-200 leading-relaxed">{step}</span>
                  </div>
                ))
              ) : (
                <p className="text-xs text-muted font-mono">No audit steps logged.</p>
              )}
            </div>
          </div>

          {/* Sub-Engine Scores Grid (Styled like DetectionEngines evidence) */}
          <div className="bg-panel border border-border rounded-lg p-4">
            <h2 className="text-sm font-semibold text-white mb-3">Contributing Sub-Engine Scores (12 Sub-Engines)</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {riskData?.subengine_breakdown && riskData.subengine_breakdown.length > 0 ? (
                riskData.subengine_breakdown.map((sub) => {
                  const sVal = sub.risk_score ?? 0
                  const sColor = sVal >= 7 ? 'text-danger' : sVal >= 5 ? 'text-warning' : 'text-success'
                  return (
                    <div key={sub.subengine_id} className="p-3 bg-bg border border-border/70 rounded-lg space-y-1.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-mono text-muted text-[11px]">{sub.subengine_id}</span>
                        <span className={`font-mono font-bold ${sColor}`}>{sVal.toFixed(1)}/10</span>
                      </div>
                      <div className="text-xs font-semibold text-white truncate">{sub.name}</div>
                      <div className="text-[10px] text-muted font-mono">
                        {(sub.confidence_score ?? 0).toFixed(0)}% confidence
                      </div>
                    </div>
                  )
                })
              ) : (
                <p className="text-xs text-muted col-span-4 font-mono">Run an analysis to inspect sub-engine telemetry.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 5: DYNAMIC CONTROLLED LOSS & DATA RECOVERY                            */}
      {/* ========================================================================= */}
      {activeTab === 'controlled_loss' && (
        <div className="space-y-6">
          {/* Header Banner (Clean dark panel with RiskBadge) */}
          <div className="bg-panel border border-border rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded bg-accent/15 border border-accent/30 flex items-center justify-center shrink-0">
                <Zap className="text-accent" size={20} />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <span>CONTROLLED TESTBED — Dynamic Packet Loss &amp; Multi-Protocol Recovery</span>
                  <RiskBadge value="TEST_TRAFFIC_ONLY" />
                </h3>
                <p className="text-xs text-muted mt-0.5">
                  Loss injection operates exclusively on designated test streams (PC 2: 192.168.1.52, PC 3: 192.168.1.53). Real sensor traffic is never discarded. Verified data recovery is cryptographically audited via SHA-256.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={handleResetController}
                className="px-3 py-1.5 bg-bg hover:bg-white/5 border border-border text-xs text-muted hover:text-white rounded transition-colors font-mono cursor-pointer"
              >
                Reset Testbed
              </button>
            </div>
          </div>

          {/* Interactive Test Configuration & Simulation Controls */}
          <div className="bg-panel border border-border rounded-lg p-4 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-3 border-b border-border">
              <div>
                <h2 className="text-sm font-semibold text-white">Controlled Loss Injection &amp; Recovery Controls</h2>
                <p className="text-xs text-muted">Configure loss rate, injection model, and target sources for PC 2 &amp; PC 3 test runs.</p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleRunSimulation}
                  disabled={isSimulating}
                  className="flex items-center gap-2 px-4 py-2 bg-accent/20 hover:bg-accent/30 text-accent border border-accent/40 rounded text-xs font-semibold font-mono tracking-wide transition-colors cursor-pointer disabled:opacity-50"
                >
                  <Zap size={14} className={isSimulating ? 'animate-spin' : ''} />
                  <span>{isSimulating ? 'Executing Testbed...' : 'Run Multi-PC Loss & Recovery Simulation'}</span>
                </button>
              </div>
            </div>

            {/* Parameter Selectors */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              {/* 1. Loss Percentage */}
              <div>
                <label className="text-xs text-muted block mb-1.5 font-mono uppercase tracking-wider text-[11px]">Loss Percentage</label>
                <div className="grid grid-cols-5 gap-1">
                  {[0, 1, 5, 10, 25].map((pct) => (
                    <button
                      key={pct}
                      type="button"
                      onClick={() => setLossPct(pct)}
                      className={`py-1.5 text-xs font-mono font-bold rounded transition-colors cursor-pointer border ${
                        lossPct === pct
                          ? 'bg-accent text-white border-accent shadow-sm'
                          : 'bg-bg border-border text-muted hover:text-white'
                      }`}
                    >
                      {pct}%
                    </button>
                  ))}
                </div>
              </div>

              {/* 2. Loss Mode */}
              <div>
                <label className="text-xs text-muted block mb-1.5 font-mono uppercase tracking-wider text-[11px]">Loss Injection Model</label>
                <select
                  value={lossMode}
                  onChange={(e) => setLossMode(e.target.value)}
                  className="w-full bg-bg border border-border rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-accent"
                >
                  <option value="DETERMINISTIC" className="bg-panel">DETERMINISTIC (Exact 1-in-N)</option>
                  <option value="RANDOM" className="bg-panel">RANDOM (Bernoulli i.i.d.)</option>
                  <option value="BURST" className="bg-panel">BURST (Gilbert-Elliott Markov)</option>
                </select>
              </div>

              {/* 3. Burst Length (if burst mode) */}
              <div>
                <label className="text-xs text-muted block mb-1.5 font-mono uppercase tracking-wider text-[11px]">Burst Packet Length</label>
                <input
                  type="number"
                  min={1}
                  max={20}
                  value={burstLen}
                  onChange={(e) => setBurstLen(parseInt(e.target.value) || 1)}
                  disabled={lossMode !== 'BURST'}
                  className="w-full bg-bg border border-border rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-accent disabled:opacity-40"
                />
              </div>

              {/* 4. Target Source Filtering */}
              <div>
                <label className="text-xs text-muted block mb-1.5 font-mono uppercase tracking-wider text-[11px]">Target Senders</label>
                <select
                  value={targetSource}
                  onChange={(e) => setTargetSource(e.target.value)}
                  className="w-full bg-bg border border-border rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-accent"
                >
                  <option value="BOTH" className="bg-panel">Both PC 2 (TCP) &amp; PC 3 (UDP)</option>
                  <option value="PC2" className="bg-panel">PC 2 Only (192.168.1.52 - TCP)</option>
                  <option value="PC3" className="bg-panel">PC 3 Only (192.168.1.53 - UDP)</option>
                </select>
              </div>
            </div>

            {simMessage && (
              <div className="p-3 bg-bg border border-accent/40 rounded text-xs text-accent flex items-center gap-2 font-mono">
                <Info size={14} className="shrink-0" />
                <span>{simMessage}</span>
              </div>
            )}
          </div>

          {/* Metric Cards Grid (6 Clean Cards) */}
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
            <div className="bg-panel border border-border rounded-lg p-3.5">
              <div className="text-[11px] text-muted uppercase font-mono tracking-wider">CONFIGURED LOSS</div>
              <div className="text-xl font-bold font-mono text-white mt-1">
                {lossControlMetrics?.configured_loss_pct ?? lossPct}%
              </div>
              <div className="text-[10px] text-muted mt-1 font-mono">Mode: {lossControlMetrics?.loss_mode ?? lossMode}</div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-3.5">
              <div className="text-[11px] text-muted uppercase font-mono tracking-wider">DETECTED LOSSES</div>
              <div className="text-xl font-bold font-mono text-danger mt-1">
                {lossControlMetrics?.total_losses_detected ?? 0}
                <span className="text-xs text-muted font-normal ml-1">pkts</span>
              </div>
              <div className="text-[10px] text-muted mt-1 font-mono">Sequence gaps</div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-3.5">
              <div className="text-[11px] text-muted uppercase font-mono tracking-wider">VERIFIED RECOVERED</div>
              <div className="text-xl font-bold font-mono text-success mt-1">
                {lossControlMetrics?.total_recovered_packets ?? 0}
                <span className="text-xs text-muted font-normal ml-1">pkts</span>
              </div>
              <div className="text-[10px] text-success font-semibold mt-1 font-mono">
                {lossControlMetrics?.recovery_rate_pct ?? 100}% rate
              </div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-3.5">
              <div className="text-[11px] text-muted uppercase font-mono tracking-wider">UNRECOVERED</div>
              <div className="text-xl font-bold font-mono text-warning mt-1">
                {lossControlMetrics?.total_unrecovered_packets ?? 0}
                <span className="text-xs text-muted font-normal ml-1">pkts</span>
              </div>
              <div className="text-[10px] text-muted mt-1 font-mono">Reported honestly</div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-3.5">
              <div className="text-[11px] text-muted uppercase font-mono tracking-wider">MEAN LATENCY</div>
              <div className="text-xl font-bold font-mono text-white mt-1">
                {(lossControlMetrics?.mean_recovery_latency_ms ?? 0).toFixed(1)}
                <span className="text-xs text-muted font-normal ml-1">ms</span>
              </div>
              <div className="text-[10px] text-muted mt-1 font-mono">Detection to recovery</div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-3.5">
              <div className="text-[11px] text-muted uppercase font-mono tracking-wider">BUFFER MEMORY</div>
              <div className="text-xl font-bold font-mono text-accent mt-1">
                {lossControlMetrics?.buffer_utilization_pct?.toFixed(1) ?? '0.0'}%
              </div>
              <div className="text-[10px] text-muted mt-1 font-mono">
                Drops: <span className="text-white font-bold">{lossControlMetrics?.buffer_overflow_drops ?? 0}</span>
              </div>
            </div>
          </div>

          {/* Cryptographic Recovery Audit & Verification Log */}
          <div className="bg-panel border border-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h2 className="text-sm font-semibold text-white">Cryptographic Recovery Verification Log</h2>
                <p className="text-xs text-muted">
                  SHA-256 payload checksum validation. Never labels guessed or reconstructed data as authentic without verification.
                </p>
              </div>
              <span className="text-xs text-muted font-mono">
                {recoveryHistoryData?.recovery_records?.length ?? 0} operations recorded
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="border-b border-border text-muted font-mono uppercase tracking-wider text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3">Seq #</th>
                    <th className="py-2.5 px-3">Protocol</th>
                    <th className="py-2.5 px-3">Sender IP</th>
                    <th className="py-2.5 px-3">Target IP</th>
                    <th className="py-2.5 px-3">Recovery Method</th>
                    <th className="py-2.5 px-3">Latency</th>
                    <th className="py-2.5 px-3">Payload Size</th>
                    <th className="py-2.5 px-3">Integrity Validation Status</th>
                    <th className="py-2.5 px-3">Checksum / Hash (SHA-256)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {recoveryHistoryData?.recovery_records && recoveryHistoryData.recovery_records.length > 0 ? (
                    recoveryHistoryData.recovery_records.slice(0, 15).map((rec, idx) => (
                      <tr key={idx} className="hover:bg-white/5 transition-colors">
                        <td className="py-2.5 px-3 font-mono text-accent font-bold">#{rec.seq_num}</td>
                        <td className="py-2.5 px-3 font-mono font-bold text-white">{rec.protocol}</td>
                        <td className="py-2.5 px-3 font-mono text-gray-300">
                          <span className="bg-bg px-2 py-0.5 rounded border border-border/60">{rec.src_ip}</span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-gray-300">
                          <span className="bg-bg px-2 py-0.5 rounded border border-border/60">{rec.dst_ip}</span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-xs text-muted">
                          <span className="px-2 py-0.5 rounded bg-bg border border-border/60 text-accent font-semibold">
                            {rec.recovery_method}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-white">{rec.recovery_latency_ms.toFixed(1)} ms</td>
                        <td className="py-2.5 px-3 font-mono text-muted">{rec.payload_bytes} B</td>
                        <td className="py-2.5 px-3">
                          <RiskBadge value={rec.validation_status} />
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-gray-400">
                          <span className="bg-bg px-2 py-0.5 rounded border border-border/60 max-w-[200px] truncate block">
                            {rec.checksum_actual || '—'}
                          </span>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={9} className="py-6 text-center text-muted font-mono">
                        No controlled recovery events recorded yet. Click "Run Multi-PC Loss &amp; Recovery Simulation" above to execute.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Detected Sequence Loss Intervals Log */}
          <div className="bg-panel border border-border rounded-lg p-4">
            <h2 className="text-sm font-semibold text-white mb-1">Detected Sequence Loss Intervals (Isolated Sensor View)</h2>
            <p className="text-xs text-muted mb-3">Distinguishes network transport drops from buffer overflow and sensor capture drops.</p>

            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="border-b border-border text-muted font-mono uppercase tracking-wider text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3">Seq #</th>
                    <th className="py-2.5 px-3">Protocol</th>
                    <th className="py-2.5 px-3">Source Endpoint</th>
                    <th className="py-2.5 px-3">Loss Classification</th>
                    <th className="py-2.5 px-3">Waiting Window</th>
                    <th className="py-2.5 px-3">Confirmed Loss</th>
                    <th className="py-2.5 px-3">Estimated Size</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {recoveryHistoryData?.loss_detected_events && recoveryHistoryData.loss_detected_events.length > 0 ? (
                    recoveryHistoryData.loss_detected_events.slice(0, 10).map((evt, idx) => (
                      <tr key={idx} className="hover:bg-white/5 transition-colors">
                        <td className="py-2.5 px-3 font-mono text-white font-bold">#{evt.seq_num}</td>
                        <td className="py-2.5 px-3 font-mono font-bold text-white">{evt.protocol}</td>
                        <td className="py-2.5 px-3 font-mono text-muted">
                          <span className="bg-bg px-2 py-0.5 rounded border border-border/60">{evt.src_ip}</span>
                        </td>
                        <td className="py-2.5 px-3">
                          <RiskBadge value={evt.loss_type} />
                        </td>
                        <td className="py-2.5 px-3 font-mono text-muted">{evt.waiting_window_ms} ms (jitter buffer)</td>
                        <td className="py-2.5 px-3">
                          <span className="text-success font-semibold font-mono text-xs">CONFIRMED</span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-white">{evt.payload_bytes} B</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={7} className="py-6 text-center text-muted font-mono">
                        No sequence drop intervals registered.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
