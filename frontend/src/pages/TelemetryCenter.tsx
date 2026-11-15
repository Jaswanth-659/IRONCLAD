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
} from 'lucide-react'
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import { useApi } from '../hooks/useApi'
import { useWebSocket } from '../hooks/useWebSocket'
import RiskBadge from '../components/RiskBadge'
import type {
  DataLossReport,
  DynamicThresholdsData,
  TrafficRatesData,
  RiskFactorData,
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
  const [activeTab, setActiveTab] = useState<'loss' | 'thresholds' | 'hosts' | 'risk'>('loss')

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

  // Listen for WebSocket completion
  useEffect(() => {
    const t = String(lastMessage?.type ?? '').toUpperCase()
    if (t === 'ANALYSIS_COMPLETED' || t === 'ANALYSIS_COMPLETE') {
      void refetchSessions()
      void refetchLoss()
      void refetchThresh()
      void refetchRates()
      void refetchRisk()
    }
  }, [lastMessage, refetchSessions, refetchLoss, refetchThresh, refetchRates, refetchRisk])

  const refreshAll = () => {
    void refetchSessions()
    void refetchLoss()
    void refetchThresh()
    void refetchRates()
    void refetchRisk()
  }

  // Format helper
  const fmtBytes = (bytes: number) => {
    if (!bytes || bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
  }

  return (
    <div className="p-6 space-y-6">
      {/* Top Banner / Navigation */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Gauge className="text-accent" size={22} />
            <h1 className="text-lg font-semibold text-white tracking-wide">
              Network Telemetry & Data-Loss Intelligence
            </h1>
          </div>
          <p className="text-xs text-muted mt-1">
            Real-time packet transmission integrity, adaptive empirical baselines, and transparent risk mathematics
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Session Selector */}
          <div className="flex items-center gap-2 bg-panel border border-border rounded px-3 py-1.5 text-xs">
            <Database size={13} className="text-muted" />
            <span className="text-muted">PCAP Session:</span>
            <select
              value={selectedSession}
              onChange={(e) => setSelectedSession(e.target.value)}
              className="bg-transparent text-white font-mono focus:outline-none cursor-pointer max-w-[200px] truncate"
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
            className="flex items-center gap-1.5 px-3 py-1.5 bg-accent/10 border border-accent/30 text-accent rounded text-xs hover:bg-accent/20 transition-colors"
          >
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-border">
        <button
          onClick={() => setActiveTab('loss')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
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
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
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
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
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
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
            activeTab === 'risk'
              ? 'border-accent text-accent bg-accent/5'
              : 'border-transparent text-muted hover:text-white'
          }`}
        >
          <Percent size={14} />
          <span>Risk Factor Breakdown</span>
        </button>
      </div>

      {/* TAB 1: DATA-LOSS MONITORING */}
      {activeTab === 'loss' && (
        <div className="space-y-6">
          {/* Top High-Priority Integrity Banner */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="text-xs text-muted">Measurement Status</div>
              <div className="flex items-center gap-2 mt-2">
                <span
                  className={`inline-flex items-center px-2.5 py-1 rounded text-xs font-bold ${
                    lossData?.measurement_status === 'CONFIRMED'
                      ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                      : lossData?.measurement_status === 'INFERRED'
                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
                  }`}
                >
                  {lossData?.measurement_status || 'UNAVAILABLE'}
                </span>
              </div>
              <div className="text-[11px] text-muted mt-2">
                {lossData?.measurement_status === 'CONFIRMED'
                  ? 'Deterministic sequence verification active.'
                  : lossData?.measurement_status === 'INFERRED'
                  ? 'Calculated from TCP retransmissions & gaps.'
                  : 'Untagged traffic; no confirmed loss fabricated.'}
              </div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="text-xs text-muted">Packets: Expected vs Received</div>
              <div className="text-xl font-bold text-white mt-1">
                {lossData?.total_packets_received?.toLocaleString() || 0}
                <span className="text-xs text-muted font-normal ml-1">
                  / {lossData?.total_packets_expected ? lossData.total_packets_expected.toLocaleString() : 'N/A'}
                </span>
              </div>
              <div className="text-xs text-muted mt-1">
                Lost Packets:{' '}
                <span className="text-danger font-semibold">
                  {lossData?.total_packets_lost !== null && lossData?.total_packets_lost !== undefined
                    ? lossData.total_packets_lost.toLocaleString()
                    : 'N/A'}
                </span>
              </div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="text-xs text-muted">Overall Packet Loss %</div>
              <div className="flex items-baseline gap-2 mt-1">
                <span
                  className={`text-2xl font-bold ${
                    (lossData?.overall_loss_percentage || 0) > 10
                      ? 'text-danger'
                      : (lossData?.overall_loss_percentage || 0) > 2
                      ? 'text-warning'
                      : 'text-success'
                  }`}
                >
                  {lossData?.overall_loss_percentage !== null && lossData?.overall_loss_percentage !== undefined
                    ? `${lossData.overall_loss_percentage.toFixed(2)}%`
                    : 'N/A'}
                </span>
                <span className="text-[11px] text-muted">loss ratio</span>
              </div>
              <div className="text-xs text-muted mt-1">
                Threshold: 2.0% (Warning) | 10.0% (Critical)
              </div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="text-xs text-muted">Missing Transmission Volume</div>
              <div className="text-xl font-bold text-white mt-1">
                {fmtBytes(lossData?.estimated_missing_bytes || 0)}
              </div>
              <div className="text-xs text-muted mt-1">
                Received: {fmtBytes(lossData?.data_volume_received_bytes || 0)}
              </div>
            </div>
          </div>

          {/* Active Data Loss Alerts */}
          {lossData?.data_loss_alerts && lossData.data_loss_alerts.length > 0 && (
            <div className="bg-danger/10 border border-danger/30 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <ShieldAlert className="text-danger" size={18} />
                <span className="text-sm font-semibold text-danger">Active Transmission Loss Alerts</span>
              </div>
              <div className="space-y-2">
                {lossData.data_loss_alerts.map((al, idx) => (
                  <div key={idx} className="flex items-start justify-between text-xs bg-black/20 p-2.5 rounded border border-danger/20">
                    <div>
                      <span className="font-semibold text-white mr-2">[{al.protocol}] {al.metric}:</span>
                      <span className="text-muted">{al.message}</span>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-danger/20 text-danger border border-danger/30">
                      {al.severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Protocol-Wise Breakdown Table */}
          <div className="bg-panel border border-border rounded-lg p-4">
            <h2 className="text-sm font-medium text-white mb-3">Protocol-Specific Transmission Telemetry</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="border-b border-border text-muted">
                  <tr>
                    <th className="py-2 px-3">Protocol</th>
                    <th className="py-2 px-3">Packets Observed</th>
                    <th className="py-2 px-3">Expected</th>
                    <th className="py-2 px-3">Lost / Missing</th>
                    <th className="py-2 px-3">Loss %</th>
                    <th className="py-2 px-3">Retransmissions</th>
                    <th className="py-2 px-3">Sequence Gaps</th>
                    <th className="py-2 px-3">Throughput (PPS / BPS)</th>
                    <th className="py-2 px-3">Measurement Status</th>
                    <th className="py-2 px-3">Anomalies</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {lossData?.protocols && Object.keys(lossData.protocols).length > 0 ? (
                    Object.entries(lossData.protocols).map(([proto, met]) => (
                      <tr key={proto} className="hover:bg-white/5 transition-colors">
                        <td className="py-2.5 px-3 font-semibold text-accent">{proto}</td>
                        <td className="py-2.5 px-3">{met.packets_observed.toLocaleString()}</td>
                        <td className="py-2.5 px-3">{met.expected_packets !== null ? met.expected_packets.toLocaleString() : '—'}</td>
                        <td className="py-2.5 px-3 text-danger font-medium">
                          {met.lost_packets !== null ? met.lost_packets.toLocaleString() : '—'}
                        </td>
                        <td className="py-2.5 px-3 font-bold">
                          {met.loss_percentage !== null ? (
                            <span className={met.loss_percentage > 2 ? 'text-warning' : 'text-success'}>
                              {met.loss_percentage.toFixed(2)}%
                            </span>
                          ) : (
                            <span className="text-muted">N/A</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3">{met.retransmissions}</td>
                        <td className="py-2.5 px-3">{met.sequence_gaps}</td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-muted">
                          {met.pps.toFixed(1)} pps · {fmtBytes(met.bps)}/s
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                              met.measurement_status === 'CONFIRMED'
                                ? 'bg-blue-500/20 text-blue-400'
                                : met.measurement_status === 'INFERRED'
                                ? 'bg-amber-500/20 text-amber-400'
                                : 'bg-gray-500/20 text-gray-400'
                            }`}
                          >
                            {met.measurement_status}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-muted">
                          {met.associated_anomalies && met.associated_anomalies.length > 0 ? (
                            <span className="text-warning">{met.associated_anomalies.join(', ')}</span>
                          ) : (
                            <span className="text-success">Clean continuity</span>
                          )}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={10} className="py-4 text-center text-muted">
                        No protocol data recorded for this session.
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
              <h2 className="text-sm font-medium text-white mb-3">Transmission Degradation Timeline</h2>
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={lossData.timeline_loss_trend}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2a3a" />
                  <XAxis dataKey="timestamp" tick={{ fill: '#6b7280', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} />
                  <Tooltip contentStyle={{ background: '#161b27', border: '1px solid #1e2a3a', borderRadius: 6, fontSize: 12 }} />
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

      {/* TAB 2: DYNAMIC THRESHOLDS & ADAPTIVE FLAGS */}
      {activeTab === 'thresholds' && (
        <div className="space-y-6">
          {/* Contamination Protection Status */}
          <div className="bg-panel border border-border rounded-lg p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded bg-accent/20 flex items-center justify-center">
                <Shield className="text-accent" size={20} />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">
                  Contamination Protection Engine:{' '}
                  <span className="text-success font-bold">ACTIVE</span>
                </h3>
                <p className="text-xs text-muted">
                  Empirical baselines filter out malicious or anomalous packet spikes so adversarial bursts cannot shift normal distribution parameters.
                </p>
              </div>
            </div>
            <div className="text-xs text-muted font-mono bg-black/30 px-3 py-1.5 rounded border border-border">
              Adaptive Baseline Mode: Two-Pass Trimmed & Winsorized
            </div>
          </div>

          {/* Active Dynamic Anomaly Flags Table */}
          <div className="bg-panel border border-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-medium text-white">Active Dynamic Anomaly Flags</h2>
              <span className="text-xs text-muted">
                {thresholdData?.active_flags?.length || 0} anomaly events flagged
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="border-b border-border text-muted">
                  <tr>
                    <th className="py-2 px-3">Category</th>
                    <th className="py-2 px-3">Associated Host</th>
                    <th className="py-2 px-3">Observed</th>
                    <th className="py-2 px-3">Baseline</th>
                    <th className="py-2 px-3">Threshold</th>
                    <th className="py-2 px-3">Deviation %</th>
                    <th className="py-2 px-3">Severity</th>
                    <th className="py-2 px-3">Confidence</th>
                    <th className="py-2 px-3">Diagnostic Explanation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {thresholdData?.active_flags && thresholdData.active_flags.length > 0 ? (
                    thresholdData.active_flags.map((flag, idx) => (
                      <tr key={idx} className="hover:bg-white/5 transition-colors">
                        <td className="py-2.5 px-3 font-semibold text-white">{flag.anomaly_category}</td>
                        <td className="py-2.5 px-3 font-mono text-accent">{flag.associated_host || '—'}</td>
                        <td className="py-2.5 px-3 font-bold">{(flag.observed_value ?? 0).toFixed(2)}</td>
                        <td className="py-2.5 px-3 text-muted">{(flag.expected_baseline ?? 0).toFixed(2)}</td>
                        <td className="py-2.5 px-3 text-muted">{(flag.current_threshold ?? 0).toFixed(2)}</td>
                        <td className="py-2.5 px-3 font-bold text-danger">+{(flag.deviation_percentage ?? 0).toFixed(1)}%</td>
                        <td className="py-2.5 px-3">
                          <RiskBadge value={flag.severity || 'LOW'} />
                        </td>
                        <td className="py-2.5 px-3">{(flag.confidence ?? 0).toFixed(0)}%</td>
                        <td className="py-2.5 px-3 text-muted">{flag.detection_explanation || '—'}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={9} className="py-4 text-center text-muted">
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
            <h2 className="text-sm font-medium text-white mb-3">Adaptive Anomaly Thresholds Matrix (12 Categories)</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {thresholdData?.thresholds && Object.keys(thresholdData.thresholds).length > 0 ? (
                Object.entries(thresholdData.thresholds).map(([cat, bounds]) => (
                  <div key={cat} className="p-3 bg-black/20 border border-border rounded">
                    <div className="text-xs font-semibold text-accent truncate">{cat}</div>
                    <div className="grid grid-cols-3 gap-1 mt-2 text-[11px]">
                      <div>
                        <div className="text-muted text-[10px]">LOW</div>
                        <div className="font-mono text-white">{bounds.LOW !== undefined ? bounds.LOW.toFixed(1) : '—'}</div>
                      </div>
                      <div>
                        <div className="text-muted text-[10px]">MED</div>
                        <div className="font-mono text-warning">{bounds.MEDIUM !== undefined ? bounds.MEDIUM.toFixed(1) : '—'}</div>
                      </div>
                      <div>
                        <div className="text-muted text-[10px]">CRIT</div>
                        <div className="font-mono text-danger">{bounds.CRITICAL !== undefined ? bounds.CRITICAL.toFixed(1) : '—'}</div>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-xs text-muted col-span-3">Statistical baselines initializing...</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: MULTI-HOST RATE VELOCITY */}
      {activeTab === 'hosts' && (
        <div className="space-y-6">
          {/* Rate Overview Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="text-xs text-muted">Overall Throughput (PPS)</div>
              <div className="text-xl font-bold text-accent mt-1">
                {rateData?.overall_pps?.toFixed(1) || 0}
                <span className="text-xs text-muted font-normal ml-1">pkts/s</span>
              </div>
            </div>
            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="text-xs text-muted">Overall Throughput (BPS)</div>
              <div className="text-xl font-bold text-blue-400 mt-1">
                {fmtBytes(rateData?.overall_bps || 0)}/s
              </div>
            </div>
            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="text-xs text-muted">Inbound Transfer</div>
              <div className="text-lg font-bold text-white mt-1">
                {rateData?.inbound_pps?.toFixed(1) || 0} pps
              </div>
              <div className="text-xs text-muted mt-0.5">{fmtBytes(rateData?.inbound_bps || 0)}/s</div>
            </div>
            <div className="bg-panel border border-border rounded-lg p-4">
              <div className="text-xs text-muted">Outbound Transfer</div>
              <div className="text-lg font-bold text-white mt-1">
                {rateData?.outbound_pps?.toFixed(1) || 0} pps
              </div>
              <div className="text-xs text-muted mt-0.5">{fmtBytes(rateData?.outbound_bps || 0)}/s</div>
            </div>
          </div>

          {/* Multi-Host Activity Cards */}
          <div className="bg-panel border border-border rounded-lg p-4">
            <h2 className="text-sm font-medium text-white mb-3">Multi-Host Rate Dynamics & Directional Velocity</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {rateData?.host_rates && rateData.host_rates.length > 0 ? (
                rateData.host_rates.map((h) => (
                  <div key={h.host_ip} className="p-4 bg-black/20 border border-border rounded-lg space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Server size={16} className="text-accent" />
                        <span className="font-mono text-sm font-bold text-white">{h.host_ip}</span>
                        {h.host_ip === '192.168.1.10' && (
                          <span className="text-[10px] bg-accent/20 text-accent px-2 py-0.5 rounded">
                            PRIMARY RECEIVER
                          </span>
                        )}
                      </div>
                      {h.active_anomaly ? (
                        <span className="text-[10px] bg-danger/20 text-danger border border-danger/30 px-2 py-0.5 rounded font-bold">
                          {h.active_anomaly}
                        </span>
                      ) : (
                        <span className="text-[10px] bg-success/20 text-success px-2 py-0.5 rounded">
                          NORMAL
                        </span>
                      )}
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div className="bg-panel/50 p-2 rounded">
                        <div className="text-muted flex items-center gap-1">
                          <ArrowDownRight size={12} className="text-green-400" /> Inbound
                        </div>
                        <div className="text-white font-semibold mt-1">
                          {h.packets_in.toLocaleString()} pkts ({fmtBytes(h.bytes_in)})
                        </div>
                        <div className="text-[10px] text-muted">{h.inbound_pps.toFixed(1)} pps</div>
                      </div>

                      <div className="bg-panel/50 p-2 rounded">
                        <div className="text-muted flex items-center gap-1">
                          <ArrowUpRight size={12} className="text-blue-400" /> Outbound
                        </div>
                        <div className="text-white font-semibold mt-1">
                          {h.packets_out.toLocaleString()} pkts ({fmtBytes(h.bytes_out)})
                        </div>
                        <div className="text-[10px] text-muted">{h.outbound_pps.toFixed(1)} pps</div>
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-xs pt-1 border-t border-border/50 text-muted">
                      <span>Total Packets: {h.total_packets.toLocaleString()}</span>
                      <span>Total Velocity: {fmtBytes(h.bps)}/s</span>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-xs text-muted col-span-2">No multi-host rates recorded yet.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: RISK FACTOR BREAKDOWN */}
      {activeTab === 'risk' && (
        <div className="space-y-6">
          {/* Transparent Score Banner */}
          <div className="bg-panel border border-border rounded-lg p-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <div className="text-xs text-muted">Engine 4 Decision Correlation</div>
                <div className="flex items-baseline gap-3 mt-1">
                  <span
                    className={`text-4xl font-extrabold ${
                      (riskData?.overall_risk_score || 0) >= 7
                        ? 'text-danger'
                        : (riskData?.overall_risk_score || 0) >= 5
                        ? 'text-warning'
                        : 'text-success'
                    }`}
                  >
                    {riskData?.overall_risk_score?.toFixed(1) || '0.0'}
                    <span className="text-sm font-normal text-muted">/ 10.0</span>
                  </span>
                  <RiskBadge value={riskData?.final_classification || 'BENIGN'} />
                </div>
                <div className="text-xs text-muted mt-2">
                  Confidence Score: <span className="text-white font-semibold">{riskData?.overall_confidence_score?.toFixed(0) || 50}%</span> · Classification Band: <span className="text-white font-semibold">{riskData?.classification_band || 'LOW'}</span>
                </div>
              </div>

              {/* Mathematical Factor Contributions */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs bg-black/20 p-3 rounded-lg border border-border">
                <div>
                  <div className="text-muted text-[11px]">Primary Signal</div>
                  <div className="font-bold text-white mt-1">
                    {Object.values(riskData?.primary_signals || {}).length > 0
                      ? Math.max(...Object.values(riskData?.primary_signals || {})).toFixed(1)
                      : '0.0'}
                  </div>
                </div>
                <div>
                  <div className="text-muted text-[11px]">Data Loss Addon</div>
                  <div className="font-bold text-accent mt-1">
                    +{riskData?.data_loss_contribution?.toFixed(2) || '0.00'}
                  </div>
                </div>
                <div>
                  <div className="text-muted text-[11px]">Rate Surge Addon</div>
                  <div className="font-bold text-warning mt-1">
                    +{riskData?.traffic_rate_contribution?.toFixed(2) || '0.00'}
                  </div>
                </div>
                <div>
                  <div className="text-muted text-[11px]">Multi-Host Bonus</div>
                  <div className="font-bold text-blue-400 mt-1">
                    +{riskData?.multi_host_contribution?.toFixed(2) || '0.00'}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Mathematical Audit Explanation Trail */}
          <div className="bg-panel border border-border rounded-lg p-4">
            <h2 className="text-sm font-medium text-white mb-3">Mathematical Calculation Steps & Audit Trail</h2>
            <div className="space-y-2">
              {riskData?.calculation_explanation && riskData.calculation_explanation.length > 0 ? (
                riskData.calculation_explanation.map((step, idx) => (
                  <div key={idx} className="flex items-start gap-2.5 text-xs text-muted bg-black/20 p-2.5 rounded border border-border/50">
                    <Info size={14} className="text-accent shrink-0 mt-0.5" />
                    <span className="text-gray-200">{step}</span>
                  </div>
                ))
              ) : (
                <p className="text-xs text-muted">No audit steps logged.</p>
              )}
            </div>
          </div>

          {/* Sub-Engine Scores Grid */}
          <div className="bg-panel border border-border rounded-lg p-4">
            <h2 className="text-sm font-medium text-white mb-3">Contributing Sub-Engine Scores</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {riskData?.subengine_breakdown && riskData.subengine_breakdown.length > 0 ? (
                riskData.subengine_breakdown.map((sub) => (
                  <div key={sub.subengine_id} className="p-3 bg-black/20 border border-border rounded">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-muted">{sub.subengine_id}</span>
                      <span
                        className={`font-bold ${
                          (sub.risk_score ?? 0) >= 7 ? 'text-danger' : (sub.risk_score ?? 0) >= 5 ? 'text-warning' : 'text-success'
                        }`}
                      >
                        {(sub.risk_score ?? 0).toFixed(1)}/10
                      </span>
                    </div>
                    <div className="text-xs font-semibold text-white mt-1 truncate">{sub.name}</div>
                    <div className="text-[10px] text-muted mt-1">{(sub.confidence_score ?? 0).toFixed(0)}% conf</div>
                  </div>
                ))
              ) : (
                <p className="text-xs text-muted col-span-4">Run an analysis to inspect sub-engine telemetry.</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
