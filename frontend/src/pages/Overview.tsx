import React from 'react'
import { Link } from 'react-router-dom'
import { Activity, AlertTriangle, Layers, Users, TrendingUp, ShieldAlert, ArrowRight, Gauge } from 'lucide-react'
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'
import { useApi } from '../hooks/useApi'
import { useWebSocket } from '../hooks/useWebSocket'
import MetricCard from '../components/MetricCard'
import RiskBadge from '../components/RiskBadge'
import PcapUpload from '../components/PcapUpload'
import type { DataLossReport } from '../types'

// Match actual OverviewStats Pydantic model field names
interface OverviewStatsActual {
  network_security_status: string
  total_packets_analysed: number
  total_flows: number
  active_alerts: number
  suspicious_hosts: number
  overall_risk_score: number
  final_classification: string
  risk_distribution: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number }
  timeline: Array<{ time: string; throughput_kb: number; risk_index: number; packets: number }>
  recent_events: Array<{
    id: number; timestamp: string; triggered_engine: string; severity: string
    description: string; source_ip: string; destination_ip: string
  }>
}

export default function Overview() {
  const { data, loading, refetch } = useApi<OverviewStatsActual>('/api/overview')
  const { data: lossData, refetch: refetchLoss } = useApi<DataLossReport>('/api/data-loss')
  const { lastMessage } = useWebSocket('ws://localhost:8000/ws')

  React.useEffect(() => {
    const t = String(lastMessage?.type ?? '').toUpperCase()
    if (t === 'ANALYSIS_COMPLETED' || t === 'ANALYSIS_COMPLETE') {
      void refetch()
      void refetchLoss()
    }
  }, [lastMessage, refetch, refetchLoss])

  const handleUploadComplete = () => {
    void refetch()
    void refetchLoss()
  }

  if (loading || !data) {
    return <div className="flex items-center justify-center h-64 text-muted text-sm">Loading telemetry…</div>
  }

  const dist = data.risk_distribution || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  const riskDistData = [
    { name: 'CRITICAL', count: dist.CRITICAL || 0, color: '#ef4444' },
    { name: 'HIGH',     count: dist.HIGH || 0,     color: '#f97316' },
    { name: 'MEDIUM',   count: dist.MEDIUM || 0,   color: '#f59e0b' },
    { name: 'LOW',      count: dist.LOW || 0,      color: '#3b82f6' },
  ]

  const statusKey = (data.network_security_status || 'NORMAL').replace(/ /g, '_').toUpperCase()

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-white">Network Security Overview</h1>
          <p className="text-xs text-muted mt-0.5">Real-time telemetry from latest analysis session</p>
        </div>
        <RiskBadge value={statusKey} />
      </div>

      {/* PCAP Upload */}
      <PcapUpload onComplete={handleUploadComplete} />

      {/* Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <MetricCard title="Total Packets"    value={(data.total_packets_analysed ?? 0).toLocaleString()} icon={Layers}       color="text-accent" />
        <MetricCard title="Total Flows"      value={(data.total_flows ?? 0).toLocaleString()}             icon={Activity}     color="text-blue-400" />
        <MetricCard title="Active Alerts"    value={data.active_alerts ?? 0}                            icon={AlertTriangle} color="text-danger" />
        <MetricCard title="Suspicious Hosts" value={data.suspicious_hosts ?? 0}                         icon={Users}        color="text-warning" />
        <MetricCard title="Overall Risk"     value={`${(data.overall_risk_score ?? 0).toFixed(1)}/10`}   icon={TrendingUp}   color={
          (data.overall_risk_score ?? 0) >= 7 ? 'text-danger' : (data.overall_risk_score ?? 0) >= 5 ? 'text-warning' : 'text-success'
        } />
      </div>

      {/* Telemetry & Transmission Integrity Quick Summary */}
      {lossData && (
        <div className="bg-panel border border-border rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded flex items-center justify-center ${
              (lossData.overall_loss_percentage || 0) > 2 ? 'bg-danger/20 text-danger' : 'bg-accent/20 text-accent'
            }`}>
              {(lossData.overall_loss_percentage || 0) > 2 ? <ShieldAlert size={20} /> : <Gauge size={20} />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-white">Transmission Integrity & Data Loss</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                  lossData.measurement_status === 'CONFIRMED'
                    ? 'bg-blue-500/20 text-blue-400'
                    : lossData.measurement_status === 'INFERRED'
                    ? 'bg-amber-500/20 text-amber-400'
                    : 'bg-gray-500/20 text-gray-400'
                }`}>
                  {lossData.measurement_status}
                </span>
              </div>
              <p className="text-xs text-muted mt-0.5">
                Packets Received: <span className="text-white font-mono">{lossData.total_packets_received.toLocaleString()}</span> · Loss Ratio:{' '}
                <span className={`font-mono font-semibold ${
                  (lossData.overall_loss_percentage || 0) > 2 ? 'text-danger' : 'text-success'
                }`}>
                  {lossData.overall_loss_percentage !== null && lossData.overall_loss_percentage !== undefined
                    ? `${lossData.overall_loss_percentage.toFixed(2)}%`
                    : 'Clean / None'}
                </span>
                {lossData.total_packets_lost !== null && lossData.total_packets_lost !== undefined && (
                  <span className="text-muted ml-2">({lossData.total_packets_lost.toLocaleString()} lost)</span>
                )}
              </p>
            </div>
          </div>
          <Link
            to="/telemetry"
            className="flex items-center gap-1.5 px-3 py-1.5 bg-white/5 hover:bg-white/10 border border-border rounded text-xs text-white transition-colors self-start md:self-auto"
          >
            <span>Inspect Telemetry & Baselines</span>
            <ArrowRight size={13} className="text-accent" />
          </Link>
        </div>
      )}

      {/* Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-panel border border-border rounded-lg p-4">
          <h2 className="text-sm font-medium text-white mb-3">Traffic Timeline</h2>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={data.timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1c1c1c" />
              <XAxis dataKey="time" tick={{ fill: '#71717a', fontSize: 11 }} />
              <YAxis tick={{ fill: '#71717a', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#080808', border: '1px solid #1c1c1c', borderRadius: 6, fontSize: 12, color: '#fff' }} />
              <Line type="monotone" dataKey="throughput_kb" stroke="#ffffff" strokeWidth={2} dot={false} name="KB/s" />
              <Line type="monotone" dataKey="risk_index"    stroke="#ef4444" strokeWidth={2} dot={false} name="Risk" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-panel border border-border rounded-lg p-4">
          <h2 className="text-sm font-medium text-white mb-3">Risk Distribution</h2>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={riskDistData} barSize={36}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1c1c1c" />
              <XAxis dataKey="name" tick={{ fill: '#71717a', fontSize: 11 }} />
              <YAxis tick={{ fill: '#71717a', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#080808', border: '1px solid #1c1c1c', borderRadius: 6, fontSize: 12, color: '#fff' }} />
              <Bar dataKey="count">
                {riskDistData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Events */}
      <div className="bg-panel border border-border rounded-lg p-4">
        <h2 className="text-sm font-medium text-white mb-3">Recent Events</h2>
        <div className="divide-y divide-border">
          {data.recent_events.length === 0 && (
            <p className="text-xs text-muted py-3">No events recorded yet.</p>
          )}
          {data.recent_events.map((ev) => (
            <div key={ev.id} className="py-2.5 flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <p className="text-xs text-white truncate">{ev.description}</p>
                <p className="text-xs text-muted mt-0.5">
                  {ev.source_ip} → {ev.destination_ip} · {ev.triggered_engine}
                </p>
              </div>
              <RiskBadge value={ev.severity} />
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
