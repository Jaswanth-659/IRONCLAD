import React from 'react'
import { Activity, AlertTriangle, Layers, Users, TrendingUp } from 'lucide-react'
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'
import { useApi } from '../hooks/useApi'
import { useWebSocket } from '../hooks/useWebSocket'
import MetricCard from '../components/MetricCard'
import RiskBadge from '../components/RiskBadge'
import PcapUpload from '../components/PcapUpload'

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
  const { lastMessage } = useWebSocket('ws://localhost:8000/ws')

  React.useEffect(() => {
    if (lastMessage?.type === 'analysis_complete') void refetch()
  }, [lastMessage, refetch])

  if (loading || !data) {
    return <div className="flex items-center justify-center h-64 text-muted text-sm">Loading telemetry…</div>
  }

  const riskDistData = [
    { name: 'CRITICAL', count: data.risk_distribution.CRITICAL, color: '#ef4444' },
    { name: 'HIGH',     count: data.risk_distribution.HIGH,     color: '#f97316' },
    { name: 'MEDIUM',   count: data.risk_distribution.MEDIUM,   color: '#f59e0b' },
    { name: 'LOW',      count: data.risk_distribution.LOW,      color: '#3b82f6' },
  ]

  const statusKey = data.network_security_status.replace(/ /g, '_').toUpperCase()

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
      <PcapUpload onComplete={refetch} />

      {/* Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <MetricCard title="Total Packets"    value={data.total_packets_analysed.toLocaleString()} icon={Layers}       color="text-accent" />
        <MetricCard title="Total Flows"      value={data.total_flows.toLocaleString()}             icon={Activity}     color="text-blue-400" />
        <MetricCard title="Active Alerts"    value={data.active_alerts}                            icon={AlertTriangle} color="text-danger" />
        <MetricCard title="Suspicious Hosts" value={data.suspicious_hosts}                         icon={Users}        color="text-warning" />
        <MetricCard title="Overall Risk"     value={`${data.overall_risk_score.toFixed(1)}/10`}   icon={TrendingUp}   color={
          data.overall_risk_score >= 7 ? 'text-danger' : data.overall_risk_score >= 5 ? 'text-warning' : 'text-success'
        } />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-panel border border-border rounded-lg p-4">
          <h2 className="text-sm font-medium text-white mb-3">Traffic Timeline</h2>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={data.timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2a3a" />
              <XAxis dataKey="time" tick={{ fill: '#6b7280', fontSize: 11 }} />
              <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#161b27', border: '1px solid #1e2a3a', borderRadius: 6, fontSize: 12 }} />
              <Line type="monotone" dataKey="throughput_kb" stroke="#3b82f6" strokeWidth={2} dot={false} name="KB/s" />
              <Line type="monotone" dataKey="risk_index"    stroke="#ef4444" strokeWidth={2} dot={false} name="Risk" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-panel border border-border rounded-lg p-4">
          <h2 className="text-sm font-medium text-white mb-3">Risk Distribution</h2>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={riskDistData} barSize={36}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2a3a" />
              <XAxis dataKey="name" tick={{ fill: '#6b7280', fontSize: 11 }} />
              <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#161b27', border: '1px solid #1e2a3a', borderRadius: 6, fontSize: 12 }} />
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
