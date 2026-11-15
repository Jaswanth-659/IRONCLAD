import React, { useState } from 'react'
import { Shield, AlertTriangle } from 'lucide-react'
import { useApi } from '../hooks/useApi'
import RiskBadge from '../components/RiskBadge'
import type { ContainmentHost, AuditLog } from '../types'

interface HostsResponse { hosts: ContainmentHost[] }
interface AuditResponse { logs: AuditLog[] }

interface ContainForm {
  operator: string
  reason: string
  notes: string
}

export default function ContainmentCenter() {
  const { data: hostsData, loading: hostsLoading, refetch: refetchHosts } = useApi<HostsResponse>('/api/containment/hosts')
  const { data: logsData, loading: logsLoading, refetch: refetchLogs } = useApi<AuditResponse>('/api/containment/audit-log')

  const [modalHost, setModalHost] = useState<ContainmentHost | null>(null)
  const [form, setForm] = useState<ContainForm>({ operator: 'SOC_Analyst', reason: '', notes: '' })
  const [submitting, setSubmitting] = useState(false)
  const [result, setResult] = useState<string | null>(null)

  const hosts = hostsData?.hosts ?? []
  const logs  = logsData?.logs  ?? []

  const handleContain = async () => {
    if (!modalHost || !form.reason) return
    setSubmitting(true)
    setResult(null)
    try {
      const res = await fetch('/api/containment/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip_address: modalHost.ip_address,
          operator:   form.operator,
          reason:     form.reason,
          notes:      form.notes,
          session_id: 'demo-session-alpha-001',
        }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setResult('✓ Simulated containment recorded. Host status updated.')
      await refetchHosts()
      await refetchLogs()
      setTimeout(() => { setModalHost(null); setResult(null) }, 2000)
    } catch (e) {
      setResult(`Error: ${e instanceof Error ? e.message : 'Unknown'}`)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-white">Containment Center</h1>
        <p className="text-xs text-muted mt-0.5">
          <span className="text-warning">⚠ SIMULATED CONTAINMENT ONLY</span>
          {' '}— Actions are recorded for audit. No actual network isolation is performed.
        </p>
      </div>

      {/* Hosts */}
      <div className="bg-panel border border-border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-sm font-medium text-white">Monitored Hosts</h2>
        </div>
        {hostsLoading && <div className="p-6 text-sm text-muted text-center">Loading…</div>}
        {!hostsLoading && (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border">
                {['IP Address', 'Hostname', 'Status', 'Risk Score', 'Reason', 'Actions'].map((h) => (
                  <th key={h} className="text-left text-muted font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {hosts.map((host) => (
                <tr key={host.id} className="hover:bg-white/5">
                  <td className="px-4 py-3 font-mono text-white">{host.ip_address}</td>
                  <td className="px-4 py-3 text-muted">{host.hostname || '—'}</td>
                  <td className="px-4 py-3"><RiskBadge value={host.status} /></td>
                  <td className="px-4 py-3">
                    <span className={`font-bold font-mono ${host.risk_score >= 7 ? 'text-danger' : host.risk_score >= 5 ? 'text-warning' : 'text-success'}`}>
                      {host.risk_score.toFixed(1)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-muted">{host.containment_reason || '—'}</td>
                  <td className="px-4 py-3">
                    {host.status !== 'CONTAINED' && (
                      <button
                        onClick={() => setModalHost(host)}
                        className="flex items-center gap-1.5 px-2.5 py-1 bg-danger/15 hover:bg-danger/25 text-danger border border-danger/30 rounded text-xs font-medium transition-colors"
                      >
                        <Shield size={11} /> Simulate Containment
                      </button>
                    )}
                    {host.status === 'CONTAINED' && (
                      <span className="text-xs text-muted">Contained by {host.contained_by}</span>
                    )}
                  </td>
                </tr>
              ))}
              {hosts.length === 0 && (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-muted">No monitored hosts.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Audit Log */}
      <div className="bg-panel border border-border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center gap-2">
          <AlertTriangle size={13} className="text-warning" />
          <h2 className="text-sm font-medium text-white">Audit Log</h2>
        </div>
        {logsLoading && <div className="p-6 text-sm text-muted text-center">Loading…</div>}
        {!logsLoading && (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border">
                {['Timestamp', 'Operator', 'Action', 'Target', 'Details'].map((h) => (
                  <th key={h} className="text-left text-muted font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-white/5">
                  <td className="px-4 py-2.5 font-mono text-muted whitespace-nowrap">{new Date(log.timestamp).toLocaleString()}</td>
                  <td className="px-4 py-2.5 text-white">{log.operator}</td>
                  <td className="px-4 py-2.5"><RiskBadge value={log.action} /></td>
                  <td className="px-4 py-2.5 font-mono text-white">{log.target}</td>
                  <td className="px-4 py-2.5 text-muted">{log.details}</td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-muted">No audit events yet.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Containment Modal */}
      {modalHost && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
          <div className="bg-panel border border-border rounded-lg w-full max-w-md p-6 space-y-4">
            <div>
              <h3 className="text-base font-semibold text-white">Simulate Containment</h3>
              <p className="text-xs text-muted mt-1">
                Target: <span className="text-white font-mono">{modalHost.ip_address}</span>
                {' '}— This action is <span className="text-warning">SIMULATED</span> and recorded for audit only.
              </p>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-muted block mb-1">Operator ID</label>
                <input
                  value={form.operator}
                  onChange={(e) => setForm((f) => ({ ...f, operator: e.target.value }))}
                  className="w-full bg-bg border border-border rounded px-3 py-1.5 text-xs text-white outline-none focus:border-accent"
                />
              </div>
              <div>
                <label className="text-xs text-muted block mb-1">Reason <span className="text-danger">*</span></label>
                <input
                  value={form.reason}
                  onChange={(e) => setForm((f) => ({ ...f, reason: e.target.value }))}
                  placeholder="e.g. Confirmed C2 communication"
                  className="w-full bg-bg border border-border rounded px-3 py-1.5 text-xs text-white outline-none focus:border-accent"
                />
              </div>
              <div>
                <label className="text-xs text-muted block mb-1">Notes</label>
                <textarea
                  value={form.notes}
                  onChange={(e) => setForm((f) => ({ ...f, notes: e.target.value }))}
                  rows={3}
                  className="w-full bg-bg border border-border rounded px-3 py-1.5 text-xs text-white outline-none focus:border-accent resize-none"
                />
              </div>
            </div>

            {result && (
              <div className={`text-xs px-3 py-2 rounded ${result.startsWith('✓') ? 'bg-success/10 text-success' : 'bg-danger/10 text-danger'}`}>
                {result}
              </div>
            )}

            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setModalHost(null)}
                className="px-3 py-1.5 text-xs border border-border rounded text-muted hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={() => void handleContain()}
                disabled={submitting || !form.reason}
                className="px-3 py-1.5 text-xs bg-danger/80 hover:bg-danger text-white rounded disabled:opacity-50 font-medium flex items-center gap-1.5"
              >
                <Shield size={11} />
                {submitting ? 'Recording…' : 'Confirm Simulated Containment'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
