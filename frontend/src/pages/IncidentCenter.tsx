import React, { useState } from 'react'
import { Search } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useApi } from '../hooks/useApi'
import RiskBadge from '../components/RiskBadge'
import type { Incident } from '../types'

interface IncidentsResponse { incidents: Incident[]; total: number }

export default function IncidentCenter() {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [page, setPage] = useState(0)
  const limit = 20

  const params = new URLSearchParams()
  if (search)   params.set('search_ip', search)
  if (severity) params.set('severity', severity)
  params.set('limit', String(limit))
  params.set('offset', String(page * limit))

  const { data, loading, error } = useApi<IncidentsResponse>(
    `/api/incidents?${params.toString()}`,
    [search, severity, page]
  )

  const incidents = data?.incidents ?? []
  const total     = data?.total ?? 0

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-lg font-semibold text-white">Incident Center</h1>
        <p className="text-xs text-muted mt-0.5">Searchable incident log — click a row for the full investigation report</p>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
          <input
            placeholder="Search IP…"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(0) }}
            className="bg-panel border border-border rounded px-7 py-1.5 text-xs text-white placeholder-muted outline-none focus:border-accent w-44"
          />
        </div>
        <select
          value={severity}
          onChange={(e) => { setSeverity(e.target.value); setPage(0) }}
          className="bg-panel border border-border rounded px-3 py-1.5 text-xs text-white outline-none focus:border-accent"
        >
          <option value="">All Severities</option>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <span className="text-xs text-muted ml-auto">{total} incidents total</span>
      </div>

      {/* Table */}
      <div className="bg-panel border border-border rounded-lg overflow-hidden">
        {loading && <div className="p-6 text-sm text-muted text-center">Loading…</div>}
        {error && <div className="p-6 text-sm text-danger text-center">Error: {error}</div>}
        {!loading && !error && (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border">
                {['#', 'Time', 'Severity', 'Source IP', 'Dest IP', 'Port', 'Engine', 'Risk', 'Classification'].map((h) => (
                  <th key={h} className="text-left text-muted font-medium px-3 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {incidents.map((inc) => (
                <tr key={inc.id} className="hover:bg-white/5 transition-colors cursor-pointer">
                  <td className="px-3 py-2.5">
                    <Link to={`/incidents/${inc.id}`} className="text-accent hover:underline font-mono">#{inc.id}</Link>
                  </td>
                  <td className="px-3 py-2.5 text-muted font-mono whitespace-nowrap">
                    {inc.timestamp ? new Date(inc.timestamp).toLocaleTimeString() : '—'}
                  </td>
                  <td className="px-3 py-2.5"><RiskBadge value={inc.severity || 'LOW'} /></td>
                  <td className="px-3 py-2.5 font-mono text-white">{inc.source_ip || '—'}</td>
                  <td className="px-3 py-2.5 font-mono text-white">{inc.destination_ip || '—'}</td>
                  <td className="px-3 py-2.5 font-mono text-muted">{inc.port || '—'}</td>
                  <td className="px-3 py-2.5 text-muted truncate max-w-36">{inc.triggered_engine || '—'}</td>
                  <td className="px-3 py-2.5">
                    <span className={`font-bold font-mono ${(inc.risk_score ?? 0) >= 7 ? 'text-danger' : (inc.risk_score ?? 0) >= 5 ? 'text-warning' : 'text-success'}`}>
                      {(inc.risk_score ?? 0).toFixed(1)}
                    </span>
                  </td>
                  <td className="px-3 py-2.5"><RiskBadge value={inc.classification || 'NORMAL'} /></td>
                </tr>
              ))}
              {incidents.length === 0 && (
                <tr><td colSpan={9} className="px-3 py-8 text-center text-muted">No incidents match your filters.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {total > limit && (
        <div className="flex items-center justify-end gap-2 text-xs">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="px-3 py-1 bg-panel border border-border rounded disabled:opacity-40 hover:border-accent text-white"
          >
            Prev
          </button>
          <span className="text-muted">Page {page + 1} of {Math.ceil(total / limit)}</span>
          <button
            onClick={() => setPage((p) => p + 1)}
            disabled={(page + 1) * limit >= total}
            className="px-3 py-1 bg-panel border border-border rounded disabled:opacity-40 hover:border-accent text-white"
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}
