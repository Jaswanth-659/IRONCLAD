import React, { useEffect, useRef } from 'react'
import { useApi } from '../hooks/useApi'
import type { TopologyNode, TopologyLink } from '../types'

interface TopoResponse { nodes: TopologyNode[]; links: TopologyLink[] }

function getRiskColor(score: number): string {
  if (score >= 7) return '#ef4444'
  if (score >= 5) return '#f59e0b'
  return '#22c55e'
}

export default function NetworkTopology() {
  const { data, loading, error } = useApi<TopoResponse>('/api/topology')
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [selected, setSelected] = React.useState<TopologyNode | null>(null)

  useEffect(() => {
    if (!data || !canvasRef.current) return
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const W = canvas.width
    const H = canvas.height
    const nodes = data.nodes
    const links = data.links

    // Simple force-directed layout positions (static seed)
    const positions: Record<string, { x: number; y: number }> = {}
    nodes.forEach((n, i) => {
      const angle = (i / nodes.length) * 2 * Math.PI
      const radius = Math.min(W, H) * 0.33
      positions[n.id] = {
        x: W / 2 + radius * Math.cos(angle),
        y: H / 2 + radius * Math.sin(angle),
      }
    })

    ctx.clearRect(0, 0, W, H)

    // Draw links
    for (const link of links) {
      const src = positions[link.source]
      const tgt = positions[link.target]
      if (!src || !tgt) continue
      ctx.beginPath()
      ctx.moveTo(src.x, src.y)
      ctx.lineTo(tgt.x, tgt.y)
      ctx.strokeStyle = link.risk_score >= 7 ? '#ef444450' : '#3b82f630'
      ctx.lineWidth = Math.max(1, Math.log2((link.bytes / 1000) + 1))
      ctx.stroke()
    }

    // Draw nodes
    for (const node of nodes) {
      const pos = positions[node.id]
      if (!pos) continue
      const r = node.node_type === 'GATEWAY' ? 10 : 8
      ctx.beginPath()
      ctx.arc(pos.x, pos.y, r, 0, 2 * Math.PI)
      ctx.fillStyle = getRiskColor(node.risk_score)
      ctx.fill()
      ctx.strokeStyle = '#161b27'
      ctx.lineWidth = 2
      ctx.stroke()

      // Label
      ctx.fillStyle = '#e2e8f0'
      ctx.font = '10px monospace'
      ctx.textAlign = 'center'
      ctx.fillText(node.ip, pos.x, pos.y + r + 12)
    }

    // Click handler
    const handleClick = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect()
      const mx = e.clientX - rect.left
      const my = e.clientY - rect.top
      for (const node of nodes) {
        const pos = positions[node.id]
        if (!pos) continue
        const dist = Math.hypot(mx - pos.x, my - pos.y)
        if (dist <= 12) { setSelected(node); return }
      }
      setSelected(null)
    }
    canvas.addEventListener('click', handleClick)
    return () => canvas.removeEventListener('click', handleClick)
  }, [data])

  if (loading) return <div className="p-6 text-sm text-muted">Loading topology…</div>
  if (error)   return <div className="p-6 text-sm text-danger">Error: {error}</div>

  return (
    <div className="p-6 space-y-4">
      <div>
        <h1 className="text-lg font-semibold text-white">Network Topology</h1>
        <p className="text-xs text-muted mt-0.5">Host communication graph — click a node to inspect</p>
      </div>

      <div className="flex gap-4">
        <div className="flex-1 bg-panel border border-border rounded-lg overflow-hidden">
          <canvas ref={canvasRef} width={700} height={420} className="w-full" />
        </div>

        {selected && (
          <div className="w-56 bg-panel border border-border rounded-lg p-4 space-y-3">
            <h3 className="text-sm font-semibold text-white">Node Details</h3>
            <div className="space-y-1.5 text-xs">
              <div><span className="text-muted">IP:</span> <span className="text-white font-mono">{selected.ip}</span></div>
              <div><span className="text-muted">Type:</span> <span className="text-white">{selected.node_type}</span></div>
              <div>
                <span className="text-muted">Risk:</span>{' '}
                <span className="font-bold font-mono" style={{ color: getRiskColor(selected.risk_score) }}>
                  {selected.risk_score.toFixed(1)}/10
                </span>
              </div>
              <div><span className="text-muted">Packets:</span> <span className="text-white font-mono">{selected.total_packets.toLocaleString()}</span></div>
              <div><span className="text-muted">Bytes:</span> <span className="text-white font-mono">{selected.total_bytes.toLocaleString()}</span></div>
            </div>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-6 text-xs text-muted">
        {[['#22c55e', 'Normal'], ['#f59e0b', 'Suspicious'], ['#ef4444', 'High Risk']].map(([col, lbl]) => (
          <div key={lbl} className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: col }} />
            {lbl}
          </div>
        ))}
      </div>
    </div>
  )
}
