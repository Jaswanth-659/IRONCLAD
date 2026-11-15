import React, { useEffect, useRef, useState, useCallback, useMemo } from 'react'
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RotateCcw,
  Shield,
  AlertTriangle,
  Layers,
  Activity,
  Database,
  RefreshCw,
  X,
  ArrowRight,
  Server,
  Radio,
  FileCode,
  HardDrive,
  Info,
} from 'lucide-react'
import { useApi } from '../hooks/useApi'
import { useWebSocket } from '../hooks/useWebSocket'
import RiskBadge from '../components/RiskBadge'
import type { TopologyNode, TopologyLink, TopologyResponse } from '../types'

interface SessionItem {
  task_id: string
  filename: string
  status: string
  total_packets: number
  total_flows: number
  overall_risk_score: number
  final_classification: string
  created_at: string
}

function getRiskColor(score: number): string {
  if (score >= 7.0) return '#ef4444' // RED: HIGH RISK / CRITICAL
  if (score >= 5.0) return '#f97316' // ORANGE: SUSPICIOUS
  if (score >= 3.0) return '#eab308' // YELLOW: LOW RISK
  return '#22c55e' // GREEN: NORMAL
}

function getRiskCategory(score: number): string {
  if (score >= 7.0) return 'HIGH RISK / CRITICAL'
  if (score >= 5.0) return 'SUSPICIOUS'
  if (score >= 3.0) return 'LOW RISK'
  return 'NORMAL'
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

interface NodePosition {
  x: number
  y: number
  vx: number
  vy: number
  radius: number
  isDragging?: boolean
}

export default function NetworkTopology() {
  const [selectedSessionId, setSelectedSessionId] = useState<string>('')
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null)
  const [selectedLink, setSelectedLink] = useState<TopologyLink | null>(null)
  const [hoveredNode, setHoveredNode] = useState<{ node: TopologyNode; x: number; y: number } | null>(null)

  // Canvas viewport transform
  const [zoom, setZoom] = useState(1.0)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const isPanningRef = useRef(false)
  const dragStartRef = useRef({ x: 0, y: 0 })
  const draggedNodeRef = useRef<string | null>(null)

  const canvasRef = useRef<HTMLCanvasElement>(null)
  const positionsRef = useRef<Record<string, NodePosition>>({})

  // Fetch session history for selector
  const { data: sessionsData, refetch: refetchSessions } = useApi<SessionItem[]>('/api/sessions')
  const sessions = Array.isArray(sessionsData) ? sessionsData : []

  // Default to latest completed session
  useEffect(() => {
    if (!selectedSessionId && sessions.length > 0) {
      const latest = sessions.find((s) => s.status === 'COMPLETED') ?? sessions[0]
      if (latest) setSelectedSessionId(latest.task_id)
    }
  }, [sessions, selectedSessionId])

  // Fetch topology for selected session
  const topoUrl = selectedSessionId
    ? `/api/topology?session_id=${encodeURIComponent(selectedSessionId)}`
    : '/api/topology'
  const { data: topoData, loading, error, refetch: refetchTopo } = useApi<TopologyResponse>(topoUrl)

  // WebSocket for real-time analysis completion
  const { lastMessage } = useWebSocket('ws://localhost:8000/ws')
  useEffect(() => {
    const t = String(lastMessage?.type ?? '').toUpperCase()
    if (t === 'ANALYSIS_COMPLETED' || t === 'ANALYSIS_COMPLETE') {
      void refetchSessions()
      void refetchTopo()
    }
  }, [lastMessage, refetchSessions, refetchTopo])

  const nodes = useMemo(() => topoData?.nodes ?? [], [topoData])
  const links = useMemo(() => topoData?.links ?? [], [topoData])

  // Initialize positions with circular/force layout
  const resetLayout = useCallback(() => {
    if (!canvasRef.current || nodes.length === 0) return
    const W = canvasRef.current.width
    const H = canvasRef.current.height
    const cx = W / 2
    const cy = H / 2
    const radius = Math.min(W, H) * 0.35

    const newPositions: Record<string, NodePosition> = {}
    nodes.forEach((n, i) => {
      // Put critical/scanner in center-orbit, others distributed
      const angle = (i / nodes.length) * 2 * Math.PI
      const r = n.risk_score >= 7 ? radius * 0.55 : radius
      newPositions[n.id] = {
        x: cx + r * Math.cos(angle),
        y: cy + r * Math.sin(angle),
        vx: 0,
        vy: 0,
        radius: n.role === 'GATEWAY' ? 14 : n.risk_score >= 7 ? 13 : 10,
      }
    })
    positionsRef.current = newPositions
    setZoom(1.0)
    setPan({ x: 0, y: 0 })
    setSelectedNode(null)
    setSelectedLink(null)
  }, [nodes])

  // Initialize on data change
  useEffect(() => {
    resetLayout()
  }, [resetLayout])

  // Fit to screen
  const fitToScreen = useCallback(() => {
    const positions = positionsRef.current
    const keys = Object.keys(positions)
    if (keys.length === 0 || !canvasRef.current) return

    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity
    for (const key of keys) {
      const p = positions[key]
      if (p.x < minX) minX = p.x
      if (p.x > maxX) maxX = p.x
      if (p.y < minY) minY = p.y
      if (p.y > maxY) maxY = p.y
    }

    const W = canvasRef.current.width
    const H = canvasRef.current.height
    const graphW = Math.max(100, maxX - minX + 100)
    const graphH = Math.max(100, maxY - minY + 100)
    const newZoom = Math.min(W / graphW, H / graphH, 1.4)
    const midX = (minX + maxX) / 2
    const midY = (minY + maxY) / 2

    setZoom(newZoom)
    setPan({
      x: W / 2 - midX * newZoom,
      y: H / 2 - midY * newZoom,
    })
  }, [])

  // Render loop
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let animId: number
    const render = () => {
      const W = canvas.width
      const H = canvas.height
      ctx.clearRect(0, 0, W, H)

      ctx.save()
      ctx.translate(pan.x, pan.y)
      ctx.scale(zoom, zoom)

      const positions = positionsRef.current

      // Draw Grid dots in background
      ctx.fillStyle = '#1e293b25'
      const gridSize = 40
      const startX = -pan.x / zoom - 100
      const endX = (W - pan.x) / zoom + 100
      const startY = -pan.y / zoom - 100
      const endY = (H - pan.y) / zoom + 100
      for (let gx = Math.floor(startX / gridSize) * gridSize; gx < endX; gx += gridSize) {
        for (let gy = Math.floor(startY / gridSize) * gridSize; gy < endY; gy += gridSize) {
          ctx.fillRect(gx, gy, 1.5, 1.5)
        }
      }

      // Draw Links
      links.forEach((link) => {
        const src = positions[link.source]
        const tgt = positions[link.target]
        if (!src || !tgt) return

        const isLinkSelected =
          selectedLink && selectedLink.source === link.source && selectedLink.target === link.target
        const isConnectedToSelected =
          selectedNode && (selectedNode.id === link.source || selectedNode.id === link.target)

        ctx.beginPath()

        // Curved line to avoid overlap for bidirectional edges
        const dx = tgt.x - src.x
        const dy = tgt.y - src.y
        const dist = Math.hypot(dx, dy)
        if (dist === 0) return

        const curvature = 20
        const cx = (src.x + tgt.x) / 2 - (dy / dist) * curvature
        const cy = (src.y + tgt.y) / 2 + (dx / dist) * curvature

        ctx.moveTo(src.x, src.y)
        ctx.quadraticCurveTo(cx, cy, tgt.x, tgt.y)

        // Styling
        if (link.is_anomalous || link.risk_score >= 7.0) {
          ctx.strokeStyle = isLinkSelected ? '#ef4444' : '#ef444490'
          ctx.lineWidth = isLinkSelected ? 3.5 : Math.max(1.8, Math.min(4, Math.log10(link.bytes + 1)))
        } else if (link.risk_score >= 5.0) {
          ctx.strokeStyle = isLinkSelected ? '#f97316' : '#f9731680'
          ctx.lineWidth = isLinkSelected ? 3 : 1.8
        } else {
          ctx.strokeStyle = isConnectedToSelected
            ? '#38bdf8'
            : isLinkSelected
            ? '#00d4aa'
            : '#33415570'
          ctx.lineWidth = isLinkSelected || isConnectedToSelected ? 2.5 : 1.2
        }
        ctx.stroke()

        // Directional Arrowhead
        const t = 0.65 // Position along curve
        const arrowX = (1 - t) * (1 - t) * src.x + 2 * (1 - t) * t * cx + t * t * tgt.x
        const arrowY = (1 - t) * (1 - t) * src.y + 2 * (1 - t) * t * cy + t * t * tgt.y
        const tangentX = 2 * (1 - t) * (cx - src.x) + 2 * t * (tgt.x - cx)
        const tangentY = 2 * (1 - t) * (cy - src.y) + 2 * t * (tgt.y - cy)
        const angle = Math.atan2(tangentY, tangentX)

        ctx.save()
        ctx.translate(arrowX, arrowY)
        ctx.rotate(angle)
        ctx.beginPath()
        ctx.moveTo(0, 0)
        ctx.lineTo(-7, -4)
        ctx.lineTo(-7, 4)
        ctx.closePath()
        ctx.fillStyle = ctx.strokeStyle
        ctx.fill()
        ctx.restore()

        // Protocol Badge along edge
        if (zoom >= 0.75) {
          const midX = (src.x + tgt.x) / 2 - (dy / dist) * (curvature * 0.7)
          const midY = (src.y + tgt.y) / 2 + (dx / dist) * (curvature * 0.7)
          ctx.font = '9px monospace'
          const label = `${link.protocol} (${formatBytes(link.bytes)})`
          const txtWidth = ctx.measureText(label).width

          ctx.fillStyle = '#0f172aee'
          ctx.fillRect(midX - txtWidth / 2 - 3, midY - 6, txtWidth + 6, 12)
          ctx.fillStyle = link.is_anomalous ? '#fca5a5' : '#94a3b8'
          ctx.textAlign = 'center'
          ctx.fillText(label, midX, midY + 3)
        }
      })

      // Draw Nodes
      nodes.forEach((node) => {
        const pos = positions[node.id]
        if (!pos) return

        const isSelected = selectedNode?.id === node.id
        const isHovered = hoveredNode?.node.id === node.id
        const riskColor = getRiskColor(node.risk_score)
        const r = pos.radius + (isSelected ? 4 : isHovered ? 2 : 0)

        // Selected halo
        if (isSelected || isHovered) {
          ctx.beginPath()
          ctx.arc(pos.x, pos.y, r + 6, 0, 2 * Math.PI)
          ctx.fillStyle = isSelected ? `${riskColor}33` : '#38bdf822'
          ctx.fill()
          ctx.strokeStyle = isSelected ? riskColor : '#38bdf8'
          ctx.lineWidth = 1.5
          ctx.stroke()
        }

        // Node circle
        ctx.beginPath()
        ctx.arc(pos.x, pos.y, r, 0, 2 * Math.PI)
        ctx.fillStyle = riskColor
        ctx.fill()
        ctx.strokeStyle = '#090d16'
        ctx.lineWidth = 2.5
        ctx.stroke()

        // Role indicator inner dot
        if (node.role === 'GATEWAY') {
          ctx.beginPath()
          ctx.arc(pos.x, pos.y, r * 0.45, 0, 2 * Math.PI)
          ctx.fillStyle = '#ffffff'
          ctx.fill()
        } else if (node.risk_score >= 7.0) {
          ctx.beginPath()
          ctx.arc(pos.x, pos.y, r * 0.4, 0, 2 * Math.PI)
          ctx.fillStyle = '#fee2e2'
          ctx.fill()
        }

        // Primary Label: IP Address (with dark pill background to prevent overlap)
        const ipLabel = node.ip || node.id
        ctx.font = isSelected ? 'bold 11px monospace' : '10px monospace'
        const labelWidth = ctx.measureText(ipLabel).width
        const pillH = 14
        const pillY = pos.y + r + 5

        ctx.fillStyle = '#0b101be0'
        ctx.strokeStyle = isSelected ? riskColor : '#1e293b'
        ctx.lineWidth = 1
        ctx.beginPath()
        ctx.roundRect(pos.x - labelWidth / 2 - 4, pillY, labelWidth + 8, pillH, 3)
        ctx.fill()
        ctx.stroke()

        ctx.fillStyle = isSelected ? '#ffffff' : '#e2e8f0'
        ctx.textAlign = 'center'
        ctx.fillText(ipLabel, pos.x, pillY + 10)

        // Sub-label: Hostname or Role badge if zoom is sufficient
        if (zoom >= 0.85) {
          const subLabel = node.hostname ? node.hostname : node.role
          ctx.font = '8px sans-serif'
          ctx.fillStyle = node.risk_score >= 7.0 ? '#fca5a5' : '#94a3b8'
          ctx.fillText(subLabel, pos.x, pillY + pillH + 9)
        }
      })

      ctx.restore()
      animId = requestAnimationFrame(render)
    }

    render()
    return () => cancelAnimationFrame(animId)
  }, [nodes, links, zoom, pan, selectedNode, selectedLink, hoveredNode])

  // Mouse Handlers: Pan, Zoom, Drag, Click
  const getCanvasCoords = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current!.getBoundingClientRect()
    const clientX = e.clientX - rect.left
    const clientY = e.clientY - rect.top
    const graphX = (clientX - pan.x) / zoom
    const graphY = (clientY - pan.y) / zoom
    return { clientX, clientY, graphX, graphY }
  }

  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const { clientX, clientY, graphX, graphY } = getCanvasCoords(e)

    // Check if clicked on a node to drag or select
    const positions = positionsRef.current
    for (const node of nodes) {
      const pos = positions[node.id]
      if (!pos) continue
      const dist = Math.hypot(graphX - pos.x, graphY - pos.y)
      if (dist <= pos.radius + 6) {
        draggedNodeRef.current = node.id
        setSelectedNode(node)
        setSelectedLink(null)
        return
      }
    }

    // Check if clicked on a link
    for (const link of links) {
      const src = positions[link.source]
      const tgt = positions[link.target]
      if (!src || !tgt) continue
      // Approximate line distance
      const d = distToSegment({ x: graphX, y: graphY }, src, tgt)
      if (d <= 8) {
        setSelectedLink(link)
        setSelectedNode(null)
        return
      }
    }

    // Start background pan
    isPanningRef.current = true
    dragStartRef.current = { x: clientX - pan.x, y: clientY - pan.y }
  }

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const { clientX, clientY, graphX, graphY } = getCanvasCoords(e)

    // Dragging node
    if (draggedNodeRef.current) {
      const pos = positionsRef.current[draggedNodeRef.current]
      if (pos) {
        pos.x = graphX
        pos.y = graphY
      }
      return
    }

    // Panning canvas
    if (isPanningRef.current) {
      setPan({
        x: clientX - dragStartRef.current.x,
        y: clientY - dragStartRef.current.y,
      })
      return
    }

    // Hover detection
    const positions = positionsRef.current
    let foundHover: TopologyNode | null = null
    for (const node of nodes) {
      const pos = positions[node.id]
      if (!pos) continue
      const dist = Math.hypot(graphX - pos.x, graphY - pos.y)
      if (dist <= pos.radius + 6) {
        foundHover = node
        break
      }
    }
    if (foundHover) {
      setHoveredNode({ node: foundHover, x: clientX, y: clientY })
    } else {
      setHoveredNode(null)
    }
  }

  const handleMouseUp = () => {
    draggedNodeRef.current = null
    isPanningRef.current = false
  }

  const handleWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault()
    const zoomFactor = e.deltaY < 0 ? 1.15 : 0.85
    const newZoom = Math.min(Math.max(0.3, zoom * zoomFactor), 3.0)

    const rect = canvasRef.current!.getBoundingClientRect()
    const mouseX = e.clientX - rect.left
    const mouseY = e.clientY - rect.top

    setPan({
      x: mouseX - (mouseX - pan.x) * (newZoom / zoom),
      y: mouseY - (mouseY - pan.y) * (newZoom / zoom),
    })
    setZoom(newZoom)
  }

  // Active Session info
  const currentSession = sessions.find((s) => s.task_id === selectedSessionId)

  // Summary Metrics
  const totalHosts = topoData?.total_hosts ?? nodes.length
  const totalConnections = topoData?.total_connections ?? links.length
  const suspiciousHosts =
    topoData?.suspicious_hosts ?? nodes.filter((n) => n.risk_score >= 5.0 && n.risk_score < 7.0).length
  const criticalHosts =
    topoData?.critical_hosts ?? nodes.filter((n) => n.risk_score >= 7.0).length
  const totalBytesCaptured = nodes.reduce((acc, n) => acc + (n.total_bytes || 0), 0)

  return (
    <div className="p-6 space-y-4">
      {/* Header & Controls Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-semibold text-white">Network Communication Topology</h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-accent/15 text-accent border border-accent/30 font-semibold">
              Live Flow Graph
            </span>
          </div>
          <p className="text-xs text-muted mt-0.5">
            Real host interaction topology mapped from captured packet flows with directional telemetry
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
              void refetchTopo()
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-panel hover:bg-border text-xs text-gray-300 border border-border rounded transition-colors"
            title="Refresh topology"
          >
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Summary KPI Banner */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 bg-panel border border-border rounded-lg p-3">
        <div className="flex items-center gap-3 px-3">
          <div className="p-2 rounded bg-blue-500/10 text-blue-400">
            <Server size={16} />
          </div>
          <div>
            <div className="text-[10px] text-muted uppercase font-mono">Total Hosts</div>
            <div className="text-sm font-bold font-mono text-white mt-0.5">{totalHosts}</div>
          </div>
        </div>

        <div className="flex items-center gap-3 px-3 border-l border-border">
          <div className="p-2 rounded bg-accent/10 text-accent">
            <Radio size={16} />
          </div>
          <div>
            <div className="text-[10px] text-muted uppercase font-mono">Active Connections</div>
            <div className="text-sm font-bold font-mono text-white mt-0.5">{totalConnections}</div>
          </div>
        </div>

        <div className="flex items-center gap-3 px-3 border-l border-border">
          <div className="p-2 rounded bg-warning/10 text-warning">
            <AlertTriangle size={16} />
          </div>
          <div>
            <div className="text-[10px] text-muted uppercase font-mono">Suspicious Hosts</div>
            <div className="text-sm font-bold font-mono text-warning mt-0.5">{suspiciousHosts}</div>
          </div>
        </div>

        <div className="flex items-center gap-3 px-3 border-l border-border">
          <div className="p-2 rounded bg-danger/10 text-danger">
            <Shield size={16} />
          </div>
          <div>
            <div className="text-[10px] text-muted uppercase font-mono">Critical / C2 Hosts</div>
            <div className="text-sm font-bold font-mono text-danger mt-0.5">{criticalHosts}</div>
          </div>
        </div>

        <div className="flex items-center gap-3 px-3 border-l border-border">
          <div className="p-2 rounded bg-purple-500/10 text-purple-400">
            <HardDrive size={16} />
          </div>
          <div>
            <div className="text-[10px] text-muted uppercase font-mono">Total Volume</div>
            <div className="text-sm font-bold font-mono text-white mt-0.5">
              {formatBytes(totalBytesCaptured)}
            </div>
          </div>
        </div>
      </div>

      {/* Main Interactive Topology Area */}
      <div className="relative flex gap-4 bg-panel border border-border rounded-lg overflow-hidden min-h-[580px]">
        {/* Canvas Workspace */}
        <div className="flex-1 relative overflow-hidden flex flex-col">
          {/* Canvas Floating Toolbar */}
          <div className="absolute top-3 left-3 z-10 flex items-center gap-1.5 bg-bg/85 backdrop-blur border border-border p-1 rounded-md shadow-lg">
            <button
              onClick={() => setZoom((z) => Math.min(3.0, z * 1.2))}
              className="p-1.5 hover:bg-panel text-muted hover:text-white rounded transition-colors"
              title="Zoom In"
            >
              <ZoomIn size={14} />
            </button>
            <button
              onClick={() => setZoom((z) => Math.max(0.3, z * 0.8))}
              className="p-1.5 hover:bg-panel text-muted hover:text-white rounded transition-colors"
              title="Zoom Out"
            >
              <ZoomOut size={14} />
            </button>
            <div className="w-[1px] h-4 bg-border mx-0.5" />
            <button
              onClick={fitToScreen}
              className="p-1.5 hover:bg-panel text-muted hover:text-white rounded transition-colors"
              title="Fit to Screen"
            >
              <Maximize2 size={14} />
            </button>
            <button
              onClick={resetLayout}
              className="p-1.5 hover:bg-panel text-muted hover:text-white rounded transition-colors"
              title="Reset Layout"
            >
              <RotateCcw size={14} />
            </button>
            <div className="w-[1px] h-4 bg-border mx-0.5" />
            <span className="text-[10px] font-mono text-muted px-1.5">{Math.round(zoom * 100)}%</span>
          </div>

          {/* Canvas */}
          <canvas
            ref={canvasRef}
            width={960}
            height={580}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onWheel={handleWheel}
            className="w-full h-full cursor-grab active:cursor-grabbing block"
          />

          {/* Hover Tooltip Popup */}
          {hoveredNode && !draggedNodeRef.current && (
            <div
              className="absolute z-20 pointer-events-none bg-bg/95 border border-border rounded p-2.5 shadow-xl text-xs space-y-1 font-mono backdrop-blur"
              style={{
                left: Math.min(hoveredNode.x + 12, 700),
                top: Math.max(10, hoveredNode.y - 40),
              }}
            >
              <div className="flex items-center gap-2 border-b border-border pb-1">
                <span className="font-bold text-white">{hoveredNode.node.ip}</span>
                <span
                  className="text-[10px] px-1.5 py-0.2 rounded font-semibold"
                  style={{
                    backgroundColor: `${getRiskColor(hoveredNode.node.risk_score)}22`,
                    color: getRiskColor(hoveredNode.node.risk_score),
                  }}
                >
                  {hoveredNode.node.risk_score.toFixed(1)}/10
                </span>
              </div>
              <div className="text-[11px] text-gray-300">
                Role: <span className="text-accent">{hoveredNode.node.role}</span> |{' '}
                {hoveredNode.node.is_internal ? 'Internal' : 'External'}
              </div>
              <div className="text-[11px] text-gray-400">
                Traffic: {formatBytes(hoveredNode.node.total_bytes)} ({hoveredNode.node.total_packets} pkts)
              </div>
              <div className="text-[10px] text-muted">Click node for full SOC forensic panel</div>
            </div>
          )}

          {/* Empty State Banner if no nodes */}
          {nodes.length === 0 && !loading && (
            <div className="absolute inset-0 flex flex-col items-center justify-center p-6 text-center bg-bg/90 z-20 space-y-3">
              <Layers size={36} className="text-muted" />
              <div>
                <h3 className="text-sm font-semibold text-white">No Topology Nodes Found</h3>
                <p className="text-xs text-muted max-w-sm mt-1">
                  The selected analysis session contains no recorded IP traffic frames. Upload a PCAP on
                  the Overview page or choose a completed session from the dropdown.
                </p>
              </div>
            </div>
          )}

          {loading && (
            <div className="absolute inset-0 flex items-center justify-center bg-bg/60 backdrop-blur z-20 text-xs text-muted">
              Loading topology graph…
            </div>
          )}
        </div>

        {/* Node / Link Inspection Side Drawer */}
        {(selectedNode || selectedLink) && (
          <div className="w-80 md:w-96 border-l border-border bg-bg/95 backdrop-blur p-4 space-y-4 overflow-y-auto max-h-[600px] shrink-0">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-border pb-2.5">
              <div className="flex items-center gap-2">
                {selectedNode ? (
                  <>
                    <Server size={15} className="text-accent" />
                    <h3 className="text-sm font-bold text-white">Host Node Inspection</h3>
                  </>
                ) : (
                  <>
                    <Activity size={15} className="text-accent" />
                    <h3 className="text-sm font-bold text-white">Connection Inspection</h3>
                  </>
                )}
              </div>
              <button
                onClick={() => {
                  setSelectedNode(null)
                  setSelectedLink(null)
                }}
                className="p-1 hover:bg-panel text-muted hover:text-white rounded"
              >
                <X size={15} />
              </button>
            </div>

            {/* NODE DETAILS VIEW */}
            {selectedNode && (
              <div className="space-y-4 text-xs">
                {/* Identity Card */}
                <div className="bg-panel border border-border rounded p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-[10px] text-muted uppercase font-mono">Host Address</div>
                      <div className="text-sm font-bold font-mono text-white mt-0.5">
                        {selectedNode.ip || selectedNode.id}
                      </div>
                    </div>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold uppercase ${
                        selectedNode.is_internal
                          ? 'bg-blue-500/15 text-blue-400 border border-blue-500/30'
                          : 'bg-orange-500/15 text-orange-400 border border-orange-500/30'
                      }`}
                    >
                      {selectedNode.is_internal ? 'INTERNAL HOST' : 'EXTERNAL HOST'}
                    </span>
                  </div>

                  {selectedNode.hostname && (
                    <div className="text-gray-300 font-mono text-[11px]">
                      <span className="text-muted">Hostname:</span> {selectedNode.hostname}
                    </div>
                  )}

                  <div className="flex items-center justify-between border-t border-border pt-2">
                    <div>
                      <span className="text-muted text-[11px]">Role: </span>
                      <span className="font-semibold text-accent font-mono">{selectedNode.role}</span>
                    </div>
                    <RiskBadge value={selectedNode.containment_status} />
                  </div>
                </div>

                {/* Risk and Threat Classification */}
                <div className="bg-panel border border-border rounded p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-muted uppercase font-mono">Forensic Risk Score</span>
                    <span
                      className="font-bold font-mono text-sm"
                      style={{ color: getRiskColor(selectedNode.risk_score) }}
                    >
                      {selectedNode.risk_score.toFixed(1)} / 10
                    </span>
                  </div>

                  <div className="w-full bg-border rounded-full h-1.5 overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${Math.min(100, selectedNode.risk_score * 10)}%`,
                        backgroundColor: getRiskColor(selectedNode.risk_score),
                      }}
                    />
                  </div>

                  <div className="flex items-center justify-between text-[11px] pt-1">
                    <span className="text-muted">Classification:</span>
                    <span
                      className="font-semibold font-mono"
                      style={{ color: getRiskColor(selectedNode.risk_score) }}
                    >
                      {getRiskCategory(selectedNode.risk_score)}
                    </span>
                  </div>
                </div>

                {/* Telemetry Metrics */}
                <div className="bg-panel border border-border rounded p-3 space-y-2">
                  <div className="text-[10px] text-muted uppercase font-mono tracking-wider">
                    Observed Host Telemetry
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                    <div className="bg-bg p-2 rounded border border-border/50">
                      <div className="text-[10px] text-muted">Total Packets</div>
                      <div className="text-white font-bold mt-0.5">
                        {selectedNode.total_packets.toLocaleString()}
                      </div>
                    </div>
                    <div className="bg-bg p-2 rounded border border-border/50">
                      <div className="text-[10px] text-muted">Total Bytes</div>
                      <div className="text-white font-bold mt-0.5">
                        {formatBytes(selectedNode.total_bytes)}
                      </div>
                    </div>
                    <div className="bg-bg p-2 rounded border border-border/50">
                      <div className="text-[10px] text-muted">Bytes Outbound</div>
                      <div className="text-gray-300 mt-0.5">
                        {formatBytes(selectedNode.bytes_sent)}
                      </div>
                    </div>
                    <div className="bg-bg p-2 rounded border border-border/50">
                      <div className="text-[10px] text-muted">Bytes Inbound</div>
                      <div className="text-gray-300 mt-0.5">
                        {formatBytes(selectedNode.bytes_recv)}
                      </div>
                    </div>
                    <div className="bg-bg p-2 rounded border border-border/50">
                      <div className="text-[10px] text-muted">Connections</div>
                      <div className="text-white font-bold mt-0.5">{selectedNode.degree}</div>
                    </div>
                    <div className="bg-bg p-2 rounded border border-border/50">
                      <div className="text-[10px] text-muted">Fan-Out Ratio</div>
                      <div className="text-gray-300 mt-0.5">{selectedNode.fan_out_ratio.toFixed(2)}</div>
                    </div>
                  </div>
                </div>

                {/* Protocols */}
                <div>
                  <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1.5">
                    Protocols Observed
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedNode.protocols.length > 0 ? (
                      selectedNode.protocols.map((proto) => (
                        <span
                          key={proto}
                          className="px-2 py-0.5 bg-panel border border-border rounded font-mono text-[11px] text-accent"
                        >
                          {proto}
                        </span>
                      ))
                    ) : (
                      <span className="text-muted text-[11px] italic">No protocols recorded</span>
                    )}
                  </div>
                </div>

                {/* Detection Alerts & Subengine Findings */}
                <div>
                  <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                    <Shield size={12} className="text-danger" />
                    Forensic Engine Alerts ({selectedNode.subengine_alerts.length})
                  </div>
                  <div className="space-y-1.5">
                    {selectedNode.subengine_alerts.length > 0 ? (
                      selectedNode.subengine_alerts.map((alert, idx) => (
                        <div
                          key={idx}
                          className="p-2 rounded bg-danger/10 border border-danger/25 text-gray-200 text-[11px] leading-tight"
                        >
                          {alert}
                        </div>
                      ))
                    ) : (
                      <div className="text-muted text-[11px] italic bg-panel p-2 rounded border border-border/50">
                        No adverse sub-engine alerts flagged for this host.
                      </div>
                    )}
                  </div>
                </div>

                {/* Connected Peers */}
                <div>
                  <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1.5">
                    Connected Peers ({selectedNode.connected_hosts.length})
                  </div>
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {selectedNode.connected_hosts.map((peerIp) => (
                      <button
                        key={peerIp}
                        onClick={() => {
                          const target = nodes.find((n) => n.id === peerIp)
                          if (target) setSelectedNode(target)
                        }}
                        className="w-full text-left px-2.5 py-1.5 bg-panel hover:bg-border rounded text-[11px] font-mono text-gray-300 flex items-center justify-between group transition-colors"
                      >
                        <span>{peerIp}</span>
                        <ArrowRight size={11} className="text-muted group-hover:text-white" />
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* LINK DETAILS VIEW */}
            {selectedLink && (
              <div className="space-y-4 text-xs">
                <div className="bg-panel border border-border rounded p-3 space-y-2">
                  <div className="text-[10px] text-muted uppercase font-mono">Communication Vector</div>
                  <div className="space-y-1.5 font-mono">
                    <div className="flex items-center justify-between">
                      <span className="text-muted">Source IP:</span>
                      <span className="text-white font-bold">{selectedLink.source}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-muted">Destination IP:</span>
                      <span className="text-white font-bold">{selectedLink.target}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-muted">Direction:</span>
                      <span className="text-accent uppercase">{selectedLink.direction}</span>
                    </div>
                  </div>
                </div>

                <div className="bg-panel border border-border rounded p-3 space-y-2">
                  <div className="text-[10px] text-muted uppercase font-mono">Connection Telemetry</div>
                  <div className="grid grid-cols-2 gap-2 font-mono">
                    <div className="bg-bg p-2 rounded border border-border/50">
                      <div className="text-[10px] text-muted">Transferred Bytes</div>
                      <div className="text-white font-bold mt-0.5">
                        {formatBytes(selectedLink.bytes)}
                      </div>
                    </div>
                    <div className="bg-bg p-2 rounded border border-border/50">
                      <div className="text-[10px] text-muted">Packet Count</div>
                      <div className="text-white font-bold mt-0.5">
                        {selectedLink.packet_count.toLocaleString()}
                      </div>
                    </div>
                    <div className="bg-bg p-2 rounded border border-border/50">
                      <div className="text-[10px] text-muted">Primary Protocol</div>
                      <div className="text-accent font-bold mt-0.5">{selectedLink.protocol}</div>
                    </div>
                    <div className="bg-bg p-2 rounded border border-border/50">
                      <div className="text-[10px] text-muted">Anomaly State</div>
                      <div
                        className={`font-bold mt-0.5 ${
                          selectedLink.is_anomalous ? 'text-danger' : 'text-success'
                        }`}
                      >
                        {selectedLink.is_anomalous ? 'ANOMALOUS' : 'NORMAL'}
                      </div>
                    </div>
                  </div>
                </div>

                {selectedLink.ports.length > 0 && (
                  <div>
                    <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1.5">
                      Ports Involved ({selectedLink.ports.length})
                    </div>
                    <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                      {selectedLink.ports.map((p) => (
                        <span
                          key={p}
                          className="px-2 py-0.5 bg-panel border border-border rounded font-mono text-[11px] text-gray-300"
                        >
                          :{p}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Visual Legend */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-3 bg-panel border border-border rounded-lg text-xs text-muted">
        <div className="flex items-center gap-6">
          <span className="font-semibold text-gray-300 uppercase tracking-wider text-[11px]">
            Node Classifications:
          </span>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full bg-success" />
            <span className="text-white">Normal (&lt;3.0)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full bg-yellow-500" />
            <span className="text-white">Low Risk (3.0–4.9)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full bg-orange-500" />
            <span className="text-white">Suspicious (5.0–6.9)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full bg-danger" />
            <span className="text-white">High Risk / C2 (≥7.0)</span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <span className="font-semibold text-gray-300 uppercase tracking-wider text-[11px]">Links:</span>
          <div className="flex items-center gap-1.5">
            <div className="w-6 h-0.5 bg-slate-500" />
            <span>Standard Flow</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-6 h-0.5 bg-danger" />
            <span>Anomalous Vector</span>
          </div>
        </div>
      </div>
    </div>
  )
}

// Distance from point to line segment
function distToSegment(
  p: { x: number; y: number },
  v: { x: number; y: number },
  w: { x: number; y: number }
): number {
  const l2 = (v.x - w.x) * (v.x - w.x) + (v.y - w.y) * (v.y - w.y)
  if (l2 === 0) return Math.hypot(p.x - v.x, p.y - v.y)
  let t = ((p.x - v.x) * (w.x - v.x) + (p.y - v.y) * (w.y - v.y)) / l2
  t = Math.max(0, Math.min(1, t))
  return Math.hypot(p.x - (v.x + t * (w.x - v.x)), p.y - (v.y + t * (w.y - v.y)))
}
