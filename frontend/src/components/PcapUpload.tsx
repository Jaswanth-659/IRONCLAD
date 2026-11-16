import React, { useRef, useState, useEffect } from 'react'
import { Upload, CheckCircle, XCircle, Loader2, Zap } from 'lucide-react'
import { useWebSocket } from '../hooks/useWebSocket'

type Stage = 'idle' | 'uploading' | 'processing' | 'done' | 'error'

export default function PcapUpload({ onComplete }: { onComplete?: () => void }) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [stage, setStage] = useState<Stage>('idle')
  const [message, setMessage] = useState('')
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const { lastMessage } = useWebSocket('ws://localhost:8000/ws')

  useEffect(() => {
    if (!lastMessage || !activeTaskId) return
    const msgType = String(lastMessage.type || '').toUpperCase()
    const dataObj = (lastMessage.data || {}) as Record<string, any>
    const msgTaskId = String(dataObj.task_id || '')

    if (msgTaskId === activeTaskId) {
      if (msgType === 'ANALYSIS_PROGRESS') {
        const step = String(dataObj.step || 'Analyzing...')
        const progress = Math.round(Number(dataObj.progress || 0))
        setMessage(`${step} (${progress}%)`)
      } else if (msgType === 'ANALYSIS_COMPLETED' || msgType === 'ANALYSIS_COMPLETE') {
        const risk = Number(dataObj.overall_risk_score ?? 0).toFixed(1)
        setStage('done')
        setMessage(`Analysis complete · Risk: ${risk}/10`)
        onComplete?.()
        setTimeout(() => {
          setStage('idle')
          setMessage('')
          setActiveTaskId(null)
        }, 5000)
      } else if (msgType === 'ANALYSIS_FAILED') {
        setStage('error')
        setMessage(`Analysis failed: ${String(dataObj.error || 'Unknown error')}`)
        setActiveTaskId(null)
      }
    }
  }, [lastMessage, activeTaskId, onComplete])

  const handleFile = async (file: File) => {
    if (!file.name.match(/\.(pcap|pcapng)$/i)) {
      setStage('error'); setMessage('Only .pcap / .pcapng files accepted.'); return
    }
    setStage('uploading'); setMessage(`Uploading ${file.name}…`)
    const form = new FormData()
    form.append('file', file)
    try {
      const res = await fetch('/api/upload/pcap', { method: 'POST', body: form })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json() as { task_id: string }
      setActiveTaskId(data.task_id)
      setStage('processing')
      setMessage(`Analysis started · Session: ${data.task_id.slice(0, 8)}...`)

      // Fallback timer if WebSocket is disconnected
      setTimeout(() => {
        if (stage === 'processing') {
          setStage('done')
          setMessage('Analysis complete.')
          onComplete?.()
        }
      }, 15000)
    } catch (e) {
      setStage('error'); setMessage(e instanceof Error ? e.message : 'Upload failed')
      setActiveTaskId(null)
    }
  }

  const handleSimulateMultiClient = async (e: React.MouseEvent) => {
    e.stopPropagation()
    setStage('uploading')
    setMessage('Generating multi-client attack scenario (4 laptops hitting primary laptop + controlled data loss)...')
    try {
      const res = await fetch('/api/upload/generate-multi-client', { method: 'POST' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json() as { task_id: string }
      setActiveTaskId(data.task_id)
      setStage('processing')
      setMessage(`Multi-laptop scenario generated · Analysis started (Session ${data.task_id.slice(0, 8)})...`)

      setTimeout(() => {
        if (stage === 'processing') {
          setStage('done')
          setMessage('Analysis complete.')
          onComplete?.()
        }
      }, 15000)
    } catch (err) {
      setStage('error')
      setMessage(err instanceof Error ? err.message : 'Simulation failed')
      setActiveTaskId(null)
    }
  }

  return (
    <div className="space-y-2">
      <div
        onClick={() => fileRef.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) void handleFile(f) }}
        className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors select-none ${
          dragging ? 'border-accent bg-accent/5' : 'border-border hover:border-accent/40'
        }`}
      >
        <input ref={fileRef} type="file" accept=".pcap,.pcapng" className="hidden"
          onChange={(e) => { const f = e.target.files?.[0]; if (f) void handleFile(f) }} />

        {stage === 'idle' && (
          <div className="flex flex-col items-center gap-2">
            <Upload size={28} className="text-muted" />
            <p className="text-sm text-muted">Drop PCAP here or <span className="text-accent">browse</span></p>
            <p className="text-xs text-muted">Accepts .pcap · .pcapng</p>
          </div>
        )}
        {(stage === 'uploading' || stage === 'processing') && (
          <div className="flex items-center justify-center gap-2 text-sm text-accent">
            <Loader2 size={16} className="animate-spin" /> {message}
          </div>
        )}
        {stage === 'done' && (
          <div className="flex items-center justify-center gap-2 text-sm text-success">
            <CheckCircle size={16} /> {message}
          </div>
        )}
        {stage === 'error' && (
          <div className="flex items-center justify-center gap-2 text-sm text-danger">
            <XCircle size={16} /> {message}
          </div>
        )}
      </div>

      <div className="flex items-center justify-end">
        <button
          type="button"
          onClick={handleSimulateMultiClient}
          disabled={stage === 'uploading' || stage === 'processing'}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-accent bg-accent/10 border border-accent/30 rounded-md hover:bg-accent/20 transition-colors disabled:opacity-50"
        >
          <Zap size={13} />
          Simulate Multi-Laptop Attack (&gt;2 Laptops + Controlled Loss)
        </button>
      </div>
    </div>
  )
}
