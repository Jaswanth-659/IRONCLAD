import React, { useRef, useState } from 'react'
import { Upload, CheckCircle, XCircle, Loader2 } from 'lucide-react'

type Stage = 'idle' | 'uploading' | 'processing' | 'done' | 'error'

export default function PcapUpload({ onComplete }: { onComplete?: () => void }) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [stage, setStage] = useState<Stage>('idle')
  const [message, setMessage] = useState('')
  const [dragging, setDragging] = useState(false)

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
      setStage('processing'); setMessage(`Analysis started · Session: ${data.task_id}`)
      setTimeout(() => { setStage('done'); setMessage('Analysis complete.'); onComplete?.() }, 5000)
    } catch (e) {
      setStage('error'); setMessage(e instanceof Error ? e.message : 'Upload failed')
    }
  }

  return (
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
  )
}
