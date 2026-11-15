import React from 'react'
import type { LucideIcon } from 'lucide-react'

interface Props {
  title: string
  value: string | number
  icon: LucideIcon
  color?: string
  subtitle?: string
}

export default function MetricCard({ title, value, icon: Icon, color = 'text-accent', subtitle }: Props) {
  return (
    <div className="bg-panel border border-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-muted uppercase tracking-wider">{title}</span>
        <Icon size={15} className={color} />
      </div>
      <div className={`text-2xl font-bold font-mono ${color}`}>{value}</div>
      {subtitle && <div className="text-xs text-muted mt-1">{subtitle}</div>}
    </div>
  )
}
