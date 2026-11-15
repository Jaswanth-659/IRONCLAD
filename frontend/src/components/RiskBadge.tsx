import React from 'react'

const STYLES: Record<string, string> = {
  CRITICAL:                   'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH:                       'bg-orange-500/15 text-orange-400 border-orange-500/30',
  HIGH_RISK:                  'bg-orange-500/15 text-orange-400 border-orange-500/30',
  SUSPICIOUS:                 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  SECONDARY_INVESTIGATION:    'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  MEDIUM:                     'bg-yellow-600/15 text-yellow-500 border-yellow-600/30',
  NORMAL:                     'bg-green-500/15 text-green-400 border-green-500/30',
  BENIGN:                     'bg-green-500/15 text-green-400 border-green-500/30',
  LOW:                        'bg-blue-500/15 text-blue-400 border-blue-500/30',
  CONFIRMED_INDICATOR_MATCH:  'bg-purple-500/15 text-purple-400 border-purple-500/30',
  HIGH_PRIORITY_ESCALATION:   'bg-red-500/15 text-red-400 border-red-500/30',
}

export default function RiskBadge({ value }: { value: string }) {
  const cls = STYLES[value] ?? 'bg-gray-500/15 text-gray-400 border-gray-500/30'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded border text-xs font-semibold uppercase tracking-wide ${cls}`}>
      {value.replace(/_/g, ' ')}
    </span>
  )
}
