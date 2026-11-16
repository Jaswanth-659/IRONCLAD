import React from 'react'

const STYLES: Record<string, string> = {
  CRITICAL:                   'border-red-900/70 bg-red-950/40 text-red-500',
  CRITICAL_ALERT:             'border-red-900/70 bg-red-950/40 text-red-500',
  HIGH:                       'border-orange-900/70 bg-orange-950/40 text-orange-500',
  HIGH_RISK:                  'border-orange-900/70 bg-orange-950/40 text-orange-500',
  SUSPICIOUS:                 'border-yellow-900/70 bg-yellow-950/40 text-yellow-500',
  SECONDARY_INVESTIGATION:    'border-yellow-900/70 bg-yellow-950/40 text-yellow-500',
  MEDIUM:                     'border-yellow-900/70 bg-yellow-950/40 text-yellow-500',
  NORMAL:                     'border-emerald-900/70 bg-emerald-950/40 text-emerald-400',
  BENIGN:                     'border-emerald-900/70 bg-emerald-950/40 text-emerald-400',
  LOW:                        'border-blue-900/70 bg-blue-950/40 text-blue-400',
  CONFIRMED_INDICATOR_MATCH:  'border-purple-900/70 bg-purple-950/40 text-purple-400',
  HIGH_PRIORITY_ESCALATION:   'border-red-900/70 bg-red-950/40 text-red-500',
  VALID_CHECKSUM:             'border-emerald-900/70 bg-emerald-950/40 text-emerald-400',
  CORRUPTED_DATA:             'border-red-900/70 bg-red-950/40 text-red-500',
  DUPLICATE:                  'border-yellow-900/70 bg-yellow-950/40 text-yellow-500',
  CONFIRMED:                  'border-blue-900/70 bg-blue-950/40 text-blue-400',
  INFERRED:                   'border-amber-900/70 bg-amber-950/40 text-amber-400',
  UNAVAILABLE:                'border-zinc-800 bg-zinc-900/40 text-zinc-400',
  ACTIVE:                     'border-emerald-900/70 bg-emerald-950/40 text-emerald-400',
  TEST_TRAFFIC_ONLY:          'border-amber-900/70 bg-amber-950/40 text-amber-400',
  COMPLETED:                  'border-emerald-900/70 bg-emerald-950/40 text-emerald-400',
  RUNNING:                    'border-blue-900/70 bg-blue-950/40 text-blue-400',
  FAILED:                     'border-red-900/70 bg-red-950/40 text-red-500',
  NOT_EXECUTED:               'border-zinc-800 bg-zinc-900/40 text-zinc-400',
}

export default function RiskBadge({ value }: { value: string }) {
  const cls = STYLES[value] ?? 'border-zinc-800 bg-zinc-900/40 text-zinc-400'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-mono font-bold uppercase tracking-wider ${cls}`}>
      {value.replace(/_/g, ' ')}
    </span>
  )
}
