import { useState, useEffect, useCallback } from 'react'

export function useApi<T>(url: string, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(url)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setData(await res.json())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Request failed')
    } finally {
      setLoading(false)
    }
  }, [url]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { void fetchData() }, [fetchData, ...deps]) // eslint-disable-line react-hooks/exhaustive-deps

  return { data, loading, error, refetch: fetchData }
}
