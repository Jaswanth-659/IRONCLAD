import { useEffect, useRef, useState, useCallback } from 'react'

export interface WsMessage {
  type: string
  data?: Record<string, any>
  [key: string]: unknown
}

export function useWebSocket(url: string) {
  const ws = useRef<WebSocket | null>(null)
  const [connected, setConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WsMessage | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const shouldConnect = useRef(true)

  const connect = useCallback(() => {
    if (!shouldConnect.current) return
    if (ws.current?.readyState === WebSocket.OPEN) return
    try {
      const socket = new WebSocket(url)
      ws.current = socket
      socket.onopen = () => setConnected(true)
      socket.onclose = () => {
        setConnected(false)
        if (shouldConnect.current) {
          reconnectTimer.current = setTimeout(connect, 3000)
        }
      }
      socket.onerror = () => socket.close()
      socket.onmessage = (e) => {
        try { setLastMessage(JSON.parse(e.data as string) as WsMessage) } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
  }, [url])

  useEffect(() => {
    shouldConnect.current = true
    connect()
    return () => {
      shouldConnect.current = false
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      ws.current?.close()
    }
  }, [connect])

  const send = useCallback((msg: string) => {
    if (ws.current?.readyState === WebSocket.OPEN) ws.current.send(msg)
  }, [])

  return { connected, lastMessage, send }
}
