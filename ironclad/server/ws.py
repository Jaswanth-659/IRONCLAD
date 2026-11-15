"""
IRONCLAD WebSocket Broadcasting and Subscription Manager.

Maintains active client connections, broadcasts real-time telemetry analysis
events, alert triggers, and containment status updates with graceful reconnection handling.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Set

from fastapi import WebSocket, WebSocketDisconnect

from ironclad.core.logging import get_logger

logger = get_logger("server.ws")


class WebSocketManager:
    """
    Central connection hub for real-time WebSocket communication
    between FastAPI backend and the React SOC dashboard.
    """

    def __init__(self) -> None:
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept new WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        logger.info("Client connected to WebSocket. Total active: %d", len(self.active_connections))
        # Send initial welcome handshake
        await self.send_personal_message(
            {
                "type": "CONNECTION_ESTABLISHED",
                "message": "Connected to IRONCLAD Real-Time Telemetry Stream",
                "client_count": len(self.active_connections),
            },
            websocket,
        )

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove disconnected client."""
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info("Client disconnected from WebSocket. Remaining: %d", len(self.active_connections))

    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket) -> None:
        """Send direct payload to single client."""
        try:
            await websocket.send_text(json.dumps(message))
        except Exception as e:
            logger.warning("Failed to send personal message: %s", e)

    async def broadcast(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        Broadcast structured telemetry or alert payload to all connected subscribers.
        """
        payload = json.dumps({"type": event_type, "data": data})
        dead_connections: List[WebSocket] = []

        async with self._lock:
            for connection in self.active_connections:
                try:
                    await connection.send_text(payload)
                except Exception as e:
                    logger.warning("Error broadcasting to connection: %s", e)
                    dead_connections.append(connection)

            for dead in dead_connections:
                if dead in self.active_connections:
                    self.active_connections.remove(dead)


# Global singleton instance
ws_manager = WebSocketManager()
