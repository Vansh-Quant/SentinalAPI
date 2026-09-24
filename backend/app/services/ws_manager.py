"""WebSocket Connection Manager for live scan progress and event streaming."""

import logging
from collections import defaultdict
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket connections grouped by scan_id."""

    def __init__(self) -> None:
        self.active_connections: dict[str, set[WebSocket]] = defaultdict(set)

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections[scan_id].add(websocket)
        logger.info("WebSocket client connected for scan %s", scan_id)

    def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        if scan_id in self.active_connections:
            self.active_connections[scan_id].discard(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
        logger.info("WebSocket client disconnected for scan %s", scan_id)

    async def broadcast_to_scan(self, scan_id: str, message: dict[str, Any]) -> None:
        """Send a JSON payload to all clients listening to a specific scan_id."""
        if scan_id not in self.active_connections:
            return

        dead_sockets: list[WebSocket] = []
        for connection in list(self.active_connections[scan_id]):
            try:
                await connection.send_json(message)
            except Exception as exc:
                logger.warning("Error broadcasting to socket on scan %s: %s", scan_id, exc)
                dead_sockets.append(connection)

        for dead in dead_sockets:
            self.disconnect(scan_id, dead)


manager = ConnectionManager()
