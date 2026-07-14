"""WebSocket connection manager"""

from fastapi import WebSocket
from typing import List


class ConnectionManager:
    def __init__(self):
        self._connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self._connections:
            self._connections.remove(ws)

    async def broadcast_tag_update(self, key: str, data: dict):
        for ws in self._connections:
            try:
                await ws.send_json({
                    "type": "tag_update",
                    "key": key,
                    "data": data,
                })
            except Exception:
                pass

    async def broadcast_event(self, event: dict):
        for ws in self._connections:
            try:
                await ws.send_json({
                    "type": "event",
                    "event": event,
                    "active_count": event.get("active_count"),
                })
            except Exception:
                pass

    @property
    def count(self):
        return len(self._connections)


ws_manager = ConnectionManager()
