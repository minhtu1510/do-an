"""WebSocket connection manager"""

from fastapi import WebSocket
from typing import List

from ..notify import notify_event, telegram_configured


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

        is_notify_worthy = event.get("severity") == "ERROR" or str(event.get("event_type", "")).startswith("ATTACK_")
        if is_notify_worthy and telegram_configured():
            await notify_event(event)

    async def broadcast_scenario_result(self, result: dict):
        for ws in self._connections:
            try:
                await ws.send_json({
                    "type": "scenario_result",
                    "result": result,
                })
            except Exception:
                pass

    async def broadcast_system_resources(self, resources: dict):
        for ws in self._connections:
            try:
                await ws.send_json({
                    "type": "system_resources",
                    **resources,
                })
            except Exception:
                pass

    @property
    def count(self):
        return len(self._connections)


ws_manager = ConnectionManager()
