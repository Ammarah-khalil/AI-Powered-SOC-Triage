"""
WebSocket broadcast layer.

Anything that changes incident state (the simulator today, a real Kafka
consumer later) calls `manager.broadcast(...)` and every connected dashboard
gets the update pushed immediately -- no polling.
"""
from __future__ import annotations

import asyncio
import json

from fastapi import WebSocket

from .models import Incident


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)

    async def broadcast(self, event_type: str, incident: Incident) -> None:
        payload = json.dumps({"type": event_type, "incident": json.loads(incident.model_dump_json())})
        dead: list[WebSocket] = []
        async with self._lock:
            connections = list(self._connections)
        for ws in connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)


manager = ConnectionManager()
