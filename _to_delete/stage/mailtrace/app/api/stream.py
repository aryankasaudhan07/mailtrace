"""Live case feed. Drives the alert panel. Track A wires Redis pub/sub in phase 4."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["stream"])


@router.websocket("/api/stream")
async def stream(ws: WebSocket) -> None:
    await ws.accept()
    await ws.send_json({"type": "hello", "message": "mailtrace stream connected"})
    try:
        while True:
            # TODO-A: subscribe to the Redis channel the Celery worker publishes
            # scored verdicts to, and forward them. Heartbeat until then.
            await asyncio.sleep(15)
            await ws.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        return
