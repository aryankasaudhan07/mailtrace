"""Live case feed. Drives the alert panel. Track A wires Redis pub/sub in phase 4."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.api import events

router = APIRouter(tags=["stream"])


@router.websocket("/api/stream")
async def stream(ws: WebSocket) -> None:
    await ws.accept()
    await ws.send_json({"type": "hello", "message": "mailtrace stream connected"})
    q = events.subscribe()
    try:
        while True:
            # Forward scored verdicts published in-process (see app/api/events.py);
            # TODO-A: swap the source for the Redis channel in phase 4.
            try:
                event = await asyncio.wait_for(q.get(), timeout=15)
                await ws.send_json(event)
            except asyncio.TimeoutError:
                await ws.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        return
    finally:
        events.unsubscribe(q)
