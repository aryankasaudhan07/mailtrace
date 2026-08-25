"""
In-process event broadcast for the live dashboard.

A deliberately tiny stand-in for the phase-4 Redis pub/sub: works only within
one process, which is exactly the demo topology (uvicorn serves both the API
and the WebSocket). When Track A wires Redis, publish() grows a Redis client
and nothing else changes.
"""

from __future__ import annotations

import asyncio
from typing import Any

_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()


def subscribe() -> asyncio.Queue[dict[str, Any]]:
    """Register a new subscriber queue. Caller must unsubscribe() it."""
    q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
    _subscribers.add(q)
    return q


def unsubscribe(q: asyncio.Queue[dict[str, Any]]) -> None:
    _subscribers.discard(q)


def publish(event: dict[str, Any]) -> None:
    """Fan an event out to every connected subscriber. Never blocks or raises."""
    for q in list(_subscribers):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            # A stalled client must not stall the API; drop for that client.
            pass
