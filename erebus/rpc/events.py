"""Bridge the framework's (synchronous, multi-threaded) EventBus to async
WebSocket subscribers.

The framework publishes events from worker threads. The web server runs an
asyncio loop. :class:`EventBridge` sits between them: it subscribes to the bus
and, for every event, hands a JSON-serializable dict to each connected client's
asyncio queue using ``loop.call_soon_threadsafe`` — the only safe way to touch
loop objects from another thread.
"""
from __future__ import annotations

import asyncio
from typing import Any


def event_to_dict(event: Any) -> dict[str, Any]:
    """Serialize a framework ``Event`` (or any obj with type/data/ts) to a dict."""
    return {
        "type": getattr(event, "type", "unknown"),
        "data": getattr(event, "data", {}) or {},
        "ts": getattr(event, "ts", None),
    }


class EventBridge:
    """Fan-out from a sync EventBus to any number of asyncio queues.

    Usage::

        bridge = EventBridge(loop)
        unsubscribe = bus.subscribe(None, bridge.publish)   # from framework thread
        q = bridge.add_client()                             # from the event loop
        ...                                                 # await q.get() in the WS handler
        bridge.remove_client(q)
    """

    def __init__(self, loop: asyncio.AbstractEventLoop, maxsize: int = 1000) -> None:
        self._loop = loop
        self._maxsize = maxsize
        self._clients: set[asyncio.Queue[dict[str, Any]]] = set()

    def add_client(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self._maxsize)
        self._clients.add(q)
        return q

    def remove_client(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        self._clients.discard(q)

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def publish(self, event: Any) -> None:
        """Called from framework worker threads. Never blocks or raises upward."""
        payload = event_to_dict(event)
        self._loop.call_soon_threadsafe(self._dispatch, payload)

    def _dispatch(self, payload: dict[str, Any]) -> None:
        # Runs on the event loop thread. Drop on a full queue rather than block,
        # so one slow client can't stall the bus or the other clients.
        for q in list(self._clients):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass
