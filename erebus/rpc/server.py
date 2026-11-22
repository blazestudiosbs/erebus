"""FastAPI server exposing live framework state to the 3D dashboard.

Endpoints:
    GET  /health        → {"ok": true, "edition": ...}
    GET  /graph         → {nodes, links, meta}  (live framework state)
    GET  /events        → Server-Sent Events stream (fallback for /ws)
    WS   /ws/events     → push stream of framework events as JSON

This layer is optional. FastAPI is imported at module scope (guarded) so that
parameter annotations resolve correctly under ``from __future__ import
annotations`` — but importing this module without the ``rpc`` extra installed
raises a clear error only when you try to build the app, not on import.
"""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, StreamingResponse
    _FASTAPI_OK = True
except ModuleNotFoundError:  # fastapi is an optional extra
    FastAPI = WebSocket = WebSocketDisconnect = object  # type: ignore[assignment,misc]
    CORSMiddleware = HTMLResponse = StreamingResponse = None  # type: ignore[assignment]
    _FASTAPI_OK = False

from .events import EventBridge
from .graph import build_graph

_DASHBOARD = Path(__file__).with_name("dashboard.html")

_RPC_HINT = 'The RPC server needs FastAPI + uvicorn. Install with: pip install -e ".[rpc]"'


def create_app(framework: Any) -> Any:
    """Build the FastAPI app bound to a live framework instance."""
    if not _FASTAPI_OK:
        raise RuntimeError(_RPC_HINT)

    state: dict[str, Any] = {"bridge": None, "unsub": None}

    @asynccontextmanager
    async def lifespan(app: Any) -> Any:
        loop = asyncio.get_running_loop()
        bridge = EventBridge(loop)
        state["bridge"] = bridge
        state["unsub"] = framework.events.subscribe(None, bridge.publish)
        try:
            yield
        finally:
            if callable(state.get("unsub")):
                state["unsub"]()

    app = FastAPI(title="Erebus RPC", version="0.1.0", lifespan=lifespan)
    # The dashboard artifact loads from a different origin; allow it to read.
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
    )

    def _graph() -> dict[str, Any]:
        return build_graph(framework.loader, framework.store, framework.config)

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> Any:
        if _DASHBOARD.exists():
            return HTMLResponse(_DASHBOARD.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>Erebus RPC</h1><p>dashboard.html not found; API at /graph</p>")

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "ok": True,
            "edition": framework.config.get("edition", "workstation"),
            "clients": state["bridge"].client_count if state["bridge"] else 0,
        }

    @app.get("/graph")
    async def graph() -> dict[str, Any]:
        return _graph()

    @app.websocket("/ws/events")
    async def ws_events(ws: WebSocket) -> None:
        await ws.accept()
        bridge: EventBridge = state["bridge"]
        q = bridge.add_client()
        # prime the client with the current graph so it can draw immediately
        await ws.send_text(json.dumps({"type": "graph.snapshot", "data": _graph()}))
        try:
            while True:
                await ws.send_text(json.dumps(await q.get()))
        except WebSocketDisconnect:
            pass
        finally:
            bridge.remove_client(q)

    @app.get("/events")
    async def sse_events() -> Any:
        """SSE fallback for clients that can't open a WebSocket."""
        bridge: EventBridge = state["bridge"]
        q = bridge.add_client()

        async def gen() -> Any:
            try:
                yield f"data: {json.dumps({'type': 'graph.snapshot', 'data': _graph()})}\n\n"
                while True:
                    yield f"data: {json.dumps(await q.get())}\n\n"
            finally:
                bridge.remove_client(q)

        return StreamingResponse(gen(), media_type="text/event-stream")

    return app


def serve(framework: Any, host: str = "127.0.0.1", port: int = 8777) -> None:
    """Boot the RPC server (blocking). Requires the ``rpc`` extra."""
    try:
        import uvicorn
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(_RPC_HINT) from exc
    uvicorn.run(create_app(framework), host=host, port=port, log_level="info")


def serve_in_thread(framework: Any, host: str = "127.0.0.1", port: int = 8777) -> Any:
    """Boot the RPC server in a background daemon thread sharing ``framework``.

    Returns ``(server, thread)``. Unlike :func:`serve`, this does not block: the
    caller (e.g. the interactive console) keeps running in the foreground while
    the dashboard reads the *same* framework — so a run typed in the console
    streams live over ``/ws/events``. Requires the ``rpc`` extra.
    """
    if not _FASTAPI_OK:
        raise RuntimeError(_RPC_HINT)
    import threading

    try:
        import uvicorn
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(_RPC_HINT) from exc

    # uvicorn skips signal handlers off the main thread, so running here is safe.
    config = uvicorn.Config(create_app(framework), host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="erebus-rpc", daemon=True)
    thread.start()
    return server, thread
