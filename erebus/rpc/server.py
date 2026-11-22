"""FastAPI server exposing framework state to the 3D dashboard and a control API.

Read endpoints (``/graph``, ``/modules``, ``/hosts``, ``/services``,
``/findings``, ``/sessions``) are same-origin only: CORS is restricted (no
wildcard) so a drive-by page cannot read them cross-origin. The event streams
(``WS /ws/events``, ``GET /events``) bypass CORS, so they require the bearer
token; ``POST /jobs`` (which starts a module) requires it too and runs through
``Framework.run()`` — i.e. the scope gate. The token is generated at startup
unless supplied, printed by the CLI, and injected into the served dashboard so
the same-origin UI can use it.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Optional  # noqa: UP035

try:
    from fastapi import (
        Depends,
        FastAPI,
        Header,
        HTTPException,
        Request,
        WebSocket,
        WebSocketDisconnect,
    )
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, Response, StreamingResponse
    _FASTAPI_OK = True
except ModuleNotFoundError:  # fastapi is an optional extra
    Depends = FastAPI = Header = HTTPException = Request = object  # type: ignore[assignment,misc]
    WebSocket = WebSocketDisconnect = object  # type: ignore[assignment,misc]
    CORSMiddleware = HTMLResponse = StreamingResponse = None  # type: ignore[assignment,misc]
    _FASTAPI_OK = False

from erebus.core.options import OptionError
from erebus.core.scope import ScopeError

from .events import EventBridge
from .graph import build_graph

_DASHBOARD = Path(__file__).with_name("dashboard.html")
_RPC_HINT = 'The RPC server needs FastAPI + uvicorn. Install with: pip install -e ".[rpc]"'
_LIVE_HINT = "the live (amnesic) edition does not serve the dashboard"


def create_app(framework: Any, token: str | None = None,
               cors_origins: list[str] | None = None) -> Any:
    """Build the FastAPI app bound to a live framework instance.

    ``token`` guards the write endpoint and the event streams; one is generated
    if not supplied and exposed as ``app.state.token``. ``cors_origins`` is the
    allowlist for cross-origin reads (empty = same-origin only).
    """
    if not _FASTAPI_OK:
        raise RuntimeError(_RPC_HINT)
    if framework.config.get("edition") == "live":
        raise RuntimeError(_LIVE_HINT)

    token = token or secrets.token_urlsafe(24)
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
    app.state.token = token
    app.add_middleware(
        CORSMiddleware, allow_origins=cors_origins or [],
        allow_methods=["*"], allow_headers=["*"],
    )

    # NB: FastAPI evaluates these parameter annotations at runtime, and Python 3.9 can't
    # evaluate `str | None` / `dict[...]` there — so the two FastAPI-introspected params
    # below use typing.Optional/Dict on purpose (don't let pyupgrade rewrite them).
    def require_token(authorization: Optional[str] = Header(default=None)) -> None:  # noqa: UP045, UP007
        expected = f"Bearer {token}"
        if not authorization or not secrets.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="missing or invalid bearer token")

    def _stream_token_ok(conn: Any) -> bool:  # WebSocket or Request; both have query_params
        return secrets.compare_digest(conn.query_params.get("token", ""), token)

    def _notes_path() -> Path:
        env = os.environ.get("EREBUS_NOTES")
        return Path(env) if env else (Path.home() / ".erebus" / "notes.md")

    def _graph() -> dict[str, Any]:
        return build_graph(framework.loader, framework.store, framework.config)

    def _rows(rows: Any) -> list[dict[str, Any]]:
        return [dict(r) for r in rows]

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> Any:
        if not _DASHBOARD.exists():
            return HTMLResponse("<h1>Erebus RPC</h1><p>dashboard.html not found; API at /graph</p>")
        html = _DASHBOARD.read_text(encoding="utf-8")
        inject = f"<script>window.EREBUS_TOKEN={json.dumps(token)};</script>"
        if "</head>" in html:
            html = html.replace("</head>", inject + "</head>", 1)
        else:
            html = inject + html
        return HTMLResponse(html)

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

    @app.get("/modules")
    async def modules() -> dict[str, Any]:
        out = []
        for key, cls in framework.loader.all():
            mtype = getattr(cls, "type", None)
            out.append({
                "key": key,
                "name": getattr(cls, "name", key),
                "type": getattr(mtype, "value", str(mtype or "auxiliary")),
                "rank": getattr(getattr(cls, "rank", None), "name", "NORMAL"),
                "attack": list(getattr(cls, "attack", []) or []),
                "description": getattr(cls, "description", "") or "",
            })
        return {"modules": out}

    @app.get("/hosts")
    async def hosts() -> dict[str, Any]:
        return {"hosts": _rows(framework.store.hosts())}

    @app.get("/services")
    async def services() -> dict[str, Any]:
        return {"services": _rows(framework.store.services())}

    @app.get("/findings")
    async def findings() -> dict[str, Any]:
        return {"findings": _rows(framework.store.findings())}

    @app.get("/sessions")
    async def sessions() -> dict[str, Any]:
        return {"sessions": _rows(framework.store.sessions())}

    @app.get("/scope")
    async def scope_show() -> dict[str, Any]:
        return {"enabled": framework.scope.enabled, "rules": framework.scope.show()}

    @app.get("/research")
    async def research() -> dict[str, Any]:
        from ..research.fuzz import FuzzRunner
        crashes = []
        for row in framework.store.findings():
            r = dict(row)
            sev = str(r.get("severity") or "").lower()
            title = str(r.get("title") or "").lower()
            if "crash" in sev or "crash" in title or "fuzz" in title:
                crashes.append(r)
        try:
            afl = FuzzRunner().available()
        except Exception:
            afl = False
        return {"afl_available": afl, "crashes": crashes}

    @app.get("/report", dependencies=[Depends(require_token)])
    async def report(format: str = "html") -> Any:
        from ..reporting import report as rpt
        fmt = (format or "html").lower()
        data = rpt.collect(framework.store, loader=framework.loader)
        if fmt == "pdf":
            try:
                body = rpt.render_pdf(data, title="Erebus engagement report")
            except RuntimeError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from None
            disp = "attachment; filename=erebus-report.pdf"
            return Response(content=body, media_type="application/pdf",
                            headers={"Content-Disposition": disp})
        if fmt == "md":
            text = rpt.render_markdown(data)
            disp = "attachment; filename=erebus-report.md"
            return Response(content=text, media_type="text/markdown; charset=utf-8",
                            headers={"Content-Disposition": disp})
        return HTMLResponse(rpt.render_html(data, title="Erebus engagement report"))

    @app.post("/jobs", dependencies=[Depends(require_token)])
    async def start_job(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        key = str(payload.get("module", "")).strip()
        options = payload.get("options") or {}
        if not key:
            raise HTTPException(status_code=400, detail="missing 'module'")
        if not isinstance(options, dict):
            raise HTTPException(status_code=400, detail="'options' must be an object")
        try:
            module = framework.use(key)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown module: {key}") from None
        try:
            for k, v in options.items():
                module.set_option(str(k), str(v))
            jid = framework.run(module, background=True)
        except OptionError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        except ScopeError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from None
        return {"job": jid, "module": module.name}

    @app.post("/scope/allow", dependencies=[Depends(require_token)])
    async def scope_allow(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        target = str(payload.get("target", "")).strip()
        if not target:
            raise HTTPException(status_code=400, detail="missing 'target'")
        framework.scope.allow(target)
        from ..core.events import Event
        framework.events.publish(Event("scope.changed", {"action": "allow", "target": target}))
        return {"ok": True, "enabled": framework.scope.enabled, "rules": framework.scope.show()}

    @app.post("/scope/set", dependencies=[Depends(require_token)])
    async def scope_set(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        text = str(payload.get("text", ""))
        if payload.get("replace"):
            framework.scope.clear()
        framework.scope.load_text(text)
        framework.scope.enabled = True  # loading a scope turns the guardrail on
        from ..core.events import Event
        framework.events.publish(Event("scope.changed",
                                       {"action": "set", "rules": len(framework.scope.show())}))
        return {"ok": True, "enabled": framework.scope.enabled, "rules": framework.scope.show()}

    @app.post("/scope/mode", dependencies=[Depends(require_token)])
    async def scope_mode(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        enabled = payload.get("enabled")
        if not isinstance(enabled, bool):
            raise HTTPException(status_code=400, detail="'enabled' must be a boolean")
        framework.scope.enabled = enabled
        from ..core.events import Event
        framework.events.publish(Event("scope.changed",
                                       {"action": "mode", "enabled": enabled}))
        return {"ok": True, "enabled": framework.scope.enabled, "rules": framework.scope.show()}

    @app.get("/notes", dependencies=[Depends(require_token)])
    async def notes_get() -> dict[str, Any]:
        path = _notes_path()
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            text = ""
        return {"text": text, "path": str(path)}

    @app.post("/notes", dependencies=[Depends(require_token)])
    async def notes_set(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        text = str(payload.get("text", ""))
        path = _notes_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            raise HTTPException(status_code=500, detail=f"could not write notes: {exc}") from None
        return {"ok": True, "bytes": len(text.encode("utf-8")), "path": str(path)}

    @app.websocket("/ws/events")
    async def ws_events(ws: WebSocket) -> None:
        if not _stream_token_ok(ws):
            await ws.close(code=1008)
            return
        await ws.accept()
        bridge = state.get("bridge")
        if bridge is None:  # lifespan not ready — send a snapshot and let the client retry
            await ws.send_text(json.dumps({"type": "graph.snapshot", "data": _graph()}))
            await ws.close(code=1012)
            return
        q = bridge.add_client()
        await ws.send_text(json.dumps({"type": "graph.snapshot", "data": _graph()}))
        try:
            while True:
                await ws.send_text(json.dumps(await q.get()))
        except WebSocketDisconnect:
            pass
        finally:
            bridge.remove_client(q)

    @app.get("/events")
    async def sse_events(request: Request) -> Any:
        if not _stream_token_ok(request):
            raise HTTPException(status_code=401, detail="missing or invalid token")
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


def serve(framework: Any, host: str = "127.0.0.1", port: int = 8777,
          token: str | None = None, cors_origins: list[str] | None = None) -> None:
    """Boot the RPC server (blocking). Requires the ``rpc`` extra."""
    try:
        import uvicorn
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(_RPC_HINT) from exc
    app = create_app(framework, token=token, cors_origins=cors_origins)
    print(f"RPC token: {app.state.token}")
    uvicorn.run(app, host=host, port=port, log_level="info")


def serve_in_thread(framework: Any, host: str = "127.0.0.1", port: int = 8777,
                    token: str | None = None, cors_origins: list[str] | None = None) -> Any:
    """Boot the RPC server in a background daemon thread sharing ``framework``.

    Returns ``(server, thread, token)``. Unlike :func:`serve`, this does not
    block: the caller (e.g. the interactive console) keeps running while the
    dashboard reads the *same* framework, so a run streams live over
    ``/ws/events``. Requires the ``rpc`` extra.
    """
    if not _FASTAPI_OK:
        raise RuntimeError(_RPC_HINT)
    import threading

    try:
        import uvicorn
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(_RPC_HINT) from exc

    app = create_app(framework, token=token, cors_origins=cors_origins)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="erebus-rpc", daemon=True)
    thread.start()
    return server, thread, app.state.token
