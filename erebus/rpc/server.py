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
import threading
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

from erebus.connectors.base import ConnectorError, MissingKey, NetworkDisabled
from erebus.connectors.vault import VaultError
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
    state: dict[str, Any] = {"bridge": None, "unsub": None,
                             "webconsole": None, "console_lock": threading.Lock()}

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

    @app.get("/copilot.png")
    async def copilot_png() -> Any:
        asset = Path(__file__).resolve().parent / "assets" / "copilot.png"
        try:
            data = asset.read_bytes()
        except OSError:
            raise HTTPException(status_code=404, detail="asset not found") from None
        return Response(content=data, media_type="image/png",
                        headers={"Cache-Control": "max-age=86400"})

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

    @app.get("/jobs")
    async def list_jobs() -> dict[str, Any]:
        """Persisted job history (newest first): module, target, status, timing."""
        return {"jobs": [dict(r) for r in framework.store.jobs()]}

    @app.get("/credentials")
    async def list_credentials() -> dict[str, Any]:
        """Discovered credentials. Secret VALUES are redacted here; the datastore
        keeps them, but they are never sent over the wire or shown in the UI."""
        out = []
        for r in framework.store.credentials():
            d = dict(r)
            d["has_secret"] = bool(d.get("secret"))
            d["secret"] = "set" if d.get("secret") else ""
            out.append(d)
        return {"credentials": out}

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

    @app.post("/copilot", dependencies=[Depends(require_token)])
    def copilot(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006  (sync: LLM call runs in a threadpool)
        from erebus.connectors.llm import LLMConnector
        from erebus.copilot import Copilot
        question = str(payload.get("question", "")).strip() or (
            "Given the engagement state, what should I do next? Suggest concrete next "
            "steps and which Erebus modules to run. Be brief.")
        provider = str(payload.get("provider", "anthropic")).strip() or "anthropic"
        if provider not in ("anthropic", "openai", "ollama"):
            raise HTTPException(
                status_code=400,
                detail=f"unknown provider {provider!r}; use anthropic, openai or ollama")
        model = str(payload.get("model", "")).strip() or None
        base_url = str(payload.get("base_url", "")).strip() or None
        try:
            conn = LLMConnector(framework.vault, provider=provider, model=model,
                                base_url=base_url, timeout=120.0,
                                offline=bool(framework.config.get("offline")),
                                tor=bool(framework.config.get("tor")))
            answer = Copilot(framework, conn).ask(question)
        except (MissingKey, NetworkDisabled) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None
        except ConnectorError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from None
        return {"answer": answer, "provider": provider}

    @app.post("/copilot/ollama/test", dependencies=[Depends(require_token)])
    def ollama_test(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        from erebus.connectors.base import Connector
        base = str(payload.get("base_url", "")).strip().rstrip("/") or "http://command-center:3000"
        conn = Connector(framework.vault, allow_insecure=True,
                         offline=bool(framework.config.get("offline")),
                         tor=bool(framework.config.get("tor")))
        conn.base_url = base

        def _openai(data: Any) -> list | None:
            if isinstance(data, dict) and isinstance(data.get("data"), list):
                return [str(m.get("id")) for m in data["data"]
                        if isinstance(m, dict) and m.get("id")]
            return None

        def _tags(data: Any) -> list | None:
            if isinstance(data, dict) and isinstance(data.get("models"), list):
                return [str(m.get("name")) for m in data["models"]
                        if isinstance(m, dict) and m.get("name")]
            return None

        try:
            key = framework.vault.get("ollama")
        except VaultError:
            key = None
        hdrs = {"Authorization": f"Bearer {key}"} if key else {}
        last = ""
        auth_required = False
        for path, extract in (("/v1/models", _openai), ("/api/tags", _tags)):
            try:
                models = extract(conn.get_json(path, secret_headers=hdrs))
            except NetworkDisabled as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from None
            except MissingKey as exc:  # server replied 401/403 -> needs a key
                auth_required = True
                last = str(exc)
                continue
            except ConnectorError as exc:
                last = str(exc)
                continue
            if models is not None:
                return {"ok": True, "url": base + path, "models": models}
        if auth_required:
            raise HTTPException(
                status_code=401,
                detail="server requires an API key; add it in the API key field below")
        raise HTTPException(status_code=502,
                            detail=last or f"{base}: no models endpoint responded")

    @app.post("/copilot/ollama/key", dependencies=[Depends(require_token)])
    def ollama_key(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        key = str(payload.get("key", "")).strip()
        try:
            if key:
                framework.vault.set("ollama", key)
            else:
                framework.vault.delete("ollama")
        except VaultError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"vault unavailable: {exc}; install  pip install -e .[connectors]",
            ) from None
        return {"ok": True, "set": bool(key)}

    @app.post("/console", dependencies=[Depends(require_token)])
    def console_cmd(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006  (sync: runs in threadpool)
        import contextlib
        import io
        import re
        line = str(payload.get("command", "")).strip()
        if not line:
            return {"output": ""}
        verb = line.split()[0].lower()
        if verb in ("exit", "quit", "eof") or line.startswith("!"):
            return {"output": "(not available in the web console)\n"}
        buf = io.StringIO()
        with state["console_lock"]:
            with contextlib.redirect_stdout(buf):
                con = state.get("webconsole")
                if con is None:
                    from erebus.console import EreConsole

                    class _WebConsole(EreConsole):  # don't tee log events to process stdout
                        def _on_log(self, e: Any) -> None:
                            pass

                    con = _WebConsole(framework=framework)
                    state["webconsole"] = con
                try:
                    con.onecmd(line)
                except Exception as exc:  # noqa: BLE001  (a console shows the error, never crashes)
                    print(f"error: {exc}")
        out = re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())  # strip ANSI colour
        return {"output": out}

    def _recent_events(limit: int = 200) -> list:
        """Stored events (oldest-first) to replay so a reconnecting client's feed
        and job history are not blank after a reload."""
        out = []
        for r in framework.store.recent_events(limit):
            try:
                data = json.loads(r["data"]) if r["data"] else {}
            except (ValueError, TypeError):
                data = {}
            out.append({"type": r["type"], "data": data, "replay": True})
        return out

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
        for _ev in _recent_events():
            await ws.send_text(json.dumps(_ev))
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
                for _ev in _recent_events():
                    yield f"data: {json.dumps(_ev)}\n\n"
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
